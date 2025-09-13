import { withClient } from '../config/db.js';
import { hashPassword, compareHash } from '../utils/hash.js';
import jwt from 'jsonwebtoken';
import { HttpError } from '../utils/httpError.js';

interface CreateUserInput {
  cpf?: string;
  nome: string;
  email: string;
  departamento_id?: string;
  cargo_nome?: string;
}

export async function createUserAuth({ cpf, nome, email, departamento_id, cargo_nome }: CreateUserInput) {
  const allowedDomains = (process.env.ALLOWED_EMAIL_DOMAINS || 'gmail.com').split(',');
  const isValidDomain = allowedDomains.some(domain => email.endsWith(`@${domain.trim()}`));
  if (!isValidDomain) {
    throw new HttpError(400, 'dominio_nao_permitido', `Apenas emails dos domínios ${allowedDomains.join(', ')} são permitidos para auto-cadastro`);
  }

  const tempPassword = Math.random().toString().slice(-6);
  const senhaHash = await hashPassword(tempPassword);

  return await withClient(async c => {
    // Validação de CPF via função do banco se informado
    if (cpf) {
      const v = await c.query('SELECT public.is_valid_cpf($1) AS ok', [cpf]);
      if (!v.rows[0].ok) {
        throw new HttpError(400, 'cpf_invalido', 'CPF inválido');
      }
    }

    try {
      // 1) Cria auth user
      const authRes = await c.query(`
        INSERT INTO auth_service.usuarios (email, senha_hash)
        VALUES ($1,$2) RETURNING id, email, criado_em
      `, [email, senhaHash]);
      const authUser = authRes.rows[0];

      // 2) Cria funcionario referenciando auth_user_id
      const funcRes = await c.query(`
        INSERT INTO user_service.funcionarios (auth_user_id, cpf, nome, email, departamento_id, cargo_nome)
        VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING id, auth_user_id, cpf, nome, email, departamento_id, cargo_nome, criado_em
      `, [authUser.id, cpf || null, nome, email, departamento_id || null, cargo_nome || null]);
      const funcionario = funcRes.rows[0];

      // 3) Atribui role padrão ALUNO
      await c.query(`
        INSERT INTO user_service.user_roles (user_id, role_id)
        SELECT $1, r.id FROM user_service.roles r WHERE r.nome='ALUNO'
        RETURNING id
      `, [funcionario.id]);

      // 4) Eventos outbox (sem senha ou hash)
      await c.query(`INSERT INTO user_service.outbox_events (topic, payload) VALUES ($1, $2)`, [
        'user.created', JSON.stringify({
          id: funcionario.id,
            auth_user_id: authUser.id,
          nome: funcionario.nome,
          email: funcionario.email,
          cpf: funcionario.cpf,
          departamento_id: funcionario.departamento_id,
          cargo_nome: funcionario.cargo_nome,
          roles: ['ALUNO']
        })
      ]);

      await c.query(`INSERT INTO user_service.outbox_events (topic, payload) VALUES ($1, $2)`, [
        'user.role.granted', JSON.stringify({
          user_id: funcionario.id,
          role: 'ALUNO'
        })
      ]);

      // 5) Retorno limpo + senha temporária (se necessário exibir para usuário final)
      return {
        id: funcionario.id,
        auth_user_id: authUser.id,
        nome: funcionario.nome,
        email: funcionario.email,
        cpf: funcionario.cpf,
        departamento_id: funcionario.departamento_id,
        cargo_nome: funcionario.cargo_nome,
        roles: ['ALUNO'],
        temp_password: tempPassword // NOTE: considerar enviar por email e NÃO retornar em prod
      };

    } catch (err: unknown) {
      interface PgErr extends Record<string, unknown> { code?: string; constraint?: string; detail?: string }
      const e = err as PgErr;
      if (e.code === '23505') {
        const msg = e.constraint || '';
        if (msg.includes('usuarios_email_key')) {
          throw new HttpError(409, 'email_ja_cadastrado', 'Este email já está cadastrado');
        }
        if (msg.includes('funcionarios_cpf_key')) {
          throw new HttpError(409, 'cpf_ja_cadastrado', 'CPF já cadastrado');
        }
        if (msg.includes('funcionarios_email_key')) {
          throw new HttpError(409, 'email_ja_cadastrado', 'Este email já está cadastrado');
        }
        throw new HttpError(409, 'duplicado', 'Registro duplicado');
      }
      if (e.code === '23503') {
        if (typeof e.detail === 'string' && e.detail.includes('departamentos')) {
          throw new HttpError(400, 'departamento_inexistente', 'Departamento não encontrado');
        }
        if (typeof e.detail === 'string' && e.detail.includes('cargos')) {
          throw new HttpError(400, 'cargo_inexistente', 'Cargo não encontrado');
        }
      }
      if (e.code === '23514' && typeof e.constraint === 'string' && e.constraint.includes('cpf_valido')) {
        throw new HttpError(400, 'cpf_invalido', 'CPF inválido');
      }
      throw err;
    }
  });
}

export async function loginUser(email: string, senha: string) {
  return await withClient(async c => {
    const res = await c.query(`SELECT f.id, f.auth_user_id, u.senha_hash FROM user_service.funcionarios f
      JOIN auth_service.usuarios u ON f.auth_user_id=u.id
      WHERE f.email=$1 AND u.ativo=true`, [email]);
    if (!res.rowCount) throw new Error('Usuário não encontrado ou inativo');

    const user = res.rows[0];
    const match = await compareHash(senha, user.senha_hash);
    if (!match) throw new Error('Senha incorreta');

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '8h' });
    await c.query(`INSERT INTO auth_service.logs_acesso (usuario_id, ip, user_agent)
      VALUES ($1,$2,$3)`, [user.auth_user_id, '0.0.0.0', 'console']);

    return token;
  });
}

export async function resetPassword(email: string) {
  const password = Math.random().toString().slice(-6);
  const senhaHash = await hashPassword(password);

  await withClient(async c => {
    const r = await c.query(`UPDATE auth_service.usuarios
      SET senha_hash=$1 WHERE email=$2 RETURNING id`, [senhaHash, email]);

    if (!r.rowCount) throw new Error('Email não encontrado');

    await c.query(`INSERT INTO user_service.outbox_events (topic, payload) VALUES
      ($1, $2)`, ['user.password_reset', JSON.stringify({ usuario_id: r.rows[0].id, email })]);
  });

  return true;
}

export async function refreshToken(oldToken: string) {
  return await withClient(async c => {
    const r = await c.query(`
      SELECT usuario_id FROM auth_service.tokens
      WHERE token_jwt=$1 AND ativo=true AND tipo_token='REFRESH' AND data_expiracao>now()
    `, [oldToken]);

    if (!r.rowCount) throw new Error('Refresh token inválido');

    const usuario_id = r.rows[0].usuario_id;
    const newJwt = jwt.sign({ userId: usuario_id }, process.env.JWT_SECRET!, { expiresIn: '8h' });

    await c.query(`UPDATE auth_service.tokens SET ativo=false WHERE token_jwt=$1`, [oldToken]);
    await c.query(`
      INSERT INTO auth_service.tokens (token_jwt, usuario_id, data_expiracao, tipo_token)
      VALUES ($1, $2, now() + interval '8 hours', 'ACCESS')
    `, [newJwt, usuario_id]);

    return newJwt;
  });
}

export async function logoutUser(token: string) {
  await withClient(async c => {
    await c.query(`UPDATE auth_service.tokens
      SET ativo=false
      WHERE token_jwt=$1`, [token]);
  });
}
