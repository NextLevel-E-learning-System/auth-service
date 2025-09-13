import { withClient } from '../config/db.js';
import { hashPassword, compareHash } from '../utils/hash.js';
import jwt from 'jsonwebtoken';
import { HttpError } from '../utils/httpError.js';

export async function createUserAuth({ cpf, nome, email, departamento_id, cargo_nome }: any) {
    // Validar domínio do email (configurável via env)
  const allowedDomains = (process.env.ALLOWED_EMAIL_DOMAINS || 'gmail.com').split(',');
  const isValidDomain = allowedDomains.some(domain => email.endsWith(`@${domain.trim()}`));
  
    if (!isValidDomain) {
    throw new HttpError(400, 'dominio_nao_permitido', `Apenas emails dos domínios ${allowedDomains.join(', ')} são permitidos para auto-cadastro`);
  }

  const password = Math.random().toString().slice(-6);
  const senhaHash = await hashPassword(password);

  return await withClient(async c => {
    const user = await c.query(`
      INSERT INTO user_service.funcionarios (cpf, nome, email, departamento_id, cargo_nome)
      VALUES ($1,$2,$3,$4,$5) RETURNING *`, [cpf, nome, email, departamento_id, cargo_nome]);

    const userId = user.rows[0].id;

    try {

    await c.query(`
      INSERT INTO auth_service.usuarios (email, senha_hash)
      VALUES ($1,$2) RETURNING *`, [email, senhaHash]);

    await c.query(`
      INSERT INTO user_service.user_roles (user_id, role_id)
      SELECT $1, id FROM user_service.roles WHERE nome='ALUNO'`, [userId]);

    await c.query(`INSERT INTO user_service.outbox_events (topic, payload) VALUES
      ('user.created', $1)`, [JSON.stringify({ userId, nome, email, senha: senhaHash, role: 'ALUNO' })]);

    } catch (err: any) {
       if (err.code === '23505') { // Violação de constraint única
      if (err.constraint?.includes('cpf')) {
        throw new HttpError(409, 'cpf_ja_cadastrado', 'CPF já está cadastrado no sistema');
      }
      if (err.constraint?.includes('email')) {
        throw new HttpError(409, 'email_ja_cadastrado', 'Este email já está cadastrado no sistema');
      }
      throw new HttpError(409, 'dados_duplicados', 'Dados já cadastrados no sistema');
    }
  }

  return user.rows[0];
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

    // Opcional: publicar evento user.password_reset
    await c.query(`INSERT INTO user_service.outbox_events (topic, payload) VALUES
      ('user.password_reset', $1)`, [JSON.stringify({ usuario_id: r.rows[0].id, email, senha: senhaHash })]);
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

    // Marca o antigo como inativo e adiciona novo token
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
