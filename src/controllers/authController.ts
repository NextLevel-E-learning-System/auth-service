import { Request, Response } from "express";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import { createHash } from 'crypto';
import { withClient } from "../config/db.js";
import { publishEvent } from "../config/rabbitmq.js";
import { HttpError } from "../utils/httpError.js";

interface UserData {
  id: string;
  email: string;
  ativo: boolean;
  roles: string; // Single role, not array
}

function buildSigningKey() {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return createHash('sha256').update(secret).digest();
}

function genAccessToken(user: UserData) {
  const accessExpHours = parseInt(process.env.ACCESS_TOKEN_EXP_HOURS || '8', 10);
  const key = buildSigningKey();
  
  // Payload com informações essenciais do usuário
  const payload = { 
    sub: user.id, 
    email: user.email, 
    ativo: user.ativo, 
    roles: user.roles, 
    type: 'access' 
  };
  
  const token = jwt.sign(payload, key, { expiresIn: `${accessExpHours}h` });
  const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000);
  return { token, expiresAt, accessExpHours };
}

function genRefreshToken(user: UserData) {
  const refreshExpHours = parseInt(process.env.REFRESH_TOKEN_EXP_HOURS || '24', 10);
  const key = buildSigningKey();
  
  // Para refresh token, incluir apenas informações essenciais
  const payload = { 
    sub: user.id, 
    email: user.email, 
    ativo: user.ativo, 
    roles: user.roles, 
    type: 'refresh' 
  };
  
  const token = jwt.sign(payload, key, { expiresIn: `${refreshExpHours}h` });
  const expiresAt = new Date(Date.now() + refreshExpHours * 60 * 60 * 1000);
  return { token, expiresAt, refreshExpHours };
}

function hash(value: string) {
  return createHash('sha256').update(value).digest('hex');
}

interface PgErrorLike { code?: string }
function isPgError(obj: unknown): obj is PgErrorLike {
  return typeof obj === 'object' && obj !== null && 'code' in obj;
}

export const register = async (req: Request, res: Response) => {
  const { email } = req.body as { email?: string };

  if (!email) {
    throw new HttpError(400, 'dados_invalidos', 'Email é obrigatório');
  }

  const allowedDomains = (process.env.ALLOWED_EMAIL_DOMAINS || 'gmail.com').split(',');
  const isValidDomain = allowedDomains.some(domain => email.toLowerCase().endsWith(`@${domain.trim().toLowerCase()}`));
  if (!isValidDomain) {
    throw new HttpError(400, 'dominio_nao_permitido', `Apenas emails dos domínios ${allowedDomains.join(', ')} são permitidos para auto-cadastro`);
  }

  const senhaClara = Math.random().toString().slice(-6);
  const hash = await bcrypt.hash(senhaClara, 12);

  try {
    await withClient(async (c) => {
      const result = await c.query(
        `INSERT INTO auth_service.usuarios(email, senha_hash) 
         VALUES ($1,$2) RETURNING funcionario_id, email, ativo, criado_em`,
        [email, hash]
      );

      const usuario = result.rows[0];

      // Publicar evento de criação de usuário (sem senha) diretamente no RabbitMQ
      try {
        await publishEvent('auth.user_created', { id: usuario.funcionario_id, email: usuario.email, criado_em: usuario.criado_em, ativo: usuario.ativo });
      } catch (errPub) {
        console.error('[auth-service] falha publicando auth.user_created', (errPub as Error).message);
      }
      // Publicar evento efêmero com a senha
      try {
        await publishEvent('auth.user_password_ephemeral', { email: usuario.email, senha: senhaClara });
      } catch (ephemeralErr) {
        console.error('[auth-service] falha publicando evento efêmero de senha', (ephemeralErr as Error).message);
      }

      res.status(201).json({ usuario: { ...usuario } });
    });
  } catch (e: unknown) {
    // Violação de chave única (email) -> 409
    if (isPgError(e) && e.code === '23505') {
      return res.status(409).json({ error: 'email_ja_cadastrado' });
    }
    throw e; // será pego pelo errorHandler
  }
};

export const login = async (req: Request, res: Response) => {
  const { email, senha } = req.body;

  await withClient(async (c) => {
    // Buscar usuário com informações completas incluindo dados do funcionário
    const { rows } = await c.query(
      `SELECT u.funcionario_id, u.email, u.ativo, u.senha_hash,
              f.nome, f.departamento_id, f.cargo_nome, f.xp_total, f.nivel, f.role
       FROM auth_service.usuarios u
       LEFT JOIN user_service.funcionarios f ON u.funcionario_id = f.id AND f.ativo = true
       WHERE u.email = $1 AND u.ativo = true`,
      [email]
    );
    
    const user = rows[0];
    if (!user) {
      throw new HttpError(401, 'credenciais_invalidas');
    }

    const valid = await bcrypt.compare(senha, user.senha_hash);
    if (!valid) {
      throw new HttpError(401, 'credenciais_invalidas');
    }

    const userData = { 
      id: user.funcionario_id, 
      email: user.email, 
      ativo: user.ativo,
      roles: user.role
    };

    // Gerar tokens com informações completas
    const { token: accessToken, expiresAt: accessExpiresAt, accessExpHours } = genAccessToken(userData);
    const { token: refreshToken, expiresAt: refreshExpiresAt } = genRefreshToken(userData);

    // Armazenar tokens no banco
    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'ACCESS', $3)`,
      [accessToken, user.funcionario_id, accessExpiresAt]
    );
    
    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'REFRESH', $3)`,
      [hash(refreshToken), user.funcionario_id, refreshExpiresAt]
    );

    // Log de acesso
    await c.query(
      `UPDATE auth_service.usuarios SET ultimo_acesso = NOW() WHERE funcionario_id = $1`,
      [user.funcionario_id]
    );

    await c.query(
      `INSERT INTO auth_service.logs_acesso(funcionario_id, ip, user_agent)
       VALUES ($1,$2,$3)`,
      [user.funcionario_id, req.ip, req.headers["user-agent"]]
    );

    // Publicar evento de login
    try {
      await publishEvent('auth.login', { userId: user.funcionario_id, email: user.email });
    } catch (e) {
      console.error('[auth-service] falha publicando auth.login', (e as Error).message);
    }

    res.json({ 
      accessToken, 
      refreshToken, 
      tokenType: 'Bearer', 
      expiresInHours: accessExpHours 
    });
  });
};

export const refresh = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  
  try {
    const key = buildSigningKey();
    const decoded = jwt.verify(refreshToken, key) as { sub: string; email: string; status: string; roles: string; iat: number; exp: number };

    await withClient(async (c) => {
      // Verificar se o refresh token hasheado existe e está ativo
      const { rows } = await c.query(
        `SELECT * FROM auth_service.tokens 
         WHERE token_jwt=$1 AND ativo=true AND tipo_token='REFRESH' AND data_expiracao > NOW()`,
        [hash(refreshToken)]
      );
      
      if (!rows[0]) {
        return res.status(401).json({ error: "Refresh token inválido" });
      }

      // Buscar dados atualizados do usuário para o novo token
      const { rows: userRows } = await c.query(
        `SELECT u.funcionario_id, u.email, u.ativo, 
                f.nome, f.departamento_id, f.cargo_nome, f.xp_total, f.nivel, f.role
         FROM auth_service.usuarios u
         LEFT JOIN user_service.funcionarios f ON u.funcionario_id = f.id AND f.ativo = true
         WHERE u.funcionario_id = $1 AND u.ativo = true`,
        [decoded.sub]
      );

      const user = userRows[0];
      if (!user) {
        return res.status(401).json({ error: "Usuário não encontrado" });
      }

      const userData: UserData = { 
        id: user.funcionario_id, 
        email: user.email, 
        ativo: user.ativo,
        roles: user.role
      };

      // Gerar novo access token
      const { token: newAccessToken, expiresAt: accessExpiresAt } = genAccessToken(userData);

      // Armazenar novo access token
      await c.query(
        `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
         VALUES ($1,$2,'ACCESS', $3)`,
        [newAccessToken, decoded.sub, accessExpiresAt]
      );

      res.json({ accessToken: newAccessToken });
    });
  } catch (error) {
    console.error('[auth-service] Erro no refresh:', error);
    res.status(401).json({ error: "Token inválido" });
  }
};

export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.body as { refreshToken?: string };
  if (!refreshToken) {
    return res.status(400).json({ error: 'refresh_token_obrigatorio' });
  }
  
  try {
    const key = buildSigningKey();
    const decoded = jwt.verify(refreshToken, key) as { sub: string };
    
    await withClient(async (c) => {
      // Invalidar especificamente o refresh token recebido (hasheado)
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE token_jwt=$1 AND tipo_token='REFRESH'`,
        [hash(refreshToken)]
      );
      
      // Invalidar todos os access tokens ativos do usuário (revogação)
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE funcionario_id=$1 AND tipo_token='ACCESS' AND ativo=true`,
        [decoded.sub]
      );
      
      // Registrar evento com aggregate_id = usuário real
      try {
        await publishEvent('auth.logout', { userId: decoded.sub, refreshToken });
      } catch (e) {
        console.error('[auth-service] falha publicando auth.logout', (e as Error).message);
      }
      
      res.json({ message: 'Logout realizado' });
    });
  } catch (error) {
    console.error('[auth-service] Erro no logout:', error);
    return res.status(401).json({ error: 'refresh_token_invalido' });
  }
};

export const reset = async (req: Request, res: Response) => {
  const { email, novaSenha } = req.body;
  const hash = await bcrypt.hash(novaSenha, 12);

  await withClient(async (c) => {
    const { rows } = await c.query(
      `UPDATE auth_service.usuarios SET senha_hash=$1 WHERE email=$2 RETURNING funcionario_id,email`,
      [hash, email]
    );
    if (!rows[0]) return res.status(404).json({ error: "Usuário não encontrado" });

    // Invalida tokens antigos
    await c.query(
      `UPDATE auth_service.tokens SET ativo=false WHERE funcionario_id=$1`,
      [rows[0].funcionario_id]
    );

    // Evento de reset de senha
    try {
      await publishEvent('auth.password_reset', { userId: rows[0].funcionario_id, email });
    } catch (e) {
      console.error('[auth-service] falha publicando auth.password_reset', (e as Error).message);
    }

    res.json({ message: "Senha redefinida com sucesso" });
  });
};