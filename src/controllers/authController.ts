import { Request, Response } from "express";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import { withClient } from "../config/db.js";
import { publishEvent } from "../config/rabbitmq.js";

const JWT_SECRET = process.env.JWT_SECRET || "changeme";

import type { SignOptions } from "jsonwebtoken";
import { HttpError } from "../utils/httpError.js";

function generateToken(payload: object, expiresIn: string) {
  const options: SignOptions = { expiresIn: expiresIn as jwt.SignOptions["expiresIn"] };
  return jwt.sign(payload, JWT_SECRET, options);
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
         VALUES ($1,$2) RETURNING id, email, ativo, criado_em`,
        [email, hash]
      );

      const usuario = result.rows[0];

      // NÃO armazenar senha em claro no evento persistido.
      await c.query(
        `INSERT INTO auth_service.outbox_events(aggregate_type, aggregate_id, event_type, payload)
         VALUES ('auth',$1,'auth.user_created',$2)`,
        [usuario.id, JSON.stringify({ id: usuario.id, email: usuario.email, criado_em: usuario.criado_em, ativo: usuario.ativo })]
      );

      // Evento efêmero separado contendo a senha (não persiste em DB). Usar fila/exchange direct.
      try {
        await publishEvent('auth.user_password_ephemeral', { email: usuario.email, senha: senhaClara });
      } catch (ephemeralErr) {
        // Logar, mas não falhar o registro do usuário.
        // eslint-disable-next-line no-console
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
    const { rows } = await c.query(
      `SELECT * FROM auth_service.usuarios WHERE email=$1 AND ativo=true`,
      [email]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "Credenciais inválidas" });

    const valid = await bcrypt.compare(senha, user.senha_hash);
    if (!valid) return res.status(401).json({ error: "Credenciais inválidas" });

  const accessToken = generateToken({ sub: user.id }, "8h");
  const refreshToken = generateToken({ sub: user.id }, "24h");

    await c.query(
  `INSERT INTO auth_service.tokens(token_jwt, usuario_id, tipo_token, data_expiracao)
   VALUES ($1,$2,'ACCESS', now() + interval '8 hours')`,
      [accessToken, user.id]
    );
    await c.query(
  `INSERT INTO auth_service.tokens(token_jwt, usuario_id, tipo_token, data_expiracao)
   VALUES ($1,$2,'REFRESH', now() + interval '24 hours')`,
      [refreshToken, user.id]
    );

    await c.query(
      `INSERT INTO auth_service.logs_acesso(usuario_id, ip, user_agent)
       VALUES ($1,$2,$3)`,
      [user.id, req.ip, req.headers["user-agent"]]
    );

    await c.query(
      `INSERT INTO auth_service.outbox_events(aggregate_type, aggregate_id, event_type, payload)
       VALUES ('auth',$1,'auth.login',$2)`,
      [user.id, JSON.stringify({ email: user.email })]
    );

    res.json({ accessToken, refreshToken });
  });
};

export const refresh = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  try {
  const decoded = jwt.verify(refreshToken, JWT_SECRET) as { sub: string; iat: number; exp: number };

    await withClient(async (c) => {
      const { rows } = await c.query(
        `SELECT * FROM auth_service.tokens 
         WHERE token_jwt=$1 AND ativo=true AND tipo_token='REFRESH'`,
        [refreshToken]
      );
      if (!rows[0]) return res.status(401).json({ error: "Refresh token inválido" });

  const newAccessToken = generateToken({ sub: decoded.sub }, "8h");

      await c.query(
  `INSERT INTO auth_service.tokens(token_jwt, usuario_id, tipo_token, data_expiracao)
   VALUES ($1,$2,'ACCESS', now() + interval '8 hours')`,
        [newAccessToken, decoded.sub]
      );

      res.json({ accessToken: newAccessToken });
    });
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
};

export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.body as { refreshToken?: string };
  if (!refreshToken) {
    return res.status(400).json({ error: 'refresh_token_obrigatorio' });
  }
  try {
    const decoded = jwt.verify(refreshToken, JWT_SECRET) as { sub: string };
    await withClient(async (c) => {
      // Invalidar especificamente o refresh token recebido
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE token_jwt=$1 AND tipo_token='REFRESH'`,
        [refreshToken]
      );
      // Invalidar todos os access tokens ativos do usuário (revogação)
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE usuario_id=$1 AND tipo_token='ACCESS' AND ativo=true`,
        [decoded.sub]
      );
      // Registrar evento com aggregate_id = usuário real
      await c.query(
        `INSERT INTO auth_service.outbox_events(aggregate_type, aggregate_id, event_type, payload)
         VALUES ('auth',$1,'auth.logout',$2)`,
        [decoded.sub, JSON.stringify({ refreshToken })]
      );
      res.json({ message: 'Logout realizado' });
    });
  } catch {
    return res.status(401).json({ error: 'refresh_token_invalido' });
  }
};

export const reset = async (req: Request, res: Response) => {
  const { email, novaSenha } = req.body;
  const hash = await bcrypt.hash(novaSenha, 12);

  await withClient(async (c) => {
    const { rows } = await c.query(
      `UPDATE auth_service.usuarios SET senha_hash=$1 WHERE email=$2 RETURNING id,email`,
      [hash, email]
    );
    if (!rows[0]) return res.status(404).json({ error: "Usuário não encontrado" });

    // Invalida tokens antigos
    await c.query(
      `UPDATE auth_service.tokens SET ativo=false WHERE usuario_id=$1`,
      [rows[0].id]
    );

    // Evento de reset de senha
    await c.query(
      `INSERT INTO auth_service.outbox_events(aggregate_type, aggregate_id, event_type, payload)
       VALUES ('auth',$1,'auth.password_reset',$2)`,
      [rows[0].id, JSON.stringify({ email })]
    );

    res.json({ message: "Senha redefinida com sucesso" });
  });
};
