import { Request, Response } from "express";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import { withClient } from "../config/db.js";

const JWT_SECRET = process.env.JWT_SECRET || "changeme";

import type { SignOptions } from "jsonwebtoken";
import { HttpError } from "../utils/httpError.js";

function generateToken(payload: object, expiresIn: string, tipo: "ACCESS"|"REFRESH") {
  const options: SignOptions = { expiresIn: expiresIn as jwt.SignOptions["expiresIn"] };
  return jwt.sign(payload, JWT_SECRET, options);
}

export const register = async (req: Request, res: Response) => {
  const allowedDomains = (process.env.ALLOWED_EMAIL_DOMAINS || 'gmail.com').split(',');
  const isValidDomain = allowedDomains.some(domain => email.endsWith(`@${domain.trim()}`));
  if (!isValidDomain) {
    throw new HttpError(400, 'dominio_nao_permitido', `Apenas emails dos domínios ${allowedDomains.join(', ')} são permitidos para auto-cadastro`);
  }
  const { email, senha } = req.body;
  const hash = await bcrypt.hash(senha, 12);

  await withClient(async (c) => {
    const result = await c.query(
      `INSERT INTO auth_service.usuarios(email, senha_hash) 
       VALUES ($1,$2) RETURNING id, email, ativo, criado_em`,
      [email, hash]
    );

    // evento outbox: user criado
    await c.query(
      `INSERT INTO auth_service.outbox_events(aggregate_type, aggregate_id, event_type, payload)
       VALUES ('auth',$1,'auth.user_created',$2)`,
      [result.rows[0].id, JSON.stringify(result.rows[0])]
    );

    res.status(201).json({ usuario: result.rows[0] });
  });
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

    const accessToken = generateToken({ sub: user.id }, "15m", "ACCESS");
    const refreshToken = generateToken({ sub: user.id }, "7d", "REFRESH");

    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, usuario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'ACCESS', now() + interval '15 minutes')`,
      [accessToken, user.id]
    );
    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, usuario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'REFRESH', now() + interval '7 days')`,
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
    const decoded: any = jwt.verify(refreshToken, JWT_SECRET);

    await withClient(async (c) => {
      const { rows } = await c.query(
        `SELECT * FROM auth_service.tokens 
         WHERE token_jwt=$1 AND ativo=true AND tipo_token='REFRESH'`,
        [refreshToken]
      );
      if (!rows[0]) return res.status(401).json({ error: "Refresh token inválido" });

      const newAccessToken = generateToken({ sub: decoded.sub }, "15m", "ACCESS");

      await c.query(
        `INSERT INTO auth_service.tokens(token_jwt, usuario_id, tipo_token, data_expiracao)
         VALUES ($1,$2,'ACCESS', now() + interval '15 minutes')`,
        [newAccessToken, decoded.sub]
      );

      res.json({ accessToken: newAccessToken });
    });
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
};

export const logout = async (req: Request, res: Response) => {
  const { refreshToken } = req.body;
  await withClient(async (c) => {
    await c.query(
      `UPDATE auth_service.tokens SET ativo=false WHERE token_jwt=$1 AND tipo_token='REFRESH'`,
      [refreshToken]
    );
    await c.query(
      `INSERT INTO auth_service.outbox_events(aggregate_type, aggregate_id, event_type, payload)
       VALUES ('auth','00000000-0000-0000-0000-000000000000','auth.logout',$1)`,
      [JSON.stringify({ refreshToken })]
    );
    res.json({ message: "Logout realizado" });
  });
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
