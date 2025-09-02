import { Request, Response, NextFunction } from 'express';
import { loginSchema, registerSchema } from '../validation/authSchemas.js';
import { login, register, logout } from '../services/authService.js';
import { HttpError } from '../utils/httpError.js';

export async function loginHandler(req: Request, res: Response, next: NextFunction) {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return next(new HttpError(400, 'validation_error', parsed.error.issues));
  try {
  const uaHeader = req.headers['user-agent'] as any;
  const ua = typeof uaHeader === 'string' ? uaHeader : (Array.isArray(uaHeader) ? (uaHeader as string[]).join(' ') : '');
  const result = await login(parsed.data.email, parsed.data.senha, req.ip, ua);
    res.json(result);
  } catch (err) { next(err); }
}

export async function registerHandler(req: Request, res: Response, next: NextFunction) {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return next(new HttpError(400, 'validation_error', parsed.error.issues));
  try {
    const result = await register(parsed.data);
    res.status(201).json(result);
  } catch (err) { next(err); }
}

export async function logoutHandler(req: Request, res: Response, next: NextFunction) {
  try {
    const result = await logout(req.header('authorization'));
    res.json(result);
  } catch (err) { next(err); }
}

export function refreshHandler(_req: Request, res: Response) {
  res.status(501).json({ error: 'nao_suportado' });
}