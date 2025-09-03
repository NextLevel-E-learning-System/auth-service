import { Request, Response, NextFunction } from 'express';
import { loginSchema, registerSchema } from '../validation/authSchemas.js';
import { login, register, logout, refresh } from '../services/authService.js';
import { HttpError } from '../utils/httpError.js';

export async function loginHandler(req: Request, res: Response, next: NextFunction) {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return next(new HttpError(400, 'validation_error', parsed.error.issues));
  try {
  const uaHeader = req.headers['user-agent'] as any;
  const ua = typeof uaHeader === 'string' ? uaHeader : (Array.isArray(uaHeader) ? (uaHeader as string[]).join(' ') : '');
    const result = await login(parsed.data.email, parsed.data.senha, req.ip, ua);
    // enviar refresh como HttpOnly cookie
    const secureCookie = process.env.NODE_ENV === 'production';
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookie,
      maxAge: 1000 * 60 * 60 * (parseInt(process.env.REFRESH_TOKEN_EXP_HOURS || '24', 10)),
      path: '/auth/v1'
    });
    if (process.env.LOG_LEVEL === 'debug') {
      // eslint-disable-next-line no-console
      console.debug('[auth-service] Set-Cookie header (login)', res.getHeader('Set-Cookie'));
    }
    res.json({ accessToken: result.accessToken, tokenType: result.tokenType, expiresInHours: result.expiresInHours });
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
    const invalidateAll = req.header('x-invalidate-all') === 'true';
    const result = await logout(req.header('authorization'), invalidateAll);
  // limpar cookie de refresh
  const secureCookie = process.env.NODE_ENV === 'production';
  res.cookie('refreshToken', '', { httpOnly: true, sameSite: 'strict', secure: secureCookie, expires: new Date(0), path: '/auth/v1' });
  res.json({ message: 'Logout efetuado' });
  } catch (err) { next(err); }
}

export async function refreshHandler(req: Request, res: Response, next: NextFunction) {
  try {
    const bodyToken = (req.body || {}).refreshToken;
    const cookieToken = (req as any).cookies?.refreshToken;
    const refreshToken = bodyToken || cookieToken;
    const uaHeader = req.headers['user-agent'] as any;
    const ua = typeof uaHeader === 'string' ? uaHeader : (Array.isArray(uaHeader) ? (uaHeader as string[]).join(' ') : '');
    const result = await refresh(refreshToken, req.ip, ua);
    // sobrescreve cookie com novo refreshToken
    const secureCookie = process.env.NODE_ENV === 'production';
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      sameSite: 'strict',
      secure: secureCookie,
      maxAge: 1000 * 60 * 60 * (parseInt(process.env.REFRESH_TOKEN_EXP_HOURS || '24', 10)),
      path: '/auth/v1'
    });
    if (process.env.LOG_LEVEL === 'debug') {
      // eslint-disable-next-line no-console
      console.debug('[auth-service] Set-Cookie header (refresh)', res.getHeader('Set-Cookie'));
    }
    res.json({ accessToken: result.accessToken, tokenType: result.tokenType, expiresInHours: result.expiresInHours });
  } catch (err) { next(err); }
}