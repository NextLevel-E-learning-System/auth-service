import { randomUUID } from 'crypto';
import bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { findUserByEmail, createUser, createEmployee, storeToken, updateLastAccessAndLog, invalidateToken, getActiveToken } from '../repositories/userRepository.js';
import { HttpError } from '../utils/httpError.js';

function genAccessToken(userId: string, roles: string[]) {
  const accessExpHours = 8;
  const token = jwt.sign({ sub: userId, roles, type: 'access' }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: `${accessExpHours}h` as any });
  const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000);
  return { token, expiresAt, accessExpHours };
}

function genRefreshToken(userId: string) {
  const refreshExpDays = 30;
  const token = jwt.sign({ sub: userId, type: 'refresh' }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: `${refreshExpDays}d` as any });
  const expiresAt = new Date(Date.now() + refreshExpDays * 24 * 60 * 60 * 1000);
  return { token, expiresAt, refreshExpDays };
}

export async function login(email: string, senha: string, ip: string | undefined, userAgent: string | null) {
  const usuario = await findUserByEmail(email);
  if (!usuario) throw new HttpError(401, 'credenciais_invalidas');
  if (usuario.status !== 'ATIVO') throw new HttpError(403, 'usuario_inativo');
  const ok = await bcrypt.compare(senha, usuario.senha_hash);
  if (!ok) throw new HttpError(401, 'credenciais_invalidas');
  const roles = [usuario.tipo_usuario];
  const { token: accessToken, expiresAt: accessExpiresAt, accessExpHours } = genAccessToken(usuario.id, roles);
  const { token: refreshToken, expiresAt: refreshExpiresAt } = genRefreshToken(usuario.id);
  await storeToken(accessToken, usuario.id, accessExpiresAt, 'ACCESS');
  await storeToken(refreshToken, usuario.id, refreshExpiresAt, 'REFRESH');
  await updateLastAccessAndLog(usuario.id, ip || '', userAgent);
  return { accessToken, refreshToken, tokenType: 'Bearer', expiresInHours: accessExpHours };
}

export async function register(data: { cpf: string; nome: string; email: string; departamento: string; cargo: string; }) {
  const { cpf, nome, email, departamento, cargo } = data;
  const allowed = (process.env.ALLOWED_EMAIL_DOMAINS || '').split(',').map(d => d.trim()).filter(Boolean);
  if (allowed.length > 0) {
    const domain = email.split('@')[1];
    if (!allowed.includes(domain)) throw new HttpError(400, 'dominio_invalido');
  }
  const id = randomUUID();
  const senhaPlano = Math.floor(100000 + Math.random() * 900000).toString();
  const hash = await bcrypt.hash(senhaPlano, 12);
  try {
    await createUser(id, email, hash);
    await createEmployee(id, cpf, nome, email, departamento, cargo);
  } catch (err: any) {
    if (err.code === '23505') throw new HttpError(409, 'duplicado');
    throw err;
  }
  return { id, email, mensagem: 'Senha enviada por e-mail (simulado)' };
}

export async function logout(authorizationHeader?: string) {
  if (!authorizationHeader) throw new HttpError(400, 'token_nao_informado');
  const token = authorizationHeader.replace(/^Bearer\s+/i, '');
  await invalidateToken(token);
  return { sucesso: true };
}

export async function refresh(refreshToken: string, ip: string | undefined, userAgent: string | null) {
  if (!refreshToken) throw new HttpError(400, 'refresh_token_obrigatorio');
  let payload: any;
  try {
    payload = jwt.verify(refreshToken, process.env.JWT_SECRET || 'dev-secret');
  } catch {
    throw new HttpError(401, 'refresh_invalido');
  }
  if (payload.type !== 'refresh') throw new HttpError(400, 'tipo_token_incorreto');
  const row = await getActiveToken(refreshToken, 'REFRESH');
  if (!row) throw new HttpError(401, 'refresh_invalido_ou_expirado');
  if (new Date(row.data_expiracao) < new Date()) throw new HttpError(401, 'refresh_expirado');
  // Rotação: invalidar antigo
  await invalidateToken(refreshToken);
  const roles = payload.roles || []; // caso queira embutir
  const { token: accessToken, expiresAt: accessExpiresAt, accessExpHours } = genAccessToken(payload.sub, roles);
  const { token: newRefreshToken, expiresAt: newRefreshExpiresAt } = genRefreshToken(payload.sub);
  await storeToken(accessToken, payload.sub, accessExpiresAt, 'ACCESS');
  await storeToken(newRefreshToken, payload.sub, newRefreshExpiresAt, 'REFRESH');
  await updateLastAccessAndLog(payload.sub, ip || '', userAgent);
  return { accessToken, refreshToken: newRefreshToken, tokenType: 'Bearer', expiresInHours: accessExpHours };
}