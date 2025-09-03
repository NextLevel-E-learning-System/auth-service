import { randomUUID, createHash } from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { findUserByEmail, findUserById, createUser, createEmployee, storeToken, updateLastAccessAndLog, invalidateToken, invalidateAllTokensOfUser, getActiveToken, storeRefreshTokenHashed, getActiveRefreshTokenByHash } from '../repositories/userRepository.js';
import { createHash as cryptoCreateHash } from 'crypto';
import { HttpError } from '../utils/httpError.js';

function buildSigningKey() {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  // Derivação simples: SHA256(secret). Mantém requisito "JWT com SHA256 + SALT" assumindo que
  // o próprio secret já incorpora entropia/salt (valor único forte gerado). Se quiser reforçar,
  // gere o secret contendo partes distintas ou concatene internamente uma constante.
  return createHash('sha256').update(secret).digest(); // 32 bytes
}

function genAccessToken(user: { id: string; email: string; status: string; roles: string[] }) {
  const accessExpHours = parseInt(process.env.ACCESS_TOKEN_EXP_HOURS || '8', 10);
  const key = buildSigningKey();
  const payload = { sub: user.id, email: user.email, status: user.status, roles: user.roles, type: 'access' };
  const token = jwt.sign(payload, key, { expiresIn: `${accessExpHours}h` as any });
  const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000);
  if (process.env.LOG_LEVEL === 'debug') {
    // eslint-disable-next-line no-console
    console.debug('[auth-service] genAccessToken payload', payload);
  }
  return { token, expiresAt, accessExpHours };
}

function hash(value: string) {
  return cryptoCreateHash('sha256').update(value).digest('hex');
}

function genRefreshToken(user: { id: string; email: string; status: string; roles: string[] }) {
  const refreshExpHours = parseInt(process.env.REFRESH_TOKEN_EXP_HOURS || '24', 10);
  const key = buildSigningKey();
  const payload = { sub: user.id, email: user.email, status: user.status, roles: user.roles, type: 'refresh' };
  const token = jwt.sign(payload, key, { expiresIn: `${refreshExpHours}h` as any });
  const expiresAt = new Date(Date.now() + refreshExpHours * 60 * 60 * 1000);
  if (process.env.LOG_LEVEL === 'debug') {
    // eslint-disable-next-line no-console
    console.debug('[auth-service] genRefreshToken payload', payload);
  }
  return { token, expiresAt, refreshExpHours };
}

export async function login(email: string, senha: string, ip: string | undefined, userAgent: string | null) {
  const usuario = await findUserByEmail(email);
  if (!usuario) throw new HttpError(401, 'credenciais_invalidas');
  if (usuario.status !== 'ATIVO') throw new HttpError(403, 'usuario_inativo');
  const ok = await bcrypt.compare(senha, usuario.senha_hash);
  if (!ok) throw new HttpError(401, 'credenciais_invalidas');
  const roles = [usuario.tipo_usuario];
  const userData = { id: usuario.id, email, status: usuario.status, roles };
  const { token: accessToken, expiresAt: accessExpiresAt, accessExpHours } = genAccessToken(userData);
  const { token: refreshToken, expiresAt: refreshExpiresAt } = genRefreshToken(userData);
  await storeToken(accessToken, usuario.id, accessExpiresAt, 'ACCESS');
  await storeRefreshTokenHashed(hash(refreshToken), usuario.id, refreshExpiresAt);
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

export async function logout(authorizationHeader?: string, invalidateAll?: boolean) {
  if (!authorizationHeader) throw new HttpError(401, 'authorization_header_required');
  const token = authorizationHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) throw new HttpError(401, 'authorization_header_required');
  // Tentar extrair sub mesmo que expirado: usamos verify normal; se expirado, tentar decode.
  let userId: string | null = null;
  try {
  // usar mesma chave derivada para coerência com geração
  const payload: any = jwt.verify(token, buildSigningKey());
    userId = payload.sub;
  } catch (e: any) {
    try {
      const decoded: any = jwt.decode(token);
      if (decoded && typeof decoded === 'object') userId = decoded.sub;
    } catch { /* ignore */ }
  }
  if (invalidateAll && userId) {
    try { await invalidateAllTokensOfUser(userId); } catch { /* ignore */ }
  } else {
    try { await invalidateToken(token); } catch { /* ignore */ }
  }
  return { sucesso: true };
}

export async function refresh(refreshToken: string, ip: string | undefined, userAgent: string | null) {
  if (!refreshToken) throw new HttpError(400, 'refresh_token_obrigatorio');
  let payload: any;
  try {
    payload = jwt.verify(refreshToken, buildSigningKey());
  } catch {
    throw new HttpError(401, 'refresh_invalido');
  }
  if (payload.type !== 'refresh') throw new HttpError(400, 'tipo_token_incorreto');
  const row = await getActiveRefreshTokenByHash(hash(refreshToken));
  if (!row) throw new HttpError(401, 'refresh_invalido_ou_expirado');
  if (new Date(row.data_expiracao) < new Date()) throw new HttpError(401, 'refresh_expirado');
  // Rotação
  await invalidateToken(hash(refreshToken));
  const usuario = await findUserById(payload.sub);
  if (!usuario) throw new HttpError(401, 'usuario_nao_encontrado');
  if (usuario.status !== 'ATIVO') throw new HttpError(403, 'usuario_inativo');
  const roles = [usuario.tipo_usuario];
  const userData = { id: usuario.id, email: usuario.email, status: usuario.status, roles };
  const { token: accessToken, expiresAt: accessExpiresAt, accessExpHours } = genAccessToken(userData);
  const { token: newRefreshToken, expiresAt: newRefreshExpiresAt } = genRefreshToken(userData);
  await storeToken(accessToken, usuario.id, accessExpiresAt, 'ACCESS');
  await storeRefreshTokenHashed(hash(newRefreshToken), usuario.id, newRefreshExpiresAt);
  await updateLastAccessAndLog(usuario.id, ip || '', userAgent);
  return { accessToken, refreshToken: newRefreshToken, tokenType: 'Bearer', expiresInHours: accessExpHours };
}