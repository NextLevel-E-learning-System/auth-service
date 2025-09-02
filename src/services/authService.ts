import { randomUUID } from 'crypto';
import bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { findUserByEmail, createUser, createEmployee, storeToken, updateLastAccessAndLog, invalidateToken } from '../repositories/userRepository.js';
import { HttpError } from '../utils/httpError.js';

export async function login(email: string, senha: string, ip: string | undefined, userAgent: string | null) {
  const usuario = await findUserByEmail(email);
  if (!usuario) throw new HttpError(401, 'credenciais_invalidas');
  if (usuario.status !== 'ATIVO') throw new HttpError(403, 'usuario_inativo');
  const ok = await bcrypt.compare(senha, usuario.senha_hash);
  if (!ok) throw new HttpError(401, 'credenciais_invalidas');
  const accessExpHours = 8;
  const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000);
  const roles = [usuario.tipo_usuario];
  const token = jwt.sign({ sub: usuario.id, roles }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: `${accessExpHours}h` as any });
  await storeToken(token, usuario.id, expiresAt);
  await updateLastAccessAndLog(usuario.id, ip || '', userAgent);
  return { accessToken: token, tokenType: 'Bearer', expiresInHours: accessExpHours };
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