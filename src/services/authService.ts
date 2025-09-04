import { randomUUID, createHash } from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { findUserByEmail, findUserById, createUser, createEmployee, storeToken, updateLastAccessAndLog, invalidateToken, invalidateAllTokensOfUser, getActiveToken, storeRefreshTokenHashed, getActiveRefreshTokenByHash, updateUserPassword } from '../repositories/authRepository.js';
import { sendRegistrationEmail, sendPasswordResetEmail } from '../utils/emailService.js';
import { createHash as cryptoCreateHash } from 'crypto';
import { HttpError } from '../utils/httpError.js';

function buildSigningKey() {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return createHash('sha256').update(secret).digest();
}

function genAccessToken(user: { id: string; email: string; status: string; roles: string[] }) {
  const accessExpHours = parseInt(process.env.ACCESS_TOKEN_EXP_HOURS || '8', 10);
  const key = buildSigningKey();
  const payload = { sub: user.id, email: user.email, status: user.status, roles: user.roles, type: 'access' };
  const token = jwt.sign(payload, key, { expiresIn: `${accessExpHours}h` as any });
  const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000);
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

export async function register(data: { 
  nome: string;
  cpf: string; 
  email: string; 
  departamento_id: string;
  cargo: string;
}) {
  const { nome, cpf, email, departamento_id, cargo } = data;
  
  // Validar domínio do email (configurável via env)
  const allowedDomains = (process.env.ALLOWED_EMAIL_DOMAINS || 'gmail.com').split(',');
  const isValidDomain = allowedDomains.some(domain => email.endsWith(`@${domain.trim()}`));
  
  if (!isValidDomain) {
    throw new HttpError(400, 'dominio_nao_permitido', `Apenas emails dos domínios ${allowedDomains.join(', ')} são permitidos para auto-cadastro`);
  }

  // Verificar se email já está cadastrado no auth_service
  const usuarioExistente = await findUserByEmail(email);
  if (usuarioExistente) {
    throw new HttpError(409, 'email_ja_cadastrado', 'Este email já está cadastrado no sistema');
  }

  const id = randomUUID();
  
  // Gerar senha numérica de 6 dígitos
  const senhaPlano = Math.floor(100000 + Math.random() * 900000).toString();
  
  // Hash da senha com bcrypt cost 12
  const hashPwd = await bcrypt.hash(senhaPlano, 12);
 
  try {
    // Criar usuário no auth_service com status ATIVO e tipo FUNCIONARIO
    await createUser(id, email, hashPwd);
    
    // Criar funcionário completo no user_service
    await createEmployee(id, cpf, nome, email, departamento_id, cargo);

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
    if (err.code === '23503') { // Violação de foreign key
      if (err.constraint?.includes('departamento')) {
        throw new HttpError(400, 'departamento_invalido', 'Departamento não encontrado');
      }
    }
    throw err;
  }

  // Enviar e-mail com a senha  usando Gmail SMTP
  try {
    await sendRegistrationEmail({ 
      nome: nome,
      email: email, 
      senha: senhaPlano,
      departamento: departamento_id
    });
  } catch (emailError) {
    console.error('Erro ao enviar email:', emailError);
    // Não falhar o registro se o email não for enviado
  }

  // Log de acesso para registrar a criação (registra no logs_acesso)
  try { 
    await updateLastAccessAndLog(id, '', 'auto-register'); 
  } catch (logError) { 
    console.error('Erro ao registrar log:', logError);
  }

  return { 
    id, 
    nome,
    cpf,
    email,
    departamento_id,
    cargo,
    tipo_usuario: 'FUNCIONARIO',
    status: 'ATIVO',
    mensagem: 'Usuário criado com sucesso. Senha enviada por e-mail.' 
  };
}

export async function logout(authorizationHeader?: string, invalidateAll?: boolean) {
  if (!authorizationHeader) throw new HttpError(401, 'authorization_header_required');
  const token = authorizationHeader.replace(/^Bearer\s+/i, '').trim();
  if (!token) throw new HttpError(401, 'authorization_header_required');
  let userId: string | null = null;
  try {
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

export async function resetPassword(params: { email?: string; userId?: string; }) {
  const { email, userId } = params;
  if (!email && !userId) throw new HttpError(400, 'email_ou_userid_obrigatorio');
  const usuario = email ? await findUserByEmail(email) : await findUserById(userId!);
  if (!usuario) throw new HttpError(404, 'usuario_nao_encontrado');
  if (usuario.status !== 'ATIVO') throw new HttpError(403, 'usuario_inativo');
  const novaSenha = Math.floor(100000 + Math.random() * 900000).toString();
  const hashPwd = await bcrypt.hash(novaSenha, 12);
  await updateUserPassword(usuario.id, hashPwd);
  try { await invalidateAllTokensOfUser(usuario.id); } catch { /* ignore */ }
  const nomeBase = (usuario.email && typeof usuario.email === 'string' && usuario.email.includes('@'))
    ? usuario.email.split('@')[0]
    : 'usuario';
  if (!usuario.email) {
    console.warn('[resetPassword][warn] email_inexistente_para_usuario', { userId: usuario.id });
  }
  try {
    await sendPasswordResetEmail({ nome: nomeBase, email: usuario.email || email || '', novaSenha });
  } catch (e) { console.error('[resetPassword][email_fail]', e); }
  try { await updateLastAccessAndLog(usuario.id, '', 'reset-password'); } catch { /* ignore */ }
  return { sucesso: true };
}