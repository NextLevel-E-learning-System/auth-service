import { withClient } from '../database/db.js';

export async function findUserByEmail(email: string) {
  return withClient(async c => {
    const r = await c.query('select id, senha_hash, tipo_usuario, status from auth_service.usuarios where email=$1', [email]);
    return r.rows[0];
  });
}

export async function findUserById(id: string) {
  return withClient(async c => {
    const r = await c.query('select id, email, senha_hash, tipo_usuario, status from auth_service.usuarios where id=$1', [id]);
    return r.rows[0];
  });
}

export async function createUser(id: string, email: string, senhaHash: string) {
  await withClient(c => c.query('insert into auth_service.usuarios (id, email, senha_hash, tipo_usuario, status) values ($1,$2,$3,$4,$5)', [id, email, senhaHash, 'FUNCIONARIO', 'ATIVO']));
}

export async function createEmployee(id: string, cpf: string | null, nome: string, email: string, departamento: string, cargo: string) {
  await withClient(c => c.query('insert into user_service.funcionarios (id, cpf, nome, email, departamento_id, cargo, xp_total, nivel, status) values ($1,$2,$3,$4,$5,$6,0,$7,$8)', [id, cpf || null, nome, email, departamento, cargo, 'Iniciante', 'ATIVO']));
}

export async function departmentExists(codigo: string) {
  return withClient(async c => {
    const r = await c.query('select 1 from user_service.departamentos where codigo=$1', [codigo]);
  return !!r.rowCount;
  });
}

export async function updateLastAccessAndLog(id: string, ip: string, userAgent: string | null) {
  await withClient(async c => {
    await c.query('update auth_service.usuarios set ultimo_acesso=now() where id=$1', [id]);
    await c.query('insert into auth_service.logs_acesso (usuario_id, ip, user_agent) values ($1,$2,$3)', [id, ip, userAgent]);
  });
}

export async function storeToken(token: string, userId: string, expiresAt: Date, tipo: 'ACCESS' | 'REFRESH') {
  await withClient(c => c.query('insert into auth_service.tokens (token_jwt, usuario_id, data_expiracao, tipo_token) values ($1,$2,$3,$4)', [token, userId, expiresAt.toISOString(), tipo]));
}

// Para refresh tokens, armazenamos apenas o hash (sha256) – token puro não fica no banco
export async function storeRefreshTokenHashed(hash: string, userId: string, expiresAt: Date) {
  await withClient(c => c.query('insert into auth_service.tokens (token_jwt, usuario_id, data_expiracao, tipo_token) values ($1,$2,$3,$4)', [hash, userId, expiresAt.toISOString(), 'REFRESH']));
}

export async function invalidateToken(token: string) {
  await withClient(c => c.query('update auth_service.tokens set ativo=false where token_jwt=$1', [token]));
}

export async function getActiveToken(token: string, tipo: 'ACCESS' | 'REFRESH') {
  return withClient(async c => {
    const r = await c.query('select usuario_id, data_expiracao from auth_service.tokens where token_jwt=$1 and ativo=true and tipo_token=$2', [token, tipo]);
    return r.rows[0];
  });
}

export async function getActiveRefreshTokenByHash(hash: string) {
  return withClient(async c => {
    const r = await c.query('select usuario_id, data_expiracao from auth_service.tokens where token_jwt=$1 and ativo=true and tipo_token=$2', [hash, 'REFRESH']);
    return r.rows[0];
  });
}

export async function invalidateAllTokensOfUser(userId: string) {
  await withClient(c => c.query('update auth_service.tokens set ativo=false where usuario_id=$1 and ativo=true', [userId]));
}