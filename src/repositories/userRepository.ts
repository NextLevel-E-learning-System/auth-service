import { withClient } from '../db.js';

export async function findUserByEmail(email: string) {
  return withClient(async c => {
    const r = await c.query('select id, senha_hash, tipo_usuario, status from usuarios where email=$1', [email]);
    return r.rows[0];
  });
}

export async function createUser(id: string, email: string, senhaHash: string) {
  await withClient(c => c.query('insert into usuarios (id, email, senha_hash, tipo_usuario, status) values ($1,$2,$3,$4,$5)', [id, email, senhaHash, 'FUNCIONARIO', 'ATIVO']));
}

export async function createEmployee(id: string, cpf: string, nome: string, email: string, departamento: string, cargo: string) {
  await withClient(c => c.query('insert into user_service.funcionarios (id, cpf, nome, email, departamento_id, cargo, xp_total, nivel, status) values ($1,$2,$3,$4,$5,$6,0,$7,$8)', [id, cpf, nome, email, departamento, cargo, 'Iniciante', 'ATIVO']));
}

export async function updateLastAccessAndLog(id: string, ip: string, userAgent: string | null) {
  await withClient(async c => {
    await c.query('update usuarios set ultimo_acesso=now() where id=$1', [id]);
    await c.query('insert into logs_acesso (usuario_id, ip, user_agent) values ($1,$2,$3)', [id, ip, userAgent]);
  });
}

export async function storeToken(token: string, userId: string, expiresAt: Date) {
  await withClient(c => c.query('insert into tokens (token_jwt, usuario_id, data_expiracao) values ($1,$2,$3)', [token, userId, expiresAt.toISOString()]));
}

export async function invalidateToken(token: string) {
  await withClient(c => c.query('update tokens set ativo=false where token_jwt=$1', [token]));
}