import { Pool, PoolClient } from 'pg';
import dotenv from 'dotenv';
dotenv.config();

if (!process.env.DATABASE_URL) throw new Error('[auth-service][db] DATABASE_URL ausente');

const needSSL = !/localhost|127\.0\.0\.1/i.test(process.env.DATABASE_URL);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: needSSL ? { rejectUnauthorized: false } : undefined
});

pool.on('error', err => console.error('[auth-service][db] pool error', err));

export async function withClient<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    const schema = (process.env.PG_SCHEMA || '').replace(/[^a-zA-Z0-9_]/g, '');
    if (schema) await client.query(`set search_path to ${schema}, public`);
    return await fn(client);
  } finally { client.release(); }
}

export async function initDb() {
  await withClient(c => c.query('select 1'));
  console.log('[auth-service][db] initDb ok');
}

export { pool };
