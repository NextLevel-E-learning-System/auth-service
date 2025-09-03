import { Pool, PoolClient } from 'pg';
import dotenv from 'dotenv';
dotenv.config();

// Conexão mínima: só DATABASE_URL. SSL relaxado quando não é localhost.
if (!process.env.DATABASE_URL) {
  throw new Error('[auth-service][db] DATABASE_URL ausente');
}

const needSSL = !/localhost|127\.0\.0\.1/i.test(process.env.DATABASE_URL);
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: needSSL ? { rejectUnauthorized: false } : undefined
});

pool.on('error', (err: any) => {
  // eslint-disable-next-line no-console
  console.error('[auth-service][db] pool error', err?.code || err.message);
});

export async function withClient<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    const schema = (process.env.PG_SCHEMA || '').replace(/[^a-zA-Z0-9_]/g, '');
    if (schema) await client.query(`set search_path to ${schema}, public`);
    return await fn(client);
  } finally {
    client.release();
  }
}

export async function initDb() {
  await withClient(c => c.query('select 1'));
  if (process.env.LOG_LEVEL === 'debug') {
    // eslint-disable-next-line no-console
    console.log('[auth-service][db] initDb ok (simple)');
  }
}

export { pool };