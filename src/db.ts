import { Pool, PoolClient } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function withClient<T>(fn: (c: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    if (process.env.PG_SCHEMA) {
      await client.query(`set search_path to ${process.env.PG_SCHEMA}, public`);
    }
    return await fn(client);
  } finally {
    client.release();
  }
}

export async function initDb() {
  // simples verificação
  await withClient(c => c.query('select 1'));
}