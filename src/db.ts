import { Pool, PoolClient } from 'pg';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import path from 'path';

// Carrega .env de forma determinística relativo ao arquivo, evitando dependência do cwd
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../.env');
dotenv.config({ path: envPath });

// Validação mínima das variáveis críticas antes de criar o pool
if (!process.env.DATABASE_URL) {
  throw new Error('[auth-service][startup] DATABASE_URL ausente. Defina em auth-service/.env ou no ambiente.');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

if (process.env.LOG_LEVEL === 'debug') {
  try {
    const hostPort = process.env.DATABASE_URL.split('@')[1]?.split('/')[0];
    // eslint-disable-next-line no-console
    console.log('[auth-service][db] inicializando pool para host:', hostPort);
  } catch { /* ignore */ }
}

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