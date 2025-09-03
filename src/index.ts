import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import path from 'path';
// Carrega .env explicitamente (diretório fixo do serviço)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
config({ path: path.resolve(__dirname, '../.env') });

// Validação de variáveis obrigatórias antes de subir servidor
const requiredVars = ['DATABASE_URL', 'JWT_SECRET'];
const missing = requiredVars.filter(v => !process.env[v]);
if (missing.length) {
  // eslint-disable-next-line no-console
  console.error('[auth-service][startup] Variáveis obrigatórias ausentes:', missing.join(', '));
  throw new Error('Variáveis de ambiente obrigatórias ausentes.');
}

import { createServer } from './server.js';

const port = Number(process.env.PORT || 3333);
if (process.env.LOG_LEVEL === 'debug') {
  // eslint-disable-next-line no-console
  console.log('[auth-service][startup] Variáveis carregadas OK. Porta:', port);
}
createServer().listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`[auth-service] listening on ${port}`);
});