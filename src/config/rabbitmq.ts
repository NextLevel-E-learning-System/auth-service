import amqplib from 'amqplib';
import { Options } from 'amqplib';

// Tipagem simplificada para evitar conflitos de definição (ajuste posterior se necessário)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let channel: any | undefined; // Channel
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let connection: any | undefined; // Connection

const EXCHANGE_AUTH = process.env.EXCHANGE_AUTH || 'auth.events'; // direct

// eslint-disable-next-line @typescript-eslint/explicit-module-boundary-types
export async function connectRabbitMQ() {
  if (channel) return channel;
  const url = process.env.RABBITMQ_URL || 'amqp://localhost';
  connection = await amqplib.connect(url);
  channel = await connection.createChannel();
  await channel.assertExchange(EXCHANGE_AUTH, 'direct', { durable: true });
  // Dead-letter infra básica (apenas placeholder)
  await channel.assertExchange('dlx.events', 'fanout', { durable: true });
  await channel.assertQueue('dlx.events', { durable: true });
  await channel.bindQueue('dlx.events', 'dlx.events', '');
  // controle de throughput básico
  channel.prefetch(20);
  return channel;
}

export interface DomainEvent<T=unknown> { type: string; payload: T; emittedAt: string; }

interface RetryConfig { attempts: number; baseDelayMs: number; maxDelayMs: number; }
const RETRY_CFG: RetryConfig = {
  attempts: Number(process.env.RABBITMQ_PUBLISH_RETRY_ATTEMPTS || 4),
  baseDelayMs: Number(process.env.RABBITMQ_PUBLISH_RETRY_BASE_DELAY_MS || 80),
  maxDelayMs: Number(process.env.RABBITMQ_PUBLISH_RETRY_MAX_DELAY_MS || 1500)
};

function sleep(ms: number) { return new Promise(res => setTimeout(res, ms)); }

// Retry exponencial simples com jitter. Focado em falhas transitórias de canal/conexão.
export async function publishEvent<T>(routingKey: string, payload: T, options?: Options.Publish) {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= RETRY_CFG.attempts; attempt++) {
    try {
      if (!channel) await connectRabbitMQ();
      const event: DomainEvent<T> = { type: routingKey, payload, emittedAt: new Date().toISOString() };
      const content = Buffer.from(JSON.stringify(event));
      const ok = channel!.publish(EXCHANGE_AUTH, routingKey, content, { persistent: true, contentType: 'application/json', ...options });
      if (!ok) {
        // Backpressure: esperar dreno do buffer
        await new Promise<void>((resolve) => channel!.once('drain', resolve));
      }
      return; // sucesso
    } catch (err) {
      lastErr = err;
      // Resetar canal/conexão para próxima tentativa
      try { await closeRabbit(); } catch { /* ignore */ }
      if (attempt < RETRY_CFG.attempts) {
        const expDelay = Math.min(RETRY_CFG.baseDelayMs * 2 ** (attempt - 1), RETRY_CFG.maxDelayMs);
        const jitter = Math.random() * expDelay * 0.25; // até 25% de jitter
        const delay = expDelay + jitter;
        // eslint-disable-next-line no-console
  const msg = err instanceof Error ? err.message : String(err);
  console.warn(`[auth-service][rabbitmq] publish retry ${attempt}/${RETRY_CFG.attempts - 1} em ${Math.round(delay)}ms (evento=${routingKey})`, msg);
        await sleep(delay);
        continue;
      }
    }
  }
  // eslint-disable-next-line no-console
  const finalMsg = lastErr instanceof Error ? lastErr.message : String(lastErr);
  console.error('[auth-service][rabbitmq] falha definitiva publicando evento', routingKey, finalMsg);
  throw lastErr;
}

export async function closeRabbit() {
  try { if (channel) await channel.close(); } catch (err) { console.error('[auth-service][rabbitmq] erro fechando canal', err instanceof Error ? err.message : String(err)); }
  try { if (connection) await connection.close(); } catch (err) { console.error('[auth-service][rabbitmq] erro fechando conexão', err instanceof Error ? err.message : String(err)); }
  channel = undefined; connection = undefined;
}

export function getChannel() { return channel; }
