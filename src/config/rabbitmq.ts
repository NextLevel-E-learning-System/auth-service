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

export async function publishEvent<T>(routingKey: string, payload: T, options?: Options.Publish) {
  if (!channel) await connectRabbitMQ();
  const event: DomainEvent<T> = { type: routingKey, payload, emittedAt: new Date().toISOString() };
  const content = Buffer.from(JSON.stringify(event));
  channel!.publish(EXCHANGE_AUTH, routingKey, content, { persistent: true, contentType: 'application/json', ...options });
}

export async function closeRabbit() {
  try { if (channel) await channel.close(); } catch (err) { console.error('[auth-service][rabbitmq] erro fechando canal', (err as any)?.message); }
  try { if (connection) await connection.close(); } catch (err) { console.error('[auth-service][rabbitmq] erro fechando conexão', (err as any)?.message); }
  channel = undefined; connection = undefined;
}

export function getChannel() { return channel; }
