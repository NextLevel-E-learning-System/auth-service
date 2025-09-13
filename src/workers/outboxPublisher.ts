import { withClient } from '../config/db.js';
import { connectRabbitMQ, publishEvent } from '../config/rabbitmq.js';

const INTERVAL_MS = Number(process.env.OUTBOX_INTERVAL_MS || 4000);

export async function processAuthOutbox() {
  await connectRabbitMQ();
  await withClient(async (c) => {
    const { rows } = await c.query(`
      SELECT id, event_type, payload FROM auth_service.outbox_events 
      WHERE published=false ORDER BY created_at ASC LIMIT 25
    `);
    for (const evt of rows) {
      try {
        const data = typeof evt.payload === 'string' ? JSON.parse(evt.payload) : evt.payload;
        await publishEvent(evt.event_type, data);
        await c.query(`UPDATE auth_service.outbox_events SET published=true WHERE id=$1`, [evt.id]);
        // eslint-disable-next-line no-console
        console.log('[auth-service][outbox] published', evt.event_type, evt.id);
      } catch (err) {
        console.error('[auth-service][outbox] erro publicando evento', evt.event_type, err);
      }
    }
  });
}

export function startAuthOutboxLoop() {
  setInterval(() => {
    processAuthOutbox().catch(err => console.error('[auth-service][outbox] loop error', err));
  }, INTERVAL_MS);
}