import { config } from 'dotenv';
config();
import app from './server.js';
import { initDb } from './config/db.js';
import { connectRabbitMQ } from './config/rabbitmq.js';
import { startAuthOutboxLoop } from './workers/outboxPublisher.js';

async function bootstrap() {
  await initDb();
  await connectRabbitMQ();
  startAuthOutboxLoop();
  const port = Number(process.env.PORT || 3333);
  app.listen(port, () => console.log(`[auth-service] listening on ${port}`));
}

bootstrap().catch(err => {
  console.error('[auth-service] falha bootstrap', err);
  process.exit(1);
});
