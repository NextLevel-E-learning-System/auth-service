import { config } from 'dotenv';
config();
import app from './server.js';
import { initDb } from './config/db.js';

initDb().then(() => {
  const port = Number(process.env.PORT || 3333);
  app.listen(port, () => console.log(`[auth-service] listening on ${port}`));
});
