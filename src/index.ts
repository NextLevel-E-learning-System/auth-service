import { config } from 'dotenv';
config();
import { createServer } from './server';

const port = Number(process.env.PORT || 3333);
createServer().listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`[auth-service] listening on ${port}`);
});