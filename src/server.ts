import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { logger } from './config/logger.js';
import { loadOpenApi } from './config/openapi.js';
import { authRouter } from './routes/authRoutes.js';

export function createServer() {
  const app = express();
app.use(express.json());
  const allowAll = process.env.ALLOW_ALL_ORIGINS === 'true';
  app.use(cors({
    origin: allowAll ? (origin, cb) => cb(null, true) : (process.env.CORS_ORIGINS || '').split(',').filter(Boolean),
    credentials: true
  }));
app.use(cookieParser());
app.use((req: express.Request & { log?: typeof logger }, _res, next) => { req.log = logger; next(); });

app.get('/openapi.json', async (_req,res)=> {
  try {
    const openapiSpec = await loadOpenApi('Auth Service API');
    res.json(openapiSpec);
  } catch (error) {
    res.status(500).json({ error: 'Failed to load OpenAPI spec' });
  }
});

app.use('/auth/v1', authRouter);
  return app;
}