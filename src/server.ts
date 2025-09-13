import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import { logger } from './config/logger.js';
import { loadOpenApi } from './config/openapi.js';
import swaggerUi from 'swagger-ui-express';
import { authRouter } from './routes/authRoutes.js';
import { errorHandler } from './middleware/errorHandler.js';

export function createServer() {
  const app = express();
app.use(express.json());
  const allowAll = process.env.ALLOW_ALL_ORIGINS === 'true';
  app.use(cors({
    origin: allowAll ? (origin, cb) => cb(null, true) : (process.env.CORS_ORIGINS || '').split(',').filter(Boolean),
    credentials: true
  }));
app.use(cookieParser());
app.use((req, _res, next) => { (req as any).log = logger; next(); });

const openapiSpec = loadOpenApi('Auth Service API');
app.get('/openapi.json', (_req,res)=> res.json(openapiSpec));
app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapiSpec));

app.use('/auth/v1', authRouter);
app.use(errorHandler);
  return app;
}