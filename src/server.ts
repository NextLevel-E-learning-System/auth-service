import express from 'express';
import cors from 'cors';
import { logger } from './config/logger.js';
import { loadOpenApi } from './config/openapi.js';
import swaggerUi from 'swagger-ui-express';
import { healthRouter } from './routes/healthRoutes.js';
import { authRouter } from './routes/authRoutes.js';
import { errorHandler } from './middleware/errorHandler.js';

export function createServer() {
  const app = express();
  app.use(express.json());
  app.use(cors({ origin: '*' }));
  app.use((req, _res, next) => { (req as any).log = logger; next(); });

  // Docs
  const openapiSpec = loadOpenApi('Auth Service API');
  app.get('/openapi.json', (_req,res)=> res.json(openapiSpec));
  app.use('/docs', swaggerUi.serve, swaggerUi.setup(openapiSpec));

  // Core routes
  app.use(healthRouter);
  app.use('/auth/v1', authRouter);

  // Error handler
  app.use(errorHandler);
  return app;
}