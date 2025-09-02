import { Router } from 'express';
export const healthRouter = Router();
healthRouter.get('/health/live', (_req, res) => res.json({ status: 'ok' }));
healthRouter.get('/health/ready', (_req, res) => res.json({ status: 'ok' }));