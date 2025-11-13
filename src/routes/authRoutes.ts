import { Router } from 'express';
import { login, logout, refresh, reset, me } from '../controllers/authController.js';

export const authRouter = Router();
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/refresh', refresh);
authRouter.post('/reset-password', reset);
authRouter.get('/me', me);
