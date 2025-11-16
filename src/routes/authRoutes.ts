import { Router } from 'express';
import { login, logout, refresh } from '../controllers/authController.js';

export const authRouter = Router();
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/refresh', refresh);
