import { Router } from 'express';
import { register, login, logout, refresh, reset } from '../controllers/authController.js';

export const authRouter = Router();
authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/refresh', refresh);
authRouter.post('/reset-password', reset);
