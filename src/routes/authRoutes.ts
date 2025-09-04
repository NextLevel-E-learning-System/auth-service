import { Router } from 'express';
import { loginHandler, registerHandler, logoutHandler, refreshHandler, resetPasswordHandler } from '../controllers/authController.js';

export const authRouter = Router();
authRouter.post('/login', loginHandler);
authRouter.post('/register', registerHandler);
authRouter.post('/logout', logoutHandler);
authRouter.post('/refresh', refreshHandler);
authRouter.post('/reset-password', resetPasswordHandler);