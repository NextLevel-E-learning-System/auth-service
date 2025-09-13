import { Request, Response } from 'express';
import { createUserAuth, loginUser, logoutUser, resetPassword } from '../services/authService.js';

export async function register(req: Request, res: Response) {
  try {
    const user = await createUserAuth(req.body);
    res.status(201).json(user);
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
}

export async function login(req: Request, res: Response) {
  try {
    const token = await loginUser(req.body.email, req.body.senha);
    res.json({ token });
  } catch (err) {
    res.status(401).json({ error: (err as Error).message });
  }
}

export async function reset(req: Request, res: Response) {
  try {
    const { email } = req.body;
    await resetPassword(email);
    res.json({ message: 'Senha enviada por email' });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
}

export async function refresh(req: Request, res: Response) {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: 'Refresh token ausente' });

    const token = await refreshToken(refreshToken);
    res.json({ token });
  } catch (err) {
    res.status(401).json({ error: (err as Error).message });
  }
}

export async function logout(req: Request, res: Response) {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(400).json({ error: 'Token ausente' });

    await logoutUser(token);
    res.json({ message: 'Logout efetuado com sucesso' });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
}
