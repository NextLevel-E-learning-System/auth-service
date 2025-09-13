import { Request, Response } from 'express';
import { createUserAuth, loginUser, logoutUser, resetPassword } from '../services/authService.js';

// Validação simples de CPF (mesmo algoritmo do banco para evitar roundtrip desnecessário)
function isValidCPF(raw?: string): boolean {
  if (!raw) return false;
  const s = raw.replace(/[^0-9]/g, '');
  if (s.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(s)) return false; // todos iguais
  const calcDigit = (base: string, factorStart: number) => {
    let sum = 0; let factor = factorStart;
    for (const ch of base) { sum += parseInt(ch, 10) * factor--; }
    const mod = sum % 11;
    return mod < 2 ? 0 : 11 - mod;
  };
  const d1 = calcDigit(s.substring(0, 9), 10);
  if (d1 !== parseInt(s[9], 10)) return false;
  const d2 = calcDigit(s.substring(0, 10), 11);
  return d2 === parseInt(s[10], 10);
}

export async function register(req: Request, res: Response) {
  try {

    if (req.body.cpf && !isValidCPF(req.body.cpf)) {
      return res.status(400).json({ error: 'cpf_invalido' });
    }

    const user = await createUserAuth(req.body);
    res.status(201).json(user);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    // Traduz constraint do banco se vier mensagem padrão
    if (message.includes('cpf_valido')) {
      return res.status(400).json({ error: 'cpf_invalido' });
    }
    res.status(400).json({ error: message });
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
