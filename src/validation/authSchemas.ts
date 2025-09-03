import { z } from 'zod';

export const loginSchema = z.object({ email: z.string().email(), senha: z.string().min(6) });
export const registerSchema = z.object({
  cpf: z.string().min(11).max(14),
  nome: z.string().min(2),
  email: z.string().email(),
  departamento: z.string().min(2),
  cargo: z.string().min(2)
});

export const refreshSchema = z.object({ refreshToken: z.string().min(10) });