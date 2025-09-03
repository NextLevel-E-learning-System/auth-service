import { z } from 'zod';

export const loginSchema = z.object({ email: z.string().email(), senha: z.string().min(6) });

// Schema para auto-cadastro - apenas email obrigatório
export const registerSchema = z.object({
  email: z.string().email('Email deve ter formato válido').refine(
    (email) => email.endsWith('@gmail.com'),
    'Apenas emails @gmail.com são permitidos para auto-cadastro'
  )
});

export const refreshSchema = z.object({ refreshToken: z.string().min(10) });