import { z } from 'zod';

export const loginSchema = z.object({ email: z.string().email(), senha: z.string().min(6) });

// Schema para cadastro completo do funcionário
export const registerSchema = z.object({
  nome: z.string().min(1, 'Nome é obrigatório'),
  cpf: z.string().regex(/^\d{11}$/, 'CPF deve conter exatamente 11 dígitos'),
  email: z.string().email('Email deve ter formato válido').refine(
    (email) => {
      const allowedDomains = (process.env.ALLOWED_EMAIL_DOMAINS || 'gmail.com').split(',');
      return allowedDomains.some(domain => email.endsWith(`@${domain.trim()}`));
    },
    'Email deve pertencer a um domínio autorizado'
  ),
  departamento_id: z.string().min(1, 'Departamento é obrigatório'),
  cargo: z.string().min(1, 'Cargo é obrigatório')
});

export const refreshSchema = z.object({ refreshToken: z.string().min(10) });