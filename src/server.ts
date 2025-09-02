import express from 'express';
import cors from 'cors';
import pino from 'pino';
import * as jwt from 'jsonwebtoken';
import { randomUUID } from 'crypto';
import { z } from 'zod';
import bcrypt from 'bcrypt';
import { withClient } from './db';

const logger = pino({ level: process.env.LOG_LEVEL || 'info' });

export function createServer() {
  const app = express();
  app.use(express.json());
  app.use(cors({ origin: '*'}));
  app.use((req, _res, next) => { (req as any).log = logger; next(); });

  app.get('/health/live', (_req, res) => res.json({ status: 'ok' }));
  app.get('/health/ready', (_req, res) => res.json({ status: 'ok' }));

  // LOGIN (R02) - expiração 8h, registra log e atualiza ultimo_acesso
  app.post('/auth/v1/login', async (req, res) => {
    const schema = z.object({ email: z.string().email(), senha: z.string().min(6) });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'validation_error', details: parsed.error.issues });
    try {
      const usuario = await withClient(async c => {
        const r = await c.query('select id, senha_hash, tipo_usuario, status from usuarios where email=$1', [parsed.data.email]);
        return r.rows[0];
      });
      if (!usuario) return res.status(401).json({ error: 'credenciais_invalidas' });
      if (usuario.status !== 'ATIVO') return res.status(403).json({ error: 'usuario_inativo' });
      const ok = await bcrypt.compare(parsed.data.senha, usuario.senha_hash);
      if (!ok) return res.status(401).json({ error: 'credenciais_invalidas' });
      const accessExpHours = 8; // conforme R02
      const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000);
      const roles = [usuario.tipo_usuario];
      const token = jwt.sign({ sub: usuario.id, roles }, process.env.JWT_SECRET || 'dev-secret', { expiresIn: `${accessExpHours}h` as any });
      await withClient(async c => {
        await c.query('insert into tokens (token_jwt, usuario_id, data_expiracao) values ($1,$2,$3)', [token, usuario.id, expiresAt.toISOString()]);
        await c.query('update usuarios set ultimo_acesso=now() where id=$1', [usuario.id]);
        await c.query('insert into logs_acesso (usuario_id, ip, user_agent) values ($1,$2,$3)', [usuario.id, req.ip, req.headers['user-agent'] || null]);
      });
      res.json({ accessToken: token, tokenType: 'Bearer', expiresInHours: accessExpHours });
    } catch (err:any) {
      logger.error({ err }, 'login_failed');
      res.status(500).json({ error: 'erro_interno' });
    }
  });

  // Refresh não faz parte do escopo atual (R02). Endpoint placeholder.
  app.post('/auth/v1/refresh', (_req, res) => res.status(501).json({ error: 'nao_suportado' }));

  // AUTOCADASTRO (R01) - gera senha numérica 6 dígitos, cria usuário e funcionário
  app.post('/auth/v1/register', async (req, res) => {
    const schema = z.object({
      cpf: z.string().min(11).max(14),
      nome: z.string().min(2),
      email: z.string().email(),
      departamento: z.string().min(2),
      cargo: z.string().min(2)
    });
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: 'validation_error', details: parsed.error.issues });
    const { cpf, nome, email, departamento, cargo } = parsed.data;
    try {
      // Validação domínio
      const allowed = (process.env.ALLOWED_EMAIL_DOMAINS || '').split(',').map(d => d.trim()).filter(Boolean);
      if (allowed.length > 0) {
        const domain = email.split('@')[1];
        if (!allowed.includes(domain)) return res.status(400).json({ error: 'dominio_invalido' });
      }
      const id = randomUUID();
      const senhaPlano = Math.floor(100000 + Math.random() * 900000).toString(); // 6 dígitos
      const hash = await bcrypt.hash(senhaPlano, 12);
      await withClient(async c => {
        await c.query('insert into usuarios (id, email, senha_hash, tipo_usuario, status) values ($1,$2,$3,$4,$5)', [id, email, hash, 'FUNCIONARIO', 'ATIVO']);
        // cria funcionário (user_service schema referenciado explicitamente)
        await c.query('insert into user_service.funcionarios (id, cpf, nome, email, departamento_id, cargo, xp_total, nivel, status) values ($1,$2,$3,$4,$5,$6,0,$7,$8)', [id, cpf, nome, email, departamento, cargo, 'Iniciante', 'ATIVO']);
      });
      logger.info({ id, email }, 'usuario_cadastrado');
      // Em produção a senha seria enviada por e-mail. Aqui retornamos somente mensagem.
      res.status(201).json({ id, email, mensagem: 'Senha enviada por e-mail (simulado)' });
    } catch (err:any) {
      if (err.code === '23505') return res.status(409).json({ error: 'duplicado' });
      logger.error({ err }, 'registro_falhou');
      res.status(500).json({ error: 'erro_interno' });
    }
  });

  // LOGOUT simples: invalida token atual
  app.post('/auth/v1/logout', async (req, res) => {
    const auth = req.header('authorization');
    if (!auth) return res.status(400).json({ error: 'token_nao_informado' });
    const token = auth.replace(/^Bearer\s+/i, '');
    try {
      await withClient(c => c.query('update tokens set ativo=false where token_jwt=$1', [token]));
      res.json({ sucesso: true });
    } catch (err:any) {
      logger.error({ err }, 'logout_falhou');
      res.status(500).json({ error: 'erro_interno' });
    }
  });

  return app;
}