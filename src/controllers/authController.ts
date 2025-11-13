import { Request, Response } from "express";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import { createHash } from 'crypto';
import { withClient } from "../config/db.js";
import { publishEvent } from "../config/rabbitmq.js";
// Respostas simplificadas diretas sem abstração excessiva

interface UserData {
  id: string;
  email: string;
  ativo: boolean;
  roles: string; // Single role, not array
}

function buildSigningKey() {
  const secret = process.env.JWT_SECRET || 'dev-secret';
  return createHash('sha256').update(secret).digest();
}

function genAccessToken(user: UserData) {
  const accessExpHours = parseInt(process.env.ACCESS_TOKEN_EXP_HOURS || '8', 10);
  const key = buildSigningKey();
  
  // Payload com informações essenciais do usuário
  const payload = { 
    sub: user.id, 
    email: user.email, 
    ativo: user.ativo, 
    roles: user.roles, 
    type: 'access' 
  };
  
  const token = jwt.sign(payload, key, { expiresIn: `${accessExpHours}h` });
  const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000);
  return { token, expiresAt, accessExpHours };
}

function genRefreshToken(user: UserData) {
  const refreshExpHours = parseInt(process.env.REFRESH_TOKEN_EXP_HOURS || '24', 10);
  const key = buildSigningKey();
  
  // Para refresh token, incluir apenas informações essenciais
  const payload = { 
    sub: user.id, 
    email: user.email, 
    ativo: user.ativo, 
    roles: user.roles, 
    type: 'refresh' 
  };
  
  const token = jwt.sign(payload, key, { expiresIn: `${refreshExpHours}h` });
  const expiresAt = new Date(Date.now() + refreshExpHours * 60 * 60 * 1000);
  return { token, expiresAt, refreshExpHours };
}

function hash(value: string) {
  return createHash('sha256').update(value).digest('hex');
}

interface PgErrorLike { code?: string }
function isPgError(obj: unknown): obj is PgErrorLike {
  return typeof obj === 'object' && obj !== null && 'code' in obj;
}


export const login = async (req: Request, res: Response) => {
  const { email, senha } = req.body;

  await withClient(async (c) => {
    // Buscar usuário com informações completas incluindo dados do funcionário
    const { rows } = await c.query(
      `SELECT u.funcionario_id, u.email, u.ativo, u.senha_hash,
              f.nome, f.departamento_id, f.cargo_nome, f.xp_total, f.nivel, f.role
       FROM auth_service.usuarios u
       LEFT JOIN user_service.funcionarios f ON u.funcionario_id = f.id AND f.ativo = true
       WHERE u.email = $1 AND u.ativo = true`,
      [email]
    );
    
    const user = rows[0];
    if (!user) {
  return res.status(401).json({ erro: 'credenciais_invalidas', mensagem: 'Credenciais inválidas' });
    }

    const valid = await bcrypt.compare(senha, user.senha_hash);
    if (!valid) {
  return res.status(401).json({ erro: 'credenciais_invalidas', mensagem: 'Credenciais inválidas' });
    }

    const userData = { 
      id: user.funcionario_id, 
      email: user.email, 
      ativo: user.ativo,
      roles: user.role
    };

    // Gerar tokens com informações completas
    const { token: accessToken, expiresAt: accessExpiresAt, accessExpHours } = genAccessToken(userData);
    const { token: refreshToken, expiresAt: refreshExpiresAt } = genRefreshToken(userData);

    // Armazenar tokens no banco
    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'ACCESS', $3)`,
      [accessToken, user.funcionario_id, accessExpiresAt]
    );
    
    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'REFRESH', $3)`,
      [hash(refreshToken), user.funcionario_id, refreshExpiresAt]
    );

    // Log de acesso
    await c.query(
      `UPDATE auth_service.usuarios SET ultimo_acesso = NOW() WHERE funcionario_id = $1`,
      [user.funcionario_id]
    );

    await c.query(
      `INSERT INTO auth_service.logs_acesso(funcionario_id, ip, user_agent)
       VALUES ($1,$2,$3)`,
      [user.funcionario_id, req.ip, req.headers["user-agent"]]
    );

    // Publicar evento de login
    try {
      await publishEvent('auth.login', { userId: user.funcionario_id, email: user.email });
    } catch (e) {
      console.error('[auth-service] falha publicando auth.login', (e as Error).message);
    }

    // Configurar cookies HTTP-only
    const isProduction = process.env.NODE_ENV === 'production';
    const cookieOptions = {
      httpOnly: true,
      secure: isProduction, // HTTPS apenas em produção
      sameSite: 'lax' as const,
      path: '/',
      maxAge: accessExpHours * 60 * 60 * 1000, // em milissegundos
    };

    const refreshCookieOptions = {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax' as const,
      path: '/',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 dias
    };

    // Setar cookies
    res.cookie('accessToken', accessToken, cookieOptions);
    res.cookie('refreshToken', refreshToken, refreshCookieOptions);

    // Retornar resposta SEM os tokens (eles estão nos cookies)
    res.status(200).json({ 
      mensagem: 'Login realizado com sucesso',
      usuario: {
        id: user.funcionario_id,
        nome: user.nome,
        email: user.email,
        departamento: user.departamento_id,
        cargo: user.cargo_nome,
        xp: user.xp_total,
        nivel: user.nivel,
        role: user.role
      }
    });
  });
};

export const refresh = async (req: Request, res: Response) => {
  // Buscar refresh token do cookie ao invés do body
  const refreshToken = req.cookies?.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ 
      erro: 'refresh_token_ausente', 
      mensagem: 'Refresh token não encontrado' 
    });
  }
  
  try {
    const key = buildSigningKey();
    const decoded = jwt.verify(refreshToken, key) as { sub: string; email: string; status: string; roles: string; iat: number; exp: number };

    await withClient(async (c) => {
      // Verificar se o refresh token hasheado existe e está ativo
      const { rows } = await c.query(
        `SELECT * FROM auth_service.tokens 
         WHERE token_jwt=$1 AND ativo=true AND tipo_token='REFRESH' AND data_expiracao > NOW()`,
        [hash(refreshToken)]
      );
      
      if (!rows[0]) {
  return res.status(401).json({ erro: 'refresh_token_invalido', mensagem: 'Refresh token inválido' });
      }

      // Buscar dados atualizados do usuário para o novo token
      const { rows: userRows } = await c.query(
        `SELECT u.funcionario_id, u.email, u.ativo, 
                f.nome, f.departamento_id, f.cargo_nome, f.xp_total, f.nivel, f.role
         FROM auth_service.usuarios u
         LEFT JOIN user_service.funcionarios f ON u.funcionario_id = f.id AND f.ativo = true
         WHERE u.funcionario_id = $1 AND u.ativo = true`,
        [decoded.sub]
      );

      const user = userRows[0];
      if (!user) {
  return res.status(401).json({ erro: 'usuario_nao_encontrado', mensagem: 'Usuário não encontrado' });
      }

      const userData: UserData = { 
        id: user.funcionario_id, 
        email: user.email, 
        ativo: user.ativo,
        roles: user.role
      };

      // Gerar novo access token
      const { token: newAccessToken, expiresAt: accessExpiresAt } = genAccessToken(userData);

      // Armazenar novo access token
      await c.query(
        `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
         VALUES ($1,$2,'ACCESS', $3)`,
        [newAccessToken, decoded.sub, accessExpiresAt]
      );

      // Atualizar cookie do access token
      const isProduction = process.env.NODE_ENV === 'production';
      const accessExpHours = parseInt(process.env.ACCESS_TOKEN_EXP_HOURS || '8', 10);
      
      res.cookie('accessToken', newAccessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax' as const,
        path: '/',
        maxAge: accessExpHours * 60 * 60 * 1000,
      });

      res.status(200).json({ mensagem: 'Token renovado com sucesso' });
    });
  } catch (error) {
    console.error('[auth-service] Erro no refresh:', error);
    res.status(401).json({ erro: 'token_invalido', mensagem: 'Token inválido ou expirado' });
  }
};

export const logout = async (req: Request, res: Response) => {
  // Buscar refresh token do cookie
  const refreshToken = req.cookies?.refreshToken;
  
  if (!refreshToken) {
    return res.status(400).json({ 
      erro: 'refresh_token_obrigatorio', 
      mensagem: 'Refresh token é obrigatório' 
    });
  }
  
  try {
    const key = buildSigningKey();
    const decoded = jwt.verify(refreshToken, key) as { sub: string };
    
    await withClient(async (c) => {
      // Invalidar especificamente o refresh token recebido (hasheado)
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE token_jwt=$1 AND tipo_token='REFRESH'`,
        [hash(refreshToken)]
      );
      
      // Invalidar todos os access tokens ativos do usuário (revogação)
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE funcionario_id=$1 AND tipo_token='ACCESS' AND ativo=true`,
        [decoded.sub]
      );
      
      // Registrar evento com aggregate_id = usuário real
      try {
        await publishEvent('auth.logout', { userId: decoded.sub, refreshToken });
      } catch (e) {
        console.error('[auth-service] falha publicando auth.logout', (e as Error).message);
      }
      
      // Limpar cookies
      res.clearCookie('accessToken', { path: '/' });
      res.clearCookie('refreshToken', { path: '/' });
      
      res.status(200).json({ mensagem: 'Logout realizado com sucesso' });
    });
  } catch (error) {
    console.error('[auth-service] Erro no logout:', error);
    
    // Mesmo com erro, limpar cookies
    res.clearCookie('accessToken', { path: '/' });
    res.clearCookie('refreshToken', { path: '/' });
    
    return res.status(401).json({ erro: 'refresh_token_invalido', mensagem: 'Refresh token inválido' });
  }
};

export const reset = async (req: Request, res: Response) => {
  const { email, novaSenha } = req.body;
  const hash = await bcrypt.hash(novaSenha, 12);

  await withClient(async (c) => {
    const { rows } = await c.query(
      `UPDATE auth_service.usuarios SET senha_hash=$1 WHERE email=$2 RETURNING funcionario_id,email`,
      [hash, email]
    );
  if (!rows[0]) return res.status(404).json({ erro: 'usuario_nao_encontrado', mensagem: 'Usuário não encontrado' });

    // Invalida tokens antigos
    await c.query(
      `UPDATE auth_service.tokens SET ativo=false WHERE funcionario_id=$1`,
      [rows[0].funcionario_id]
    );

    // Evento de reset de senha
    try {
      await publishEvent('auth.password_reset', { userId: rows[0].funcionario_id, email });
    } catch (e) {
      console.error('[auth-service] falha publicando auth.password_reset', (e as Error).message);
    }

  res.status(200).json({ mensagem: 'Senha redefinida com sucesso' });
  });
};

// Endpoint para obter dados do usuário autenticado
export const me = async (req: Request, res: Response) => {
  // O user_id virá do header x-user-id injetado pelo API Gateway
  const userId = req.headers['x-user-id'] as string;
  
  if (!userId) {
    return res.status(401).json({ 
      erro: 'nao_autenticado', 
      mensagem: 'Usuário não autenticado' 
    });
  }
  
  try {
    await withClient(async (c) => {
      const { rows } = await c.query(
        `SELECT u.id, u.email, u.ativo, u.roles 
         FROM auth_service.usuarios u 
         WHERE u.id = $1`,
        [userId]
      );
      
      if (rows.length === 0) {
        return res.status(404).json({ 
          erro: 'usuario_nao_encontrado', 
          mensagem: 'Usuário não encontrado' 
        });
      }
      
      const user = rows[0];
      
      // Buscar dados adicionais do funcionário no user-service
      // Como não temos acesso direto, retornar apenas dados do auth
      res.status(200).json({
        id: user.id,
        email: user.email,
        role: user.roles,
        ativo: user.ativo
      });
    });
  } catch (error) {
    console.error('[auth-service] Erro no /me:', error);
    return res.status(500).json({ 
      erro: 'erro_servidor', 
      mensagem: 'Erro ao buscar dados do usuário' 
    });
  }
};