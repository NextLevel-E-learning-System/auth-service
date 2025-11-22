import { Request, Response } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { createHash } from 'crypto'
import { withClient } from '../config/db.js'

interface UserData {
  id: string
  email: string
  ativo: boolean
  roles: string // Single role, not array
}

function buildSigningKey() {
  const secret = process.env.JWT_SECRET || 'dev-secret'
  return createHash('sha256').update(secret).digest()
}

function genAccessToken(user: UserData) {
  const accessExpHours = parseInt(process.env.ACCESS_TOKEN_EXP_HOURS || '8', 10)
  const key = buildSigningKey()

  // Payload com informações essenciais do usuário
  const payload = {
    sub: user.id,
    email: user.email,
    ativo: user.ativo,
    roles: user.roles,
    type: 'access',
  }

  const token = jwt.sign(payload, key, { expiresIn: `${accessExpHours}h` })
  const expiresAt = new Date(Date.now() + accessExpHours * 60 * 60 * 1000)
  return { token, expiresAt, accessExpHours }
}

function genRefreshToken(user: UserData) {
  const refreshExpHours = parseInt(process.env.REFRESH_TOKEN_EXP_HOURS || '24', 10)
  const key = buildSigningKey()

  // Para refresh token, incluir apenas informações essenciais
  const payload = {
    sub: user.id,
    email: user.email,
    ativo: user.ativo,
    roles: user.roles,
    type: 'refresh',
  }

  const token = jwt.sign(payload, key, { expiresIn: `${refreshExpHours}h` })
  const expiresAt = new Date(Date.now() + refreshExpHours * 60 * 60 * 1000)
  return { token, expiresAt, refreshExpHours }
}

function hash(value: string) {
  return createHash('sha256').update(value).digest('hex')
}

// Detectar se é localhost para configurar cookies corretamente
function isLocalhost(req: Request): boolean {
  const origin = req.headers.origin || ''
  return origin.includes('localhost') || origin.includes('127.0.0.1')
}

// Configuração de cookies adaptativa
function getCookieOptions(req: Request, maxAgeMs: number) {
  const isLocal = isLocalhost(req)

  return {
    httpOnly: true,
    secure: true, // HTTPS sempre (necessário para sameSite=none)
    sameSite: isLocal ? ('lax' as const) : ('none' as const), // lax para localhost, none para cross-origin
    path: '/',
    maxAge: maxAgeMs,
  }
}

export const login = async (req: Request, res: Response) => {
  const { email, senha } = req.body

  await withClient(async c => {
    // Buscar usuário com informações completas incluindo dados do funcionário
    const { rows } = await c.query(
      `SELECT u.funcionario_id, u.email, u.ativo, u.senha_hash,
              f.nome, f.departamento_id, f.cargo_nome, f.xp_total, f.nivel, f.role
       FROM auth_service.usuarios u
       LEFT JOIN user_service.funcionarios f ON u.funcionario_id = f.id AND f.ativo = true
       WHERE u.email = $1 AND u.ativo = true`,
      [email]
    )

    const user = rows[0]
    if (!user) {
      return res
        .status(401)
        .json({ erro: 'credenciais_invalidas', mensagem: 'Credenciais inválidas' })
    }

    const valid = await bcrypt.compare(senha, user.senha_hash)
    if (!valid) {
      return res
        .status(401)
        .json({ erro: 'credenciais_invalidas', mensagem: 'Credenciais inválidas' })
    }

    const userData = {
      id: user.funcionario_id,
      email: user.email,
      ativo: user.ativo,
      roles: user.role,
    }

    // Gerar tokens com informações completas
    const {
      token: accessToken,
      expiresAt: accessExpiresAt,
      accessExpHours,
    } = genAccessToken(userData)
    const { token: refreshToken, expiresAt: refreshExpiresAt } = genRefreshToken(userData)

    // Armazenar tokens no banco
    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'ACCESS', $3)`,
      [accessToken, user.funcionario_id, accessExpiresAt]
    )

    await c.query(
      `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
       VALUES ($1,$2,'REFRESH', $3)`,
      [hash(refreshToken), user.funcionario_id, refreshExpiresAt]
    )

    // Log de acesso
    await c.query(
      `UPDATE auth_service.usuarios SET ultimo_acesso = NOW() WHERE funcionario_id = $1`,
      [user.funcionario_id]
    )

    await c.query(
      `INSERT INTO auth_service.logs_acesso(funcionario_id, ip, user_agent)
       VALUES ($1,$2,$3)`,
      [user.funcionario_id, req.ip, req.headers['user-agent']]
    )

    // Configurar cookies adaptáveis: lax para localhost HTTPS, none para cross-origin Railway
    const accessCookieOptions = getCookieOptions(req, accessExpHours * 60 * 60 * 1000)
    const refreshCookieOptions = getCookieOptions(req, 7 * 24 * 60 * 60 * 1000) // 7 dias

    // Setar cookies
    res.cookie('accessToken', accessToken, accessCookieOptions)
    res.cookie('refreshToken', refreshToken, refreshCookieOptions)

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
        role: user.role,
      },
    })
  })
}

export const refresh = async (req: Request, res: Response) => {
  // Buscar refresh token do cookie ao invés do body
  const refreshToken = req.cookies?.refreshToken

  if (!refreshToken) {
    return res.status(401).json({
      erro: 'refresh_token_ausente',
      mensagem: 'Refresh token não encontrado',
    })
  }

  try {
    const key = buildSigningKey()
    const decoded = jwt.verify(refreshToken, key) as {
      sub: string
      email: string
      status: string
      roles: string
      iat: number
      exp: number
    }

    await withClient(async c => {
      // Verificar se o refresh token hasheado existe e está ativo
      const { rows } = await c.query(
        `SELECT * FROM auth_service.tokens 
         WHERE token_jwt=$1 AND ativo=true AND tipo_token='REFRESH' AND data_expiracao > NOW()`,
        [hash(refreshToken)]
      )

      if (!rows[0]) {
        return res
          .status(401)
          .json({ erro: 'refresh_token_invalido', mensagem: 'Refresh token inválido' })
      }

      // Buscar dados atualizados do usuário para o novo token
      const { rows: userRows } = await c.query(
        `SELECT u.funcionario_id, u.email, u.ativo, 
                f.nome, f.departamento_id, f.cargo_nome, f.xp_total, f.nivel, f.role
         FROM auth_service.usuarios u
         LEFT JOIN user_service.funcionarios f ON u.funcionario_id = f.id AND f.ativo = true
         WHERE u.funcionario_id = $1 AND u.ativo = true`,
        [decoded.sub]
      )

      const user = userRows[0]
      if (!user) {
        return res
          .status(401)
          .json({ erro: 'usuario_nao_encontrado', mensagem: 'Usuário não encontrado' })
      }

      const userData: UserData = {
        id: user.funcionario_id,
        email: user.email,
        ativo: user.ativo,
        roles: user.role,
      }

      // Gerar novo access token
      const { token: newAccessToken, expiresAt: accessExpiresAt } = genAccessToken(userData)

      // Armazenar novo access token
      await c.query(
        `INSERT INTO auth_service.tokens(token_jwt, funcionario_id, tipo_token, data_expiracao)
         VALUES ($1,$2,'ACCESS', $3)`,
        [newAccessToken, decoded.sub, accessExpiresAt]
      )

      // Atualizar cookie do access token
      const accessExpHours = parseInt(process.env.ACCESS_TOKEN_EXP_HOURS || '8', 10)
      const accessCookieOptions = getCookieOptions(req, accessExpHours * 60 * 60 * 1000)
      res.cookie('accessToken', newAccessToken, accessCookieOptions)

      res.status(200).json({ mensagem: 'Token renovado com sucesso' })
    })
  } catch (error) {
    console.error('[auth-service] Erro no refresh:', error)
    res.status(401).json({ erro: 'token_invalido', mensagem: 'Token inválido ou expirado' })
  }
}

export const logout = async (req: Request, res: Response) => {
  // Buscar refresh token do cookie
  const refreshToken = req.cookies?.refreshToken

  if (!refreshToken) {
    return res.status(400).json({
      erro: 'refresh_token_obrigatorio',
      mensagem: 'Refresh token é obrigatório',
    })
  }

  try {
    const key = buildSigningKey()
    const decoded = jwt.verify(refreshToken, key) as { sub: string }

    await withClient(async c => {
      // Invalidar especificamente o refresh token recebido (hasheado)
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE token_jwt=$1 AND tipo_token='REFRESH'`,
        [hash(refreshToken)]
      )

      // Invalidar todos os access tokens ativos do usuário (revogação)
      await c.query(
        `UPDATE auth_service.tokens SET ativo=false WHERE funcionario_id=$1 AND tipo_token='ACCESS' AND ativo=true`,
        [decoded.sub]
      )

      // Limpar cookies com as mesmas opções usadas no set
      const clearOptions = getCookieOptions(req, 0)
      res.clearCookie('accessToken', clearOptions)
      res.clearCookie('refreshToken', clearOptions)

      res.status(200).json({ mensagem: 'Logout realizado com sucesso' })
    })
  } catch (error) {
    console.error('[auth-service] Erro no logout:', error)

    // Mesmo com erro, limpar cookies
    res.clearCookie('accessToken', { path: '/' })
    res.clearCookie('refreshToken', { path: '/' })

    return res
      .status(401)
      .json({ erro: 'refresh_token_invalido', mensagem: 'Refresh token inválido' })
  }
}
