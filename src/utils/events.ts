import { publishEvent } from "../config/rabbitmq";

// Auth service deve emitir apenas eventos relacionados à autenticação
export async function emitAuthLogin(userId: string, ip?: string, userAgent?: string) {
  await publishEvent('auth.login', { userId, ip, userAgent, timestamp: new Date().toISOString() });
}

export async function emitAuthLogout(userId: string, ip?: string) {
  await publishEvent('auth.logout', { userId, ip, timestamp: new Date().toISOString() });
}

export async function emitAuthTokenRefresh(userId: string, ip?: string) {
  await publishEvent('auth.token_refresh', { userId, ip, timestamp: new Date().toISOString() });
}