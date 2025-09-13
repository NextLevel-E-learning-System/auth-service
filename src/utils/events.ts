import { publishEvent } from "../config/rabbitmq";

export async function emitUserCreated(user: any, senha: string) {
  await publishEvent('user.events', { type: 'user.created', payload: { ...user, senha } });
}

export async function emitUserPasswordReset(email: string, senha: string) {
  await publishEvent('user.events', { type: 'user.password_reset', payload: { email, senha } });
}