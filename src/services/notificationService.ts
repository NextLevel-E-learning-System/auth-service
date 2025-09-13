import { withClient } from '../config/db.js';

export async function sendPasswordEmail(email: string, password: string) {
  await withClient(async c => {
    await c.query(`INSERT INTO notification_service.filas_email (destinatario, assunto, corpo, status)
      VALUES ($1,$2,$3,'PENDENTE')`,
      [email, 'Sua senha', `Sua senha é: ${password}`]);
  });
}
