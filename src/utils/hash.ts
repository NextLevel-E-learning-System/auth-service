import bcrypt from 'bcryptjs';

export async function hashPassword(pwd: string) {
  return bcrypt.hash(pwd, 12);
}

export async function compareHash(pwd: string, hash: string) {
  return bcrypt.compare(pwd, hash);
}
