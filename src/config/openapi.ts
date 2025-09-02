import fs from 'fs';
import path from 'path';

export function loadOpenApi(title = 'Service API') {
  const candidates = [
    path.join(process.cwd(), 'docs', 'openapi.json'),
    path.join(process.cwd(), 'dist', '..', 'docs', 'openapi.json'),
    path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', 'docs', 'openapi.json')
  ];
  for (const p of candidates) {
    try { if (fs.existsSync(p)) return JSON.parse(fs.readFileSync(p, 'utf-8')); } catch { /* ignore */ }
  }
  return { openapi: '3.0.3', info: { title: `${title} (fallback)`, version: '1.0.0' }, paths: {} };
}