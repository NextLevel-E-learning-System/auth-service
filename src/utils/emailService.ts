import nodemailer from 'nodemailer';

let transporter: nodemailer.Transporter | null = null;

function buildTransporter() {
  if (transporter) return transporter;
  const host = process.env.SMTP_HOST;
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if (!host || !user || !pass) {
    throw new Error('smtp_nao_configurado');
  }
  transporter = nodemailer.createTransport({
    host,
    port,
    secure: port === 465,
    auth: { user, pass }
  });
  return transporter;
}

export async function sendMail(to: string, subject: string, text: string, html?: string) {
  const from = process.env.SMTP_FROM || 'no-reply@example.com';
  const t = buildTransporter();
  const info = await t.sendMail({ from, to, subject, text, html: html || `<pre>${text}</pre>` });
  return info;
}

export function buildRegistrationHtml(params: { nome: string; email: string; senha: string; departamento: string; appName?: string }) {
  const { nome, email, senha, departamento, appName } = params;
  const title = appName || 'NextLevel E-learning System';
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8" /><title>Bem-vindo(a) - ${title}</title>
    <style>
      body{font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;margin:0;padding:0;color:#222}
      .container{max-width:520px;margin:32px auto;background:#fff;border-radius:10px;padding:32px;border:1px solid #e3e8ef;box-shadow:0 4px 12px rgba(0,0,0,0.05)}
      h1{font-size:24px;margin:0 0 16px;color:#2a4365;text-align:center}
      .logo{text-align:center;margin-bottom:20px;font-size:28px;font-weight:700;color:#1a365d}
      p{line-height:1.6;margin:0 0 16px;color:#4a5568}
      .senha-box{font-size:32px;letter-spacing:6px;font-weight:700;background:#1a365d;color:#fff;padding:20px;text-align:center;border-radius:8px;margin:24px 0;font-family:'Courier New',monospace;border:3px solid #2d3748}
      .meta{font-size:14px;color:#555;margin-top:24px;background:#f7fafc;padding:16px;border-radius:6px;border-left:4px solid #4299e1}
      .badge{display:inline-block;background:#edf2f7;color:#2a4365;padding:6px 12px;border-radius:20px;font-size:12px;font-weight:600;margin:2px 4px 2px 0}
      .footer{font-size:12px;color:#666;margin-top:32px;text-align:center;border-top:1px solid #eee;padding-top:16px}
      .warning{background:#fed7d7;color:#c53030;padding:12px;border-radius:6px;margin:16px 0;border-left:4px solid #e53e3e}
      a{color:#2b6cb0;text-decoration:none}
      .btn{display:inline-block;background:#4299e1;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600;margin:16px 0}
    </style></head><body>
    <div class="container">
      <div class="logo">🎓 ${title}</div>
      <h1>Bem-vindo(a)!</h1>
      <p>Seu acesso à plataforma <strong>${title}</strong> foi criado com sucesso.</p>
      
      <div class="meta">
        <strong>📋 Dados da Conta:</strong><br/>
        <span class="badge">📧 Email</span> ${email}<br/>
      </div>
      
      <p><strong>🔐 Use a senha abaixo para fazer seu login:</strong></p>
      <div class="senha-box">${senha}</div>
 
      <p>Após o login, você terá acesso a todos os cursos e recursos da plataforma de treinamento.</p>
      
      <div class="footer">
        <p>Se você não solicitou este cadastro, ignore este e-mail ou contate o suporte.</p>
        <p>&copy; ${new Date().getFullYear()} ${title}. Todos os direitos reservados.</p>
      </div>
    </div></body></html>`;
}

export async function sendRegistrationEmail(params: { nome: string; email: string; senha: string; departamento: string }) {
  const html = buildRegistrationHtml({ ...params, appName: process.env.APP_NAME || 'NextLevel E-learning System' });
  const text = `🎓 Bem-vindo(a) ao NextLevel E-learning System!\n\nOlá ${params.nome}!\n\nSua conta foi criada com sucesso.\n\n🔐 Senha temporária: ${params.senha}\n\n📧 Email: ${params.email}\n🏢 Departamento: ${params.departamento}\n🎯 Nível inicial: Iniciante\n⭐ XP inicial: 0 pontos\n\n⚠️ Por segurança, altere sua senha após o primeiro acesso.\n\nSe você não solicitou este cadastro, ignore este e-mail.\n\n---\nNextLevel E-learning System\n© ${new Date().getFullYear()}`;
  
  return sendMail(
    params.email, 
    `🎓 Bem-vindo(a) ao NextLevel E-learning - Acesso Liberado`, 
    text, 
    html
  );
}
