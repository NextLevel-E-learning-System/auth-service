import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';

let transporter: nodemailer.Transporter | null = null;

// Função para carregar logo em Base64
function loadLogoBase64(): string | undefined {
  try {
    const logoPath = path.join(__dirname, '..', 'assets', 'logo.png');
    
    if (fs.existsSync(logoPath)) {
      console.log(`Logo encontrada em: ${logoPath}`);
      const logoBuffer = fs.readFileSync(logoPath);
      return logoBuffer.toString('base64');
    }
    
    return undefined;
  } catch (error) {
    console.warn('Erro ao carregar a logo:', error);
    return undefined;
  }
}

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
    auth: { user, pass },
    tls: {
      rejectUnauthorized: false
    }
  });
  return transporter;
}

export async function sendMail(to: string, subject: string, text: string, html?: string) {
  const from = process.env.SMTP_FROM || 'NextLevel E-learning <no-reply@nextlevel.com>';
  const t = buildTransporter();
  const info = await t.sendMail({ from, to, subject, text, html: html || `<pre>${text}</pre>` });
  return info;
}

export function buildRegistrationHtml(params: { nome: string; email: string; senha: string; departamento: string; appName?: string; logoBase64?: string }) {
  const { nome, email, senha, departamento, appName, logoBase64 } = params;
  const title = appName || 'NextLevel E-learning System';
  
  // Logo em Base64 ou fallback para emoji
  const logoHtml = logoBase64 
    ? `<img src="data:image/png;base64,${logoBase64}" alt="${title}" style="max-width:200px;height:auto;margin-bottom:20px;" />`
    : `🎓 ${title}`;
  
  return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8" /><title>Bem-vindo(a) - ${title}</title>
    <style>
      body{font-family:Arial,Helvetica,sans-serif;background:#f5f7fa;margin:0;padding:0;color:#222}
      .container{max-width:520px;margin:32px auto;background:#fff;border-radius:10px;padding:32px;border:1px solid #e3e8ef;box-shadow:0 4px 12px rgba(0,0,0,0.05)}
      h1{font-size:24px;margin:0 0 16px;color:#2a4365;text-align:center}
      .logo{text-align:center;margin-bottom:30px}
      .logo img{max-width:200px;height:auto;display:block;margin:0 auto}
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
      <div class="logo">${logoHtml}</div>
      <h1>Bem-vindo(a), ${nome.split(' ')[0]}!</h1>
      <p>Seu acesso à plataforma <strong>${title}</strong> foi criado com sucesso.</p>
      
      <div class="meta">
        <strong>📋 Dados da Conta:</strong><br/>
        <span class="badge">📧 Email</span> ${email}<br/>
        <span class="badge">🏢 Departamento</span> ${departamento}<br/>
        <span class="badge">🎯 Nível</span> Iniciante<br/>
        <span class="badge">⭐ XP Inicial</span> 0 pontos
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

export async function sendRegistrationEmail(params: { nome: string; email: string; senha: string; departamento: string; }) {
  const logoBase64 = loadLogoBase64(); // Carrega a logo automaticamente
  const html = buildRegistrationHtml({ 
    ...params, 
    appName: process.env.APP_NAME || 'NextLevel E-learning System',
    logoBase64 
  });
  const text = `🎓 Bem-vindo(a) ao NextLevel E-learning System!\n\nOlá ${params.nome}!\n\nSua conta foi criada com sucesso.\n\n🔐 Senha: ${params.senha}\n\n📧 Email: ${params.email}\n🏢 Departamento: ${params.departamento}\n🎯 Nível inicial: Iniciante\n⭐ XP inicial: 0 pontos\n\nSe você não solicitou este cadastro, ignore este e-mail.\n\n---\nNextLevel E-learning System\n© ${new Date().getFullYear()}`;

  return sendMail(
    params.email, 
    `🎓 Bem-vindo(a) ao NextLevel E-learning - Acesso Liberado`, 
    text, 
    html
  );
}
