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
  
  const logoBase64Data = logoBase64 || loadLogoBase64();
  
  return `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bem-vindo(a) ao ${title}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 30px;
            text-align: center;
        }
        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .logo img {
            max-height: 160px;
        }
        .content {
            padding: 20px 30px;
        }
        .welcome-text {
            font-size: 18px;
            color: #333;
            margin-bottom: 30px;
            text-align: center;
        }
        .credentials-box {
            background-color: #f8f9fa;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 25px;
            margin: 30px 0;
        }
        .credential-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e9ecef;
        }
        .credential-item:last-child {
            margin-bottom: 0;
            padding-bottom: 0;
            border-bottom: none;
        }
        .credential-label {
            font-weight: 600;
            color: #495057;
            font-size: 14px;
        }
        .credential-value {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background-color: #ffffff;
            padding: 8px 12px;
            border-radius: 4px;
            border: 1px solid #dee2e6;
            font-size: 14px;
            color: #212529;
            font-weight: 500;
        }
        .instructions {
            background-color: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 20px;
            margin: 30px 0;
            border-radius: 0 8px 8px 0;
        }
        .instructions h3 {
            margin-top: 0;
            color: #1976d2;
            font-size: 16px;
        }
        .instructions ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .instructions li {
            margin-bottom: 8px;
            color: #424242;
        }
        .footer {
            background-color: #f8f9fa;
            padding: 30px;
            text-align: center;
            border-top: 1px solid #e9ecef;
        }
        .footer p {
            margin: 0;
            color: #6c757d;
            font-size: 14px;
        }
        @media (max-width: 600px) {
            body {
                padding: 10px;
            }
            .header {
                padding: 30px 20px;
            }
            .content {
                padding: 30px 20px;
            }
            .credential-item {
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }
            .credential-value {
                width: 100%;
                box-sizing: border-box;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                ${logoBase64Data ? `<img src="data:image/png;base64,${logoBase64Data}" alt="Logo">` : ''}
            </div>

        </div>
        
        <div class="content">
            <div class="welcome-text">
                Olá <strong>${nome.split(' ')[0]}</strong>! 👋<br>
               <p>Seu acesso à plataforma <strong>${title}</strong> foi criado com sucesso.</p> <br>
               <p>Abaixo estão suas credenciais de acesso:</p>
            </div>
            
            <div class="credentials-box">
                <div class="credential-item">
                    <span class="credential-label">📧 Email:</span>
                    <span class="credential-value">${email}</span>
                </div>
                <div class="credential-item">
                    <span class="credential-label">🔑 Senha:</span>
                    <span class="credential-value">${senha}</span>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>&copy; ${new Date().getFullYear()} ${title}. Este é um email automático, não responda.</p>
        <p>Se você não solicitou esta conta, ignore este e-mail ou contate o suporte.</p>
        </div>
    </div>
</body>
</html>`;
}

export async function sendRegistrationEmail(params: { nome: string; email: string; senha: string; departamento: string; }) {
  const logoBase64 = loadLogoBase64();
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

// ======================= RESET PASSWORD =========================
export function buildResetPasswordHtml(params: { nome: string; email: string; novaSenha: string; appName?: string; logoBase64?: string }) {
    const { nome, email, novaSenha, appName, logoBase64 } = params;
    const title = appName || 'NextLevel E-learning System';
    const logoBase64Data = logoBase64 || loadLogoBase64();
    return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>Redefinição de Senha - ${title}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont,'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background:#f4f6f8; margin:0; padding:24px; color:#333; }
        .card { max-width:620px; margin:0 auto; background:#fff; border-radius:14px; box-shadow:0 6px 28px rgba(0,0,0,0.08); overflow:hidden; }
        .header { background:linear-gradient(135deg,#ff8a05,#ff4800); padding:28px 30px; text-align:center; color:#fff; }
        .logo img { max-height:120px; }
        h1 { margin:0; font-size:22px; letter-spacing:.5px; }
        .content { padding:32px 36px 40px; }
        .hi { font-size:17px; margin:0 0 22px; }
        .warn { background:#fff3cd; border-left:5px solid #ff9800; padding:14px 18px; border-radius:8px; font-size:14px; line-height:1.5; margin:26px 0; }
        .credentials { background:#f1f5f9; border:1px solid #e2e8f0; padding:26px 24px 10px; border-radius:10px; margin:30px 0 34px; }
        .kv { display:flex; justify-content:space-between; align-items:center; margin-bottom:18px; padding-bottom:14px; border-bottom:1px solid #e2e8f0; }
        .kv:last-child { margin-bottom:0; padding-bottom:0; border-bottom:none; }
        .k { font-size:12px; font-weight:600; text-transform:uppercase; color:#475569; letter-spacing:.5px; }
        .v { font-family:'Monaco','Menlo','Ubuntu Mono',monospace; background:#fff; padding:8px 14px; border-radius:6px; border:1px solid #cbd5e1; font-size:15px; font-weight:500; color:#1e293b; }
        .steps { background:#eef6ff; border:1px solid #b6dcff; padding:22px 24px 10px; border-radius:10px; }
        .steps h3 { margin:0 0 12px; font-size:15px; color:#0b62c1; }
        .steps ol { margin:0 0 4px 18px; padding:0; }
        .steps li { margin:0 0 10px; font-size:14px; }
        .footer { background:#f8fafc; padding:26px 26px 32px; text-align:center; font-size:12px; color:#64748b; border-top:1px solid #e2e8f0; }
        .small-note { font-size:12px; color:#475569; margin-top:14px; }
        @media (max-width:640px){ body { padding:14px; } .content { padding:30px 24px 34px; } .kv{ flex-direction:column; align-items:flex-start; gap:8px; } .v{ width:100%; box-sizing:border-box; } }
    </style>
</head>
<body>
    <div class="card">
        <div class="header">
            <div class="logo">${logoBase64Data ? `<img src="data:image/png;base64,${logoBase64Data}" alt="Logo" />` : ''}</div>
            <h1>Redefinição de Senha</h1>
        </div>
        <div class="content">
            <p class="hi">Olá <strong>${nome}</strong>, sua senha foi redefinida com sucesso.</p>
            <div class="warn">Se você <strong>não</strong> solicitou esta redefinição, altere a senha imediatamente após acessar e informe a equipe de suporte.</div>
            <div class="credentials">
                <div class="kv"><span class="k">Email</span><span class="v">${email}</span></div>
                <div class="kv"><span class="k">Nova Senha </span><span class="v">${novaSenha}</span></div>
            </div>
            <div class="steps">
                <h3>Próximos passos recomendados:</h3>
                <ol>
                    <li>Acesse a plataforma e autentique-se com a senha .</li>
                    <li>Altere a senha imediatamente para uma senha forte e única.</li>
                    <li>Nunca compartilhe suas credenciais e evite reutilizar senhas.</li>
                </ol>
            </div>
            <p class="small-note">Esta senha é . Após o primeiro login, personalize-a para maior segurança.</p>
        </div>
        <div class="footer">&copy; ${new Date().getFullYear()} ${title}. Este é um email automático, não responda.</div>
    </div>
</body>
</html>`;
}

export async function sendResetPasswordEmail(params: { nome: string; email: string; novaSenha: string; }) {
    const logoBase64 = loadLogoBase64();
    const html = buildResetPasswordHtml({ ...params, appName: process.env.APP_NAME || 'NextLevel E-learning System', logoBase64 });
    const text = `🔐 Redefinição de Senha - NextLevel\n\nOlá ${params.nome}, sua senha foi redefinida.\n\nNova senha: ${params.novaSenha}\n\nUse-a para acessar e troque imediatamente. Se você não solicitou, contate o suporte.\n\n— NextLevel E-learning System`;
    return sendMail(params.email, '🔐 Sua senha foi redefinida', text, html);
}
