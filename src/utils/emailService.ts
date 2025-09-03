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
