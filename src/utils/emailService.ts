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
    const enableDebug = process.env.SMTP_DEBUG === 'true';
    transporter = nodemailer.createTransport({
        host,
        port,
        secure: port === 465,
        auth: { user, pass },
        tls: {
            rejectUnauthorized: false
        },
        logger: enableDebug,
        debug: enableDebug
    });
    if (enableDebug) {
        console.log('[email][transporter_created]', { host, port, user });
    }
    return transporter;
}

export async function sendMail(to: string, subject: string, text: string, html?: string) {
    // Gmail normalmente exige remetente igual ao usuário autenticado ou alias verificado
    const suggestedFrom = process.env.SMTP_USER ? `${process.env.SMTP_USER}` : 'no-reply@example.com';
    const from = process.env.SMTP_FROM || suggestedFrom;
    const t = buildTransporter();
    try {
        const info = await t.sendMail({ from, to, subject, text, html: html || `<pre>${text}</pre>` });
        if (process.env.SMTP_DEBUG === 'true') {
            console.log('[email][sent]', { to, subject, messageId: info.messageId });
        }
        return info;
    } catch (err: any) {
        console.error('[email][send_fail]', { to, subject, err: err?.message });
        throw err;
    }
}

export function buildRegistrationHtml(params: { nome: string; email: string; senha: string; departamento: string; appName?: string; logoBase64?: string }) {
  const { nome, email, senha, departamento, appName, logoBase64 } = params;
  const title = appName || 'NextLevel E-learning System';
  
  const logoBase64Data = logoBase64 || loadLogoBase64();
    const styles = `
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,Cantarell,sans-serif;background:#f2f4f8;margin:0;padding:22px;color:#2d3748;}
        .shell{max-width:640px;margin:0 auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 8px 32px -4px rgba(31,41,55,.15);} 
        .hdr{background:linear-gradient(135deg,#6366f1,#764ba2);padding:30px 34px;text-align:center;color:#fff;position:relative;}
        .hdr .logo img{max-height:150px;}
        h1{margin:14px 0 0;font-size:22px;letter-spacing:.5px;font-weight:600;}
        .body{padding:34px 40px 48px;}
        .hi{font-size:18px;margin:0 0 26px;text-align:center;}
        .cred-wrapper{background:linear-gradient(135deg,#eef2ff,#f8f9ff);border:1px solid #e0e7ff;padding:26px 26px 18px;border-radius:16px;position:relative;margin:34px 0 42px;}
        .cred-title{position:absolute;top:-14px;left:18px;background:#6366f1;color:#fff;padding:4px 14px;font-size:12px;border-radius:24px;font-weight:600;letter-spacing:.5px;box-shadow:0 2px 6px rgba(0,0,0,.15);} 
        .cred-grid{display:flex;flex-direction:column;gap:18px;margin-top:10px;}
        .cred-item{display:flex;flex-direction:column;gap:6px;}
        .label{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:#4a5568;}
        .val{background:#fff;border:1px solid #d9e2ef;border-radius:10px;padding:10px 14px;font-family:'Monaco','Menlo','Ubuntu Mono',monospace;font-size:15px;color:#1a202c;font-weight:600;display:inline-block;min-width:120px;}
        .pwd-badge{background:linear-gradient(135deg,#ffb347,#ff7b54);color:#fff;border:none;box-shadow:0 4px 14px -4px rgba(0,0,0,.25);}
        .note{font-size:13px;line-height:1.5;margin-top:10px;color:#4a5568;}
        .separator{height:1px;background:linear-gradient(90deg,rgba(99,102,241,0),rgba(99,102,241,.5),rgba(99,102,241,0));margin:40px 0 30px;border:0;}
        .footer{background:#f8fafc;padding:30px 34px;text-align:center;border-top:1px solid #e2e8f0;font-size:12px;color:#64748b;}
        @media(max-width:640px){body{padding:14px}.body{padding:32px 24px 46px}.cred-wrapper{padding:24px 20px 14px}.val{width:100%;box-sizing:border-box}}
    `;
    return `<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"/><title>${title} - Acesso Criado</title><style>${styles}</style></head><body>
        <div class="shell">
            <div class="hdr">
                <div class="logo">${logoBase64Data ? `<img src="data:image/png;base64,${logoBase64Data}" alt="Logo"/>` : ''}</div>
                <h1>Bem-vindo(a)</h1>
            </div>
            <div class="body">
                <p class="hi">Olá <strong>${nome.split(' ')[0]}</strong> 👋<br/>Sua conta em <strong>${title}</strong> foi criada com sucesso.</p>
                <div class="cred-wrapper">
                    <span class="cred-title">CREDENCIAIS INICIAIS</span>
                    <div class="cred-grid">
                        <div class="cred-item">
                            <span class="label">Email</span>
                            <span class="val">${email}</span>
                        </div>
                        <div class="cred-item">
                            <span class="label">Senha </span>
                            <span class="val pwd-badge">${senha}</span>
                        </div>
                    </div>
                    <div class="note">Use esta senha para o primeiro acesso e altere imediatamente por uma senha forte. Não compartilhe suas credenciais.</div>
                </div>
                <p style="font-size:13px;color:#4a5568;margin:0 0 22px;">Departamento informado: <strong>${departamento}</strong> | Nível inicial: <strong>Iniciante</strong> | XP: <strong>0</strong></p>
                <hr class="separator"/>
                <p style="font-size:12px;color:#718096;margin:0;">Se você não solicitou este cadastro, ignore este e-mail.</p>
            </div>
            <div class="footer">&copy; ${new Date().getFullYear()} ${title}. Email automático - não responda.</div>
        </div>
    </body></html>`;
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

// -------- Reset reutilizando layout: muda apenas título do badge e assunto --------
export async function sendPasswordResetEmail(params: { nome: string; email: string; novaSenha: string; }) {
    // Reutiliza buildRegistrationHtml passando departamento 'N/D'
    const html = buildRegistrationHtml({ nome: params.nome, email: params.email, senha: params.novaSenha, departamento: 'N/D', appName: process.env.APP_NAME || 'NextLevel E-learning System', logoBase64: loadLogoBase64() });
    const text = `🔐 Reset de Senha - NextLevel\n\nOlá ${params.nome}, sua senha foi redefinida.\nNova senha : ${params.novaSenha}\nAltere após o primeiro login.\n\n— NextLevel E-learning System`;
    return sendMail(params.email, '🔐 Reset de Senha - Nova Senha ', text, html);
}

