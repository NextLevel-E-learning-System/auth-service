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
    const from = 'no-reply@nextlevel.com';
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

// Template unificado (cadastro e reset) baseado no HTML fornecido (compatível com clientes Outlook / MSO)
export function buildPasswordTemplate(params: { tipo: 'register' | 'reset'; nome: string; senha: string; appName?: string }) {
    const { nome, senha, appName } = params; // tipo ignorado: mesmo corpo para ambos
    const firstName = (nome || '').trim().split(/\s+/)[0];
    const titleText = 'SENHA DE ACESSO';
    const actionText = 'Use a senha abaixo para fazer seu login:';
        const year = new Date().getFullYear();
        const systemName = appName || 'NextLevel E-learning System';
        // Botão mostra a senha (sem link de ação real) – usamos href vazio para não quebrar filtros; pode ser ajustado depois
        const safeSenha = senha.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return `<!DOCTYPE html><html dir="ltr" xmlns="http://www.w3.org/1999/xhtml" xmlns:o="urn:schemas-microsoft-com:office:office">
  <head>
    <meta charset="UTF-8">
    <meta content="width=device-width, initial-scale=1" name="viewport">
    <meta name="x-apple-disable-message-reformatting">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta content="telephone=no" name="format-detection">
    <title></title>
  </head>
  <body class="body">
    <div dir="ltr" class="es-wrapper-color">
      <table width="100%" cellspacing="0" cellpadding="0" class="es-wrapper">
        <tbody>
          <tr>
            <td valign="top" class="esd-email-paddings">
              <table cellpadding="0" cellspacing="0" align="center" class="es-header">
                <tbody>
                  <tr>
                    <td align="center" class="es-adaptive esd-stripe">
                      <table width="600" cellspacing="0" cellpadding="0" bgcolor="#3d5ca3" align="center" class="es-header-body" style="background-color:rgb(61, 92, 163)">
                        <tbody>
                          <tr>
                            <td align="left" background="https://fwurcif.stripocdn.email/content/guids/CABINET_112efbf2b7fdaa9566e70d14a2294afa7330a36c054b2038b95a508d08fa26a1/images/chatgpt_image_4_de_set_de_2025_21_40_20.png" class="esd-structure es-p10" style="background-image: url(https://fwurcif.stripocdn.email/content/guids/CABINET_112efbf2b7fdaa9566e70d14a2294afa7330a36c054b2038b95a508d08fa26a1/images/chatgpt_image_4_de_set_de_2025_21_40_20.png); background-repeat: repeat; background-position: left top; background-size: cover">
                              <table cellspacing="0" cellpadding="0" align="left" class="es-left">
                                <tbody>
                                  <tr>
                                    <td width="580" align="left" class="esd-container-frame">
                                      <table width="100%" cellspacing="0" cellpadding="0">
                                        <tbody>
                                          <tr>
                                            <td align="center" class="esd-block-image" style="font-size: 0">
                                              <a target="_blank">
                                                <img src="https://fwurcif.stripocdn.email/content/guids/CABINET_112efbf2b7fdaa9566e70d14a2294afa7330a36c054b2038b95a508d08fa26a1/images/logo.png" alt="" width="150" class="img-6091">
                                              </a>
                                            </td>
                                          </tr>
                                        </tbody>
                                      </table>
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </td>
                  </tr>
                </tbody>
              </table>
              <table cellspacing="0" cellpadding="0" align="center" class="es-content">
                <tbody>
                  <tr>
                    <td bgcolor="#fafafa" align="center" class="esd-stripe" style="background-color:rgb(250, 250, 250)">
                      <table esd-img-prev-src width="600" cellspacing="0" cellpadding="0" bgcolor="#ffffff" align="center" class="es-content-body" style="background-color: rgb(255, 255, 255)">
                        <tbody>
                          <tr>
                            <td esd-img-prev-src="https://fkus.stripocdn.email/content/guids/CABINET_8a8240f4650bd716d3cd69675fe184ca/images/1041555765740937.png" esd-img-prev-position="left top" esd-img-prev-repeat="no-repeat" bgcolor="transparent" align="left" class="esd-structure es-p20r es-p20l es-p20t" style="background-color: transparent; background-position: left top">
                              <table width="100%" cellspacing="0" cellpadding="0">
                                <tbody>
                                  <tr>
                                    <td width="560" valign="top" align="center" class="esd-container-frame">
                                      <table esd-img-prev-src esd-img-prev-position="left top" width="100%" cellspacing="0" cellpadding="0" style="background-position:left top">
                                        <tbody>
                                          <tr>
                                            <td align="center" class="esd-block-image es-p5t es-p5b" style="font-size: 0">
                                              <a target="_blank">
                                                <img src="https://fwurcif.stripocdn.email/content/guids/CABINET_dd354a98a803b60e2f0411e893c82f56/images/23891556799905703.png" alt="" width="175" style="display:block">
                                              </a>
                                            </td>
                                          </tr>
                                          <tr>
                                            <td align="center" class="esd-block-text es-p15t es-p15b">
                                              <h1 style="color:#333333;font-size:20px">
                                              ${titleText}
                                              </h1>
                                            </td>
                                          </tr>
                                          <tr>
                                            <td align="left" class="esd-block-text es-p40r es-p40l">
                                              <p style="text-align:center">
                                 Olá,&nbsp;${firstName} </p>
                                            </td>
                                          </tr>
                                          <tr>
                                            <td align="left" class="esd-block-text es-p35r es-p40l">
                                              <p style="text-align:center">${actionText}
                                               </p>
                                            </td>
                                          </tr>
                                          <tr>
                                            <td align="center" class="esd-block-button es-p10r es-p10l es-p20t es-p20b">
                                              <span class="es-button-border">
                                              ${safeSenha}
                                               </span>
                                            </td>
                                          </tr>
                                        </tbody>
                                      </table>
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                          <tr>
                          </tr>
                          <tr>
                          </tr>
                        </tbody>
                      </table>
                    </td>
                  </tr>
                </tbody>
              </table>
              <table cellspacing="0" cellpadding="0" align="center" class="es-footer">
                <tbody>
                  <tr>
                    <td bgcolor="#fafafa" align="center" class="esd-stripe" style="background-color:rgb(250, 250, 250)">
                      <table esd-img-prev-src width="600" cellspacing="0" cellpadding="0" bgcolor="#ffffff" align="center" class="es-footer-body">
                        <tbody>
                          <tr>
                            <td esd-img-prev-src esd-img-prev-position="left top" align="left" background="https://fwurcif.stripocdn.email/content/guids/CABINET_112efbf2b7fdaa9566e70d14a2294afa7330a36c054b2038b95a508d08fa26a1/images/chatgpt_image_4_de_set_de_2025_21_40_20.png" class="esd-structure es-p10t es-p20r es-p20l es-p10b" style="background-position: left top; background-image: url(https://fwurcif.stripocdn.email/content/guids/CABINET_112efbf2b7fdaa9566e70d14a2294afa7330a36c054b2038b95a508d08fa26a1/images/chatgpt_image_4_de_set_de_2025_21_40_20.png); background-repeat: no-repeat; background-size: cover">
                              <table width="100%" cellspacing="0" cellpadding="0">
                                <tbody>
                                  <tr>
                                    <td width="560" valign="top" align="center" class="esd-container-frame">
                                      <table width="100%" cellspacing="0" cellpadding="0">
                                        <tbody>
                                          <tr>
                                            <td align="center" class="esd-block-text es-p5t es-p5b es-text-6283">
                                              <p class="es-text-mobile-size-14" style="font-size: 14px; color: #ffffff">
<strong>© ${year}. &nbsp;${systemName}.</strong>
                                              </p>
                                            </td>
                                          </tr>
                                        </tbody>
                                      </table>
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </td>
                  </tr>
                </tbody>
              </table>
              <table cellspacing="0" cellpadding="0" align="center" class="es-footer">
                <tbody>
                  <tr>
                    <td bgcolor="#fafafa" align="center" class="esd-stripe" style="background-color:rgb(250, 250, 250)">
                      <table esd-img-prev-src width="600" cellspacing="0" cellpadding="0" bgcolor="transparent" align="center" class="es-footer-body" style="background-color:transparent">
                        <tbody>
                          <tr>
                            <td align="left" esd-img-prev-src class="esd-structure es-p15t es-p20r es-p20l es-p5b">
                              <table width="100%" cellspacing="0" cellpadding="0">
                                <tbody>
                                  <tr>
                                    <td width="560" valign="top" align="center" class="esd-container-frame">
                                      <table width="100%" cellspacing="0" cellpadding="0">
                                        <tbody>
                                          <tr>
                                            <td esd-links-color="#666666" align="center" class="esd-block-text es-text-8687">
                                              <p class="es-text-mobile-size-12" style="font-size: 12px">
                                                <a target="_blank" href="tel:123456789" style="font-size: 12px; color: #666666">E-mail automático - não responda.</a>
                                              </p>
                                            </td>
                                          </tr>
                                          <tr>
                                            <td esd-links-underline="underline" align="center" class="esd-block-text es-m-p5t es-p5b">
                                              <p style="font-size:12px;color:#666666">
                                                Se você não fez essa solicitação, ignore este e-mail. ou entre em contato com o suporte.
                                              </p>
                                            </td>
                                          </tr>
                                        </tbody>
                                      </table>
                                    </td>
                                  </tr>
                                </tbody>
                              </table>
                            </td>
                          </tr>
                        </tbody>
                      </table>
                    </td>
                  </tr>
                </tbody>
              </table>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </body>
</html>`;
}

export async function sendRegistrationEmail(params: { nome: string; email: string; senha: string; }) {
    const html = buildPasswordTemplate({ tipo: 'register', nome: params.nome, senha: params.senha, appName: process.env.APP_NAME });
    // Texto em branco: senha só aparece no HTML conforme template fornecido
    return sendMail(params.email, '🎓 Acesso Criado - NextLevel', '', html);
}

// -------- Reset reutilizando layout: muda apenas título do badge e assunto --------
export async function sendPasswordResetEmail(params: { nome: string; email: string; novaSenha: string; }) {
    const html = buildPasswordTemplate({ tipo: 'reset', nome: params.nome, senha: params.novaSenha, appName: process.env.APP_NAME });
    return sendMail(params.email, '🔐 Senha Redefinida - NextLevel', '', html);
}

