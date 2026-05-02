const express = require("express");
const admin = require("firebase-admin");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
app.use(express.json());

// ─────────────────────────────────────────
// Firebase Admin Init
// ─────────────────────────────────────────
const serviceAccount = require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: "escola-do-cristao-milion-6787e",
});

const db = admin.firestore();
const auth = admin.auth();

// ─────────────────────────────────────────
// Email Transporter (configure via .env)
// ─────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT) || 465,
  secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ─────────────────────────────────────────
// Verificação de assinatura Kiwify
// ─────────────────────────────────────────
function verifyKiwifySignature(req) {
  const secret = process.env.KIWIFY_WEBHOOK_SECRET;
  if (!secret) return true; // pula se não configurado

  const signature = req.headers["x-kiwify-signature"] || "";
  const body = JSON.stringify(req.body);
  const expected = crypto
    .createHmac("sha1", secret)
    .update(body)
    .digest("hex");

  return signature === expected;
}

// ─────────────────────────────────────────
// Envio de e-mail de boas-vindas
// ─────────────────────────────────────────
async function sendWelcomeEmail(name, email, password) {
  const mailOptions = {
    from: `"Escola do Cristão" <${process.env.SMTP_USER}>`,
    to: email,
    subject: "✅ Seu acesso à Escola do Cristão está pronto!",
    html: `
      <!DOCTYPE html>
      <html lang="pt-BR">
      <head>
        <meta charset="UTF-8" />
        <style>
          body { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }
          .container { max-width: 580px; margin: 40px auto; background: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.08); }
          .header { background: #1a237e; padding: 32px 40px; text-align: center; }
          .header h1 { color: #ffffff; margin: 0; font-size: 24px; }
          .body { padding: 36px 40px; }
          .body p { color: #333; line-height: 1.7; font-size: 15px; }
          .credentials { background: #f0f4ff; border-left: 4px solid #1a237e; border-radius: 6px; padding: 18px 24px; margin: 24px 0; }
          .credentials p { margin: 6px 0; font-size: 15px; color: #222; }
          .credentials strong { color: #1a237e; }
          .btn { display: inline-block; margin-top: 24px; padding: 14px 32px; background: #1a237e; color: #fff; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: bold; }
          .footer { background: #f4f4f4; text-align: center; padding: 20px; font-size: 12px; color: #888; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 Bem-vindo(a) à Escola do Cristão!</h1>
          </div>
          <div class="body">
            <p>Olá, <strong>${name}</strong>!</p>
            <p>Sua compra foi confirmada. Abaixo estão suas credenciais de acesso à plataforma:</p>
            <div class="credentials">
              <p>📧 <strong>E-mail:</strong> ${email}</p>
              <p>🔑 <strong>Senha:</strong> ${password}</p>
            </div>
            <p>Recomendamos que você altere sua senha após o primeiro acesso.</p>
            <a class="btn" href="${process.env.APP_URL || "https://escoladocristao.com.br"}">
              Acessar a plataforma
            </a>
            <p style="margin-top:28px;">Qualquer dúvida, estamos à disposição. Que Deus abençoe sua jornada! 🙏</p>
          </div>
          <div class="footer">
            © ${new Date().getFullYear()} Escola do Cristão — Todos os direitos reservados.
          </div>
        </div>
      </body>
      </html>
    `,
  };

  await transporter.sendMail(mailOptions);
  console.log(`📧 E-mail enviado para ${email}`);
}

// ─────────────────────────────────────────
// Rota principal do webhook
// ─────────────────────────────────────────
app.post("/webhook/kiwify", async (req, res) => {
  try {
    // 1. Verificar assinatura
    if (!verifyKiwifySignature(req)) {
      console.warn("⚠️  Assinatura inválida recebida.");
      return res.status(401).json({ error: "Assinatura inválida" });
    }

    const payload = req.body;
    console.log("📦 Payload recebido:", JSON.stringify(payload, null, 2));

    // 2. Filtrar apenas status aprovado
    // Kiwify envia order_status = "paid" para compras aprovadas
    const orderStatus = payload?.order_status;
    if (orderStatus !== "paid") {
      console.log(`ℹ️  Status ignorado: ${orderStatus}`);
      return res.status(200).json({ message: `Status '${orderStatus}' ignorado` });
    }

    // 3. Extrair dados do comprador
    const customer = payload?.Customer || {};
    const name = customer.full_name || customer.name || "Aluno";
    const email = customer.email;

    if (!email) {
      console.error("❌ E-mail não encontrado no payload");
      return res.status(400).json({ error: "E-mail não encontrado no payload" });
    }

    const DEFAULT_PASSWORD = "ecm@2026";
    const orderId = payload?.order_id || `kiwify_${Date.now()}`;
    const productName = payload?.Product?.name || "Plano Pago";

    // 4. Criar usuário no Firebase Auth (ou atualizar se já existir)
    let uid;
    try {
      const existingUser = await auth.getUserByEmail(email);
      uid = existingUser.uid;
      console.log(`👤 Usuário já existe no Auth: ${uid}`);

      await auth.updateUser(uid, {
        displayName: name,
        password: DEFAULT_PASSWORD,
        emailVerified: true,
      });
    } catch (authError) {
      if (authError.code === "auth/user-not-found") {
        const newUser = await auth.createUser({
          email,
          password: DEFAULT_PASSWORD,
          displayName: name,
          emailVerified: true,
        });
        uid = newUser.uid;
        console.log(`✅ Novo usuário criado no Firebase Auth: ${uid}`);
      } else {
        throw authError;
      }
    }

    // 5. Criar/Atualizar documento no Firestore
    const now = admin.firestore.FieldValue.serverTimestamp();

    await db.collection("users").doc(uid).set(
      {
        uid,
        name,
        email,
        plan: "paid",
        planName: productName,
        orderId,
        purchasedAt: now,
        updatedAt: now,
        active: true,
        source: "kiwify",
      },
      { merge: true }
    );

    // Salva pedido para histórico
    await db.collection("orders").doc(orderId).set({
      uid,
      email,
      name,
      orderId,
      productName,
      orderStatus,
      rawPayload: payload,
      createdAt: now,
    });

    console.log(`📝 Firestore atualizado para UID: ${uid}`);

    // 6. Enviar e-mail de boas-vindas
    await sendWelcomeEmail(name, email, DEFAULT_PASSWORD);

    return res.status(200).json({
      success: true,
      message: "Usuário criado/atualizado com sucesso",
      uid,
      email,
    });
  } catch (error) {
    console.error("❌ Erro no webhook:", error);
    return res.status(500).json({ error: "Erro interno", details: error.message });
  }
});

// Health check
app.get("/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Webhook rodando na porta ${PORT}`));