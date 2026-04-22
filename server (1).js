// ============================================
// DRAKY BACKEND — Telegram Stars Payment Handler
// ============================================
// Deploy this to Render.com (free) or Railway.app
//
// Setup:
// 1. Set env variable BOT_TOKEN (get from @BotFather)
// 2. Deploy this as a Node.js service
// 3. Put the deploy URL into BACKEND_URL in draky_stars.html
// 4. Set webhook: https://api.telegram.org/bot<TOKEN>/setWebhook?url=<YOUR_URL>/webhook

const express = require('express');
const app = express();
app.use(express.json());

const BOT_TOKEN = process.env.BOT_TOKEN;
if (!BOT_TOKEN) {
  console.error('❌ BOT_TOKEN environment variable is required');
  process.exit(1);
}

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

// Enable CORS so Mini App can call us
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Health check
app.get('/', (req, res) => res.json({ status: 'DRAKY backend running 🐉' }));

// =============================================
// 1) CREATE INVOICE — Mini App calls this
// =============================================
app.post('/api/create-invoice', async (req, res) => {
  try {
    const { title, description, payload, amount } = req.body;

    // Validate inputs
    if (!title || !description || !payload || !amount) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    if (typeof amount !== 'number' || amount < 1) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    // Call Telegram Bot API → createInvoiceLink
    const response = await fetch(`${TELEGRAM_API}/createInvoiceLink`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: title.slice(0, 32),           // max 32 chars
        description: description.slice(0, 255), // max 255 chars
        payload,                              // your own identifier (max 128 bytes)
        provider_token: '',                   // empty for Stars
        currency: 'XTR',                      // XTR = Telegram Stars
        prices: [{ label: title, amount }],   // amount in stars (integer)
      }),
    });

    const data = await response.json();
    if (!data.ok) {
      console.error('Telegram API error:', data);
      return res.status(500).json({ error: data.description || 'Telegram API failed' });
    }

    return res.json({ url: data.result });
  } catch (err) {
    console.error('create-invoice error:', err);
    return res.status(500).json({ error: err.message });
  }
});

// =============================================
// 2) WEBHOOK — Telegram sends events here
// =============================================
app.post('/webhook', async (req, res) => {
  const update = req.body;

  // Pre-checkout: approve the payment
  if (update.pre_checkout_query) {
    const q = update.pre_checkout_query;
    try {
      await fetch(`${TELEGRAM_API}/answerPreCheckoutQuery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pre_checkout_query_id: q.id, ok: true }),
      });
    } catch (e) {
      console.error('pre_checkout approval failed:', e);
    }
  }

  // Successful payment: grant the purchase
  if (update.message && update.message.successful_payment) {
    const msg = update.message;
    const pay = msg.successful_payment;
    const userId = msg.from.id;

    console.log(`✅ Payment success: user=${userId} amount=${pay.total_amount} payload=${pay.invoice_payload}`);

    // TODO: In a real system, you'd look up `userId` and `pay.invoice_payload`
    // to credit the right item. The payload contains your identifier.
    //
    // Example:
    //   if (pay.invoice_payload.startsWith('market_')) { ... give dragon ... }
    //   if (pay.invoice_payload.startsWith('energy_')) { ... give energy ... }
    //   if (pay.invoice_payload.startsWith('premium_')) { ... give premium ... }
    //
    // Store this in a database (Firebase, Supabase, MongoDB, etc.)
    // Mini App reads its state from the database on open.

    // Notify user
    try {
      await fetch(`${TELEGRAM_API}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: userId,
          text: `🎉 Ödeme alındı! ${pay.total_amount} ⭐ · Öğen hesabına eklendi.`,
        }),
      });
    } catch (e) {
      console.error('send confirmation failed:', e);
    }
  }

  // /start command — handle referral
  if (update.message && update.message.text && update.message.text.startsWith('/start')) {
    const msg = update.message;
    const userId = msg.from.id;
    const userName = msg.from.first_name || 'Oyuncu';

    // Check for referral param (e.g., "/start ref_tg_12345")
    const parts = msg.text.split(' ');
    if (parts.length > 1 && parts[1].startsWith('ref_')) {
      const referrerId = parts[1].slice(4);
      console.log(`🎁 Referral: ${userName} (${userId}) came from ${referrerId}`);

      // TODO: Credit the referrer in your database
      // await db.credit(referrerId, REFERRAL_REWARD);
    }

    // Send welcome with Mini App button
    try {
      await fetch(`${TELEGRAM_API}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: userId,
          text: `🐉 DRAKY'ye hoş geldin ${userName}! Ejderhanı topla, zindanlarda dövüş, Airdrop kazan!`,
          reply_markup: {
            inline_keyboard: [[
              { text: '🎮 OYNA', web_app: { url: 'https://YOUR-NETLIFY-URL.netlify.app' } }
            ]],
          },
        }),
      });
    } catch (e) {
      console.error('send /start failed:', e);
    }
  }

  res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🐉 DRAKY backend listening on port ${PORT}`);
});
