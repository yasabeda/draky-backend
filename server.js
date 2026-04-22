// ============================================
// DRAKY BACKEND v2 — with Supabase Sync
// ============================================
//
// Setup:
// 1. Supabase project oluştur: https://supabase.com
// 2. SQL Editor → supabase_schema.sql'i çalıştır
// 3. Settings → API → iki değeri al:
//    - Project URL: https://xxxxx.supabase.co
//    - service_role key (secret, başında "eyJ..." ile başlar)
// 4. Render env variables'a ekle:
//    - BOT_TOKEN (mevcut)
//    - SUPABASE_URL
//    - SUPABASE_SERVICE_KEY
// 5. Deploy et

const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json({ limit: '2mb' }));

const BOT_TOKEN = process.env.BOT_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!BOT_TOKEN) {
  console.error('❌ BOT_TOKEN is required');
  process.exit(1);
}
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.warn('⚠️ SUPABASE not configured — sync endpoints will fail');
}

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.get('/', (req, res) => res.json({
  status: 'DRAKY backend running 🐉',
  supabase: !!(SUPABASE_URL && SUPABASE_KEY),
}));

function verifyTelegramInitData(initData) {
  if (!initData) return null;
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return null;
    params.delete('hash');
    const dataCheckString = [...params.entries()]
      .map(([k, v]) => `${k}=${v}`)
      .sort()
      .join('\n');
    const secret = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const calcHash = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');
    if (calcHash !== hash) return null;
    const userStr = params.get('user');
    if (!userStr) return null;
    const user = JSON.parse(userStr);
    return { userId: 'tg_' + user.id, username: user.username, firstName: user.first_name };
  } catch (e) {
    return null;
  }
}

async function sb(path, options = {}) {
  if (!SUPABASE_URL || !SUPABASE_KEY) throw new Error('Supabase not configured');
  const url = SUPABASE_URL + '/rest/v1/' + path;
  const r = await fetch(url, {
    ...options,
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation',
      ...(options.headers || {}),
    },
  });
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`Supabase ${r.status}: ${text}`);
  }
  return r.json();
}

// ======== SYNC ========
app.post('/api/load', async (req, res) => {
  try {
    const { initData } = req.body;
    const user = verifyTelegramInitData(initData);
    if (!user) return res.status(401).json({ error: 'Invalid initData' });
    const rows = await sb(`players?user_id=eq.${encodeURIComponent(user.userId)}&select=state,display_name`);
    if (rows.length === 0) {
      await sb('players', {
        method: 'POST',
        body: JSON.stringify({
          user_id: user.userId,
          username: user.username || null,
          display_name: user.firstName || 'Oyuncu',
          state: {},
        }),
      });
      return res.json({ state: null, isNew: true });
    }
    return res.json({ state: rows[0].state, displayName: rows[0].display_name, isNew: false });
  } catch (err) {
    console.error('/api/load error:', err.message);
    return res.status(500).json({ error: 'Load failed' });
  }
});

app.post('/api/save', async (req, res) => {
  try {
    const { initData, state, leaderboardInfo } = req.body;
    const user = verifyTelegramInitData(initData);
    if (!user) return res.status(401).json({ error: 'Invalid initData' });
    if (!state || typeof state !== 'object') {
      return res.status(400).json({ error: 'Invalid state' });
    }
    await sb('players', {
      method: 'POST',
      headers: { 'Prefer': 'resolution=merge-duplicates' },
      body: JSON.stringify({
        user_id: user.userId,
        username: user.username || null,
        display_name: user.firstName || 'Oyuncu',
        state,
      }),
    });
    if (leaderboardInfo) {
      try {
        await sb('leaderboard', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify({
            user_id: user.userId,
            display_name: user.firstName || 'Oyuncu',
            trophies: leaderboardInfo.trophies || 0,
            total_power: leaderboardInfo.totalPower || 0,
            dragons_count: leaderboardInfo.dragonsCount || 0,
            is_premium: leaderboardInfo.isPremium || false,
          }),
        });
      } catch (e) { console.warn('Leaderboard fail:', e.message); }
    }
    return res.json({ ok: true });
  } catch (err) {
    console.error('/api/save error:', err.message);
    return res.status(500).json({ error: 'Save failed' });
  }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const rows = await sb('leaderboard?select=user_id,display_name,trophies,total_power,dragons_count,is_premium&order=trophies.desc&limit=100');
    return res.json({ players: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Leaderboard fetch failed' });
  }
});

app.post('/api/referrals', async (req, res) => {
  try {
    const { initData } = req.body;
    const user = verifyTelegramInitData(initData);
    if (!user) return res.status(401).json({ error: 'Invalid initData' });
    const rows = await sb(`referrals?referrer_id=eq.${encodeURIComponent(user.userId)}&select=*&order=created_at.desc&limit=50`);
    const total = rows.reduce((s, r) => s + (r.reward || 0), 0);
    return res.json({ referrals: rows, count: rows.length, totalEarned: total });
  } catch (err) {
    return res.status(500).json({ error: 'Referrals fetch failed' });
  }
});

// ======== STARS PAYMENT ========
app.post('/api/create-invoice', async (req, res) => {
  try {
    const { title, description, payload, amount } = req.body;
    if (!title || !description || !payload || !amount) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    if (typeof amount !== 'number' || amount < 1) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    const response = await fetch(`${TELEGRAM_API}/createInvoiceLink`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: title.slice(0, 32),
        description: description.slice(0, 255),
        payload,
        provider_token: '',
        currency: 'XTR',
        prices: [{ label: title, amount }],
      }),
    });
    const data = await response.json();
    if (!data.ok) return res.status(500).json({ error: data.description });
    return res.json({ url: data.result });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ======== WEBHOOK ========
app.post('/webhook', async (req, res) => {
  const update = req.body;

  if (update.pre_checkout_query) {
    const q = update.pre_checkout_query;
    try {
      await fetch(`${TELEGRAM_API}/answerPreCheckoutQuery`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pre_checkout_query_id: q.id, ok: true }),
      });
    } catch (e) {}
  }

  if (update.message && update.message.successful_payment) {
    const msg = update.message;
    const pay = msg.successful_payment;
    const userId = 'tg_' + msg.from.id;
    console.log(`✅ Payment: ${userId} ${pay.total_amount}⭐ ${pay.invoice_payload}`);
    if (SUPABASE_URL && SUPABASE_KEY) {
      try {
        await sb('payments', {
          method: 'POST',
          body: JSON.stringify({
            user_id: userId,
            stars_amount: pay.total_amount,
            payload: pay.invoice_payload,
            telegram_charge_id: pay.telegram_payment_charge_id,
          }),
        });
      } catch (e) { console.warn('Payment log fail:', e.message); }
    }
    try {
      await fetch(`${TELEGRAM_API}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: msg.from.id,
          text: `🎉 Ödeme alındı! ${pay.total_amount} ⭐`,
        }),
      });
    } catch (e) {}
  }

  if (update.message && update.message.text && update.message.text.startsWith('/start')) {
    const msg = update.message;
    const userId = 'tg_' + msg.from.id;
    const userName = msg.from.first_name || 'Oyuncu';
    const parts = msg.text.split(' ');
    if (parts.length > 1 && parts[1].startsWith('ref_')) {
      const referrerId = parts[1].slice(4);
      if (referrerId !== userId && SUPABASE_URL && SUPABASE_KEY) {
        try {
          const refRows = await sb(`players?user_id=eq.${encodeURIComponent(referrerId)}&select=state`);
          const isPrem = refRows.length > 0 && refRows[0].state && refRows[0].state.isPremium;
          const reward = isPrem ? 7 : 3;
          await sb('referrals', {
            method: 'POST',
            body: JSON.stringify({
              referrer_id: referrerId,
              referred_id: userId,
              referred_name: userName,
              reward,
              is_premium_bonus: isPrem,
            }),
          });
          if (refRows.length > 0) {
            const newState = refRows[0].state || {};
            newState.drakyCoin = (newState.drakyCoin || 0) + reward;
            newState.referralRewardsTotal = (newState.referralRewardsTotal || 0) + reward;
            await sb(`players?user_id=eq.${encodeURIComponent(referrerId)}`, {
              method: 'PATCH',
              body: JSON.stringify({ state: newState }),
            });
            const referrerTelegramId = referrerId.replace('tg_', '');
            try {
              await fetch(`${TELEGRAM_API}/sendMessage`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  chat_id: referrerTelegramId,
                  text: `🎉 ${userName} davetinle katıldı! +${reward} 💎 DRAKY kazandın!`,
                }),
              });
            } catch (e) {}
          }
        } catch (e) {
          if (!e.message.includes('23505')) console.warn('Referral err:', e.message);
        }
      }
    }
    try {
      await fetch(`${TELEGRAM_API}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: msg.from.id,
          text: `🐉 DRAKY'ye hoş geldin ${userName}! 🎮 OYNA butonuna bas!`,
        }),
      });
    } catch (e) {}
  }

  res.sendStatus(200);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🐉 DRAKY backend v2 on port ${PORT}`);
  console.log(`   BOT_TOKEN: ${BOT_TOKEN ? '✅' : '❌'}`);
  console.log(`   SUPABASE: ${SUPABASE_URL ? '✅' : '❌'}`);
});
