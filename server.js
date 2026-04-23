// ============================================
// DRAKY BACKEND v3 — Secure
// ============================================
// Features:
//   • HMAC Telegram initData verification
//   • Rate limiting (per IP + per user)
//   • Anti-cheat: state validation (server rejects unrealistic changes)
//   • CORS restricted to allowed origins
//   • Supabase sync (players, leaderboard, referrals, payments)
//   • Telegram Stars payment handling
//
// Environment variables required:
//   BOT_TOKEN             — from @BotFather
//   SUPABASE_URL          — https://xxxxx.supabase.co
//   SUPABASE_SERVICE_KEY  — service_role key (backend only!)
//   ALLOWED_ORIGINS       — comma-separated list, e.g. "https://your.netlify.app"
//                           (leave empty for dev/any-origin)

const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json({ limit: '2mb' }));

const BOT_TOKEN = process.env.BOT_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

if (!BOT_TOKEN) {
  console.error('❌ BOT_TOKEN is required');
  process.exit(1);
}
if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.warn('⚠️ SUPABASE not configured — sync endpoints will fail');
}

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

// ============================================
// CORS — restricted to allowed origins
// ============================================
app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.length === 0) {
    // No restriction (dev mode — warn in logs)
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  } else if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    // Origin not allowed — for webhook from Telegram or health checks, still respond
    // but don't expose CORS headers to frontend from unknown origins
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Max-Age', '86400');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ============================================
// Rate limiting (in-memory, per IP + per user)
// ============================================
const rateLimits = new Map();  // key → { count, resetAt }
const RATE_LIMIT_CLEANUP_INTERVAL = 60000;  // 1 min
// Periodically clean expired entries (memory leak protection)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimits.entries()) {
    if (entry.resetAt < now) rateLimits.delete(key);
  }
}, RATE_LIMIT_CLEANUP_INTERVAL);

function checkRateLimit(key, maxReqs, windowMs) {
  const now = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || entry.resetAt < now) {
    rateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (entry.count >= maxReqs) return false;
  entry.count++;
  return true;
}

function rateLimitMiddleware(maxReqs, windowMs) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip || 'unknown';
    const key = `ip:${ip}:${req.path}`;
    if (!checkRateLimit(key, maxReqs, windowMs)) {
      return res.status(429).json({ error: 'Too many requests — slow down' });
    }
    next();
  };
}

// ============================================
// Health check
// ============================================
app.get('/', (req, res) => res.json({
  status: 'DRAKY backend running 🐉',
  supabase: !!(SUPABASE_URL && SUPABASE_KEY),
  cors_restricted: ALLOWED_ORIGINS.length > 0,
}));

// Dedicated health endpoint for UptimeRobot
app.get('/api/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ============================================
// Telegram initData HMAC verification
// ============================================
function verifyTelegramInitData(initData) {
  if (!initData || typeof initData !== 'string') return null;
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
    // Check freshness: initData older than 24 hours is rejected
    const authDate = parseInt(params.get('auth_date') || '0', 10);
    if (authDate && (Date.now() / 1000 - authDate) > 86400) return null;
    const userStr = params.get('user');
    if (!userStr) return null;
    const user = JSON.parse(userStr);
    if (!user || !user.id) return null;
    return {
      userId: 'tg_' + user.id,
      username: (user.username || '').slice(0, 64),
      firstName: (user.first_name || 'Oyuncu').slice(0, 40),
    };
  } catch (e) {
    return null;
  }
}

// ============================================
// Supabase REST helper
// ============================================
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

// ============================================
// Anti-cheat state validator
// ============================================
const MAX_LIMITS = {
  gold: 1e12,           // 1 trillion max
  stars: 100000,        // max Stars ever held
  drakyCoin: 10000,     // max airdrop coins
  energy: 500,          // safety cap
  maxEnergy: 500,
  trophies: 100000,
  dragons: 500,         // max dragon count
  arenaWins: 1000000,
  arenaLosses: 1000000,
  dungeonsCompleted: 1000000,
  totalTaps: 1e10,
};

// Per-minute rate of increase limits (to catch sudden spikes)
const MAX_INCREASE_PER_MIN = {
  gold: 1000000,        // 1M/min max (tap farming)
  drakyCoin: 75,        // daily cap is 75
  trophies: 200,        // realistic arena win rate
  stars: 10000,         // one huge purchase
};

function validateState(newState, oldState) {
  if (!newState || typeof newState !== 'object') return { ok: false, error: 'invalid state' };

  // Sanity check: dragons must be an array
  if (!Array.isArray(newState.dragons)) return { ok: false, error: 'dragons must be array' };
  if (newState.dragons.length > MAX_LIMITS.dragons) {
    return { ok: false, error: 'too many dragons' };
  }

  // Check absolute caps
  for (const [key, max] of Object.entries(MAX_LIMITS)) {
    if (key === 'dragons') continue;  // handled above
    const val = newState[key];
    if (typeof val === 'number' && val > max) {
      return { ok: false, error: `${key} exceeds max (${val} > ${max})` };
    }
    if (typeof val === 'number' && val < 0 && key !== 'arenaLosses') {
      return { ok: false, error: `${key} is negative` };
    }
  }

  // If old state exists, check rate of increase
  if (oldState && typeof oldState === 'object') {
    const lastSave = oldState.lastLoad || 0;
    const minutesSince = Math.max(0.5, (Date.now() - lastSave) / 60000);
    for (const [key, maxPerMin] of Object.entries(MAX_INCREASE_PER_MIN)) {
      const oldVal = oldState[key] || 0;
      const newVal = newState[key] || 0;
      const delta = newVal - oldVal;
      if (delta > maxPerMin * minutesSince) {
        return {
          ok: false,
          error: `${key} grew too fast: +${delta} in ${minutesSince.toFixed(1)}min (max ${Math.floor(maxPerMin * minutesSince)})`,
        };
      }
    }
  }

  return { ok: true };
}

// ============================================
// SYNC ENDPOINTS
// ============================================

// Load player state
app.post('/api/load', rateLimitMiddleware(30, 60000), async (req, res) => {
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
          display_name: user.firstName,
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

// Save player state (with anti-cheat)
app.post('/api/save', rateLimitMiddleware(30, 60000), async (req, res) => {
  try {
    const { initData, state, leaderboardInfo } = req.body;
    const user = verifyTelegramInitData(initData);
    if (!user) return res.status(401).json({ error: 'Invalid initData' });
    if (!state || typeof state !== 'object') {
      return res.status(400).json({ error: 'Invalid state' });
    }

    // Per-user rate limit (extra layer)
    if (!checkRateLimit(`user:${user.userId}:save`, 20, 60000)) {
      return res.status(429).json({ error: 'Save rate too high' });
    }

    // Load existing state for anti-cheat comparison
    let oldState = null;
    try {
      const rows = await sb(`players?user_id=eq.${encodeURIComponent(user.userId)}&select=state`);
      if (rows.length > 0) oldState = rows[0].state;
    } catch(e) { /* proceed without comparison */ }

    // Anti-cheat validation
    const check = validateState(state, oldState);
    if (!check.ok) {
      console.warn(`⚠️ Anti-cheat rejected save for ${user.userId}: ${check.error}`);
      return res.status(400).json({ error: 'State validation failed: ' + check.error });
    }

    // Upsert
    await sb('players', {
      method: 'POST',
      headers: { 'Prefer': 'resolution=merge-duplicates' },
      body: JSON.stringify({
        user_id: user.userId,
        username: user.username || null,
        display_name: user.firstName,
        state,
      }),
    });

    // Update leaderboard
    if (leaderboardInfo && typeof leaderboardInfo === 'object') {
      try {
        await sb('leaderboard', {
          method: 'POST',
          headers: { 'Prefer': 'resolution=merge-duplicates' },
          body: JSON.stringify({
            user_id: user.userId,
            display_name: user.firstName,
            trophies: Math.max(0, Math.min(MAX_LIMITS.trophies, leaderboardInfo.trophies || 0)),
            total_power: Math.max(0, Math.min(1e9, leaderboardInfo.totalPower || 0)),
            dragons_count: Math.max(0, Math.min(MAX_LIMITS.dragons, leaderboardInfo.dragonsCount || 0)),
            is_premium: !!leaderboardInfo.isPremium,
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

// Global leaderboard (public, cached friendly)
app.get('/api/leaderboard', rateLimitMiddleware(60, 60000), async (req, res) => {
  try {
    const rows = await sb('leaderboard?select=user_id,display_name,trophies,total_power,dragons_count,is_premium&order=trophies.desc&limit=100');
    res.setHeader('Cache-Control', 'public, max-age=30');
    return res.json({ players: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Leaderboard fetch failed' });
  }
});

// Get user's referrals
app.post('/api/referrals', rateLimitMiddleware(20, 60000), async (req, res) => {
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

// ============================================
// STARS PAYMENT
// ============================================
app.post('/api/create-invoice', rateLimitMiddleware(10, 60000), async (req, res) => {
  try {
    const { title, description, payload, amount, initData } = req.body;

    // Verify user (extra safety — stars invoices should only go to real users)
    const user = verifyTelegramInitData(initData);
    if (!user) return res.status(401).json({ error: 'Invalid initData' });

    if (!title || !description || !payload || !amount) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    if (typeof amount !== 'number' || amount < 1 || amount > 100000) {
      return res.status(400).json({ error: 'Invalid amount (1-100000)' });
    }

    const response = await fetch(`${TELEGRAM_API}/createInvoiceLink`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        title: String(title).slice(0, 32),
        description: String(description).slice(0, 255),
        payload: String(payload).slice(0, 128),
        provider_token: '',
        currency: 'XTR',
        prices: [{ label: String(title).slice(0, 32), amount }],
      }),
    });
    const data = await response.json();
    if (!data.ok) return res.status(500).json({ error: 'Invoice creation failed' });
    return res.json({ url: data.result });
  } catch (err) {
    console.error('create-invoice error:', err.message);
    return res.status(500).json({ error: 'Internal error' });
  }
});

// ============================================
// TELEGRAM WEBHOOK
// ============================================
app.post('/webhook', async (req, res) => {
  // Respond immediately to avoid Telegram timeouts
  res.sendStatus(200);

  try {
    const update = req.body;

    // Pre-checkout: approve payment
    if (update.pre_checkout_query) {
      const q = update.pre_checkout_query;
      try {
        await fetch(`${TELEGRAM_API}/answerPreCheckoutQuery`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pre_checkout_query_id: q.id, ok: true }),
        });
      } catch (e) { console.error('pre_checkout failed:', e.message); }
    }

    // Successful payment
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

    // /start command — referral handling
    if (update.message && update.message.text && update.message.text.startsWith('/start')) {
      const msg = update.message;
      const userId = 'tg_' + msg.from.id;
      const userName = (msg.from.first_name || 'Oyuncu').slice(0, 40);
      const parts = msg.text.split(' ');
      if (parts.length > 1 && parts[1].startsWith('ref_')) {
        const referrerId = parts[1].slice(4).slice(0, 64);  // length limit
        if (referrerId !== userId && SUPABASE_URL && SUPABASE_KEY && /^tg_\d+$/.test(referrerId)) {
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
              newState.drakyCoin = Math.min(MAX_LIMITS.drakyCoin, (newState.drakyCoin || 0) + reward);
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
  } catch (err) {
    console.error('webhook processing error:', err.message);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🐉 DRAKY backend v3 (secure) on port ${PORT}`);
  console.log(`   BOT_TOKEN: ${BOT_TOKEN ? '✅' : '❌'}`);
  console.log(`   SUPABASE: ${SUPABASE_URL ? '✅' : '❌'}`);
  console.log(`   CORS origins: ${ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS.join(', ') : '(open — dev mode)'}`);
});
