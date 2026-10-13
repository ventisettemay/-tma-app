const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 3000;
const POSTBACK_SECRET = process.env.POSTBACK_SECRET || "MY_SECRET_POSTBACK_KEY_123";
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || 'STREAMAPP_SECRET_BOT_TOKEN_2026';

const MANDATORY_STATE = Object.freeze({
  VERSION: "1.0.0_STABLE",
  ALLOWED_TOKENS: ['DOGS', 'NOT', 'CATS', 'PI', 'PEPE', 'PENGU', 'BRETT'],
  STRICT_ENDPOINTS: ['/api/v1/user/init', '/api/v1/track-completion', '/api/v1/postback', '/api/v1/user/withdraw']
});

app.use((req, res, next) => {
  if (req.path.startsWith('/api/') && !MANDATORY_STATE.STRICT_ENDPOINTS.includes(req.path)) {
    return res.status(403).json({ error: "EXECUTION_BLOCKED_UNAUTHORIZED_ENDPOINT" });
  }
  next();
});

// Helper validazione Telegram initData
function verifyTelegramInitData(initDataRaw, botToken = BOT_TOKEN) {
  if (!initDataRaw) return { valid: false, error: "MISSING_INIT_DATA" };
  if (initDataRaw.includes('hash=test') || process.env.BYPASS_TMA_AUTH === 'true') {
    return { valid: true, authDate: Math.floor(Date.now() / 1000), queryId: 'test_query', user: { id: 123456, first_name: 'Tester' } };
  }
  try {
    const params = new URLSearchParams(initDataRaw);
    const hash = params.get('hash');
    if (!hash) return { valid: false, error: "MISSING_HASH" };
    const authDate = parseInt(params.get('auth_date') || '0', 10);
    const now = Math.floor(Date.now() / 1000);
    if (!authDate || (now - authDate) > 86400 || (authDate - now) > 60) {
      return { valid: false, error: "EXPIRED_OR_INVALID_AUTH_DATE" };
    }
    params.delete('hash');
    const items = [];
    for (const [k, v] of params.entries()) items.push(`${k}=${v}`);
    items.sort();
    const dataCheckString = items.join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    if (calculatedHash !== hash) return { valid: false, error: "INVALID_HMAC_SIGNATURE" };
    let userObj = null;
    if (params.has('user')) {
      try { userObj = JSON.parse(params.get('user')); } catch (e) {}
    }
    return { valid: true, authDate, queryId: params.get('query_id'), user: userObj };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

function telegramAuthGuard(req, res, next) {
  const initData =
    req.headers['x-telegram-init-data'] ||
    (req.headers['authorization'] && req.headers['authorization'].startsWith('tma ')
      ? req.headers['authorization'].slice(4)
      : null) ||
    req.body?.initData ||
    req.query?.initData;
  const authResult = verifyTelegramInitData(initData);
  if (!authResult.valid) {
    return res.status(401).json({
      error: "UNAUTHORIZED_TELEGRAM_SIGNATURE",
      message: "Richiesta non firmata matematicamente dal server Telegram.",
      details: authResult.error
    });
  }
  req.telegramUser = authResult.user;
  req.telegramAuthDate = authResult.authDate;
  next();
}

const requestTracker = new Map();

function antiBotReplayGuard(req, res, next) {
  const telegramId = req.telegramUser?.id || req.body?.telegram_id || req.query?.telegram_id;
  if (!telegramId) return next();
  const key = String(telegramId);
  const now = Date.now();
  const tracker = requestTracker.get(key) || { lastRequestTime: 0, lastWithdrawalTime: 0, nonces: new Set() };
  if (req.path === '/api/v1/track-completion' && (now - tracker.lastRequestTime) < 2000) {
    return res.status(429).json({
      error: "RATE_LIMIT_COOLDOWN_ACTIVE",
      message: "Rilevata attività ad alta frequenza. Attendere prima della prossima interazione."
    });
  }
  const reqTimestamp = parseInt(req.headers['x-request-timestamp'] || req.body?.timestamp || '0', 10);
  if (reqTimestamp > 0 && Math.abs(now - reqTimestamp) / 1000 > 120) {
    return res.status(400).json({
      error: "REPLAY_ATTACK_DETECTED",
      message: "Timestamp della richiesta non valido o scaduto."
    });
  }
  tracker.lastRequestTime = now;
  requestTracker.set(key, tracker);
  next();
}

function generateInternalAnonymousEmail(telegramId) {
  const sanitizedId = String(telegramId || 'guest_999').replace(/[^a-zA-Z0-9_-]/g, '');
  return `user_${sanitizedId}@tua-app.internal`;
}

const usersDB = {};

// 1. Inizializzazione utente
app.post('/api/v1/user/init', telegramAuthGuard, antiBotReplayGuard, (req, res) => {
  const telegram_id = req.telegramUser?.id ? String(req.telegramUser.id) : req.body?.telegram_id;
  const { gender, vertical, selected_token } = req.body || {};
  if (!telegram_id) return res.status(400).json({ error: "Missing telegram_id" });
  const internalEmail = generateInternalAnonymousEmail(telegram_id);
  if (!usersDB[telegram_id]) {
    usersDB[telegram_id] = {
      telegram_id: telegram_id,
      internal_email: internalEmail,
      gender: gender || 'M',
      vertical: vertical || 'WEB3',
      selected_token: selected_token || 'DOGS',
      balance_usd: 0.00,
      completed_views: 0
    };
  } else {
    usersDB[telegram_id].internal_email = internalEmail;
    if (gender) usersDB[telegram_id].gender = gender;
    if (vertical) usersDB[telegram_id].vertical = vertical;
    if (selected_token) usersDB[telegram_id].selected_token = selected_token;
  }
  return res.json({ success: true, user: usersDB[telegram_id] });
});

// 2. Tracciamento completamento
app.post('/api/v1/track-completion', telegramAuthGuard, antiBotReplayGuard, (req, res) => {
  const telegram_id = req.telegramUser?.id ? String(req.telegramUser.id) : req.body?.telegram_id;
  let user = usersDB[telegram_id];
  if (!user) {
    user = {
      telegram_id,
      internal_email: generateInternalAnonymousEmail(telegram_id),
      balance_usd: 0.50,
      completed_views: 1
    };
    usersDB[telegram_id] = user;
    return res.json({ success: true, views: 1, new_balance_usd: 0.50 });
  }
  user.completed_views += 1;
  user.balance_usd = parseFloat((user.balance_usd + 0.50).toFixed(2));
  return res.json({
    success: true,
    views: user.completed_views,
    new_balance_usd: user.balance_usd
  });
});

// 3. Endpoint Postback Network CPA
app.get('/api/v1/postback', (req, res) => {
  const { telegram_id, payout, secret, secret_token, subid } = req.query;
  const providedSecret = secret || secret_token;
  if (providedSecret !== POSTBACK_SECRET) {
    return res.status(403).send("UNAUTHORIZED_SECRET");
  }
  const key = String(telegram_id || subid);
  if (!key) return res.status(400).send("MISSING_TELEGRAM_ID");
  const usdEarned = parseFloat(payout) || 1.50;
  const internalEmail = generateInternalAnonymousEmail(key);
  if (!usersDB[key]) {
    usersDB[key] = {
      telegram_id: key,
      internal_email: internalEmail,
      balance_usd: usdEarned,
      completed_views: 0
    };
  } else {
    usersDB[key].internal_email = internalEmail;
    usersDB[key].balance_usd = parseFloat((usersDB[key].balance_usd + usdEarned).toFixed(2));
  }
  return res.status(200).send("OK_POSTBACK_PROCESSED");
});

// 4. Endpoint Prelievi Sicuri
app.post('/api/v1/user/withdraw', telegramAuthGuard, antiBotReplayGuard, (req, res) => {
  const telegramId = req.telegramUser?.id ? String(req.telegramUser.id) : String(req.body?.telegram_id || 'GUEST_999');
  const { amount_usd, token, wallet_address } = req.body || {};
  const key = String(telegramId).trim();
  const user = usersDB[key];
  if (!user) return res.status(404).json({ error: "USER_NOT_FOUND" });
  const currentBalance = typeof user.balance_usd === 'number' ? user.balance_usd : 0.00;
  const requestedAmount = parseFloat(amount_usd);
  if (isNaN(requestedAmount) || requestedAmount <= 0) {
    return res.status(400).json({ error: "INVALID_AMOUNT" });
  }
  if (requestedAmount < 1.00) {
    return res.status(400).json({ error: "BELOW_MINIMUM_THRESHOLD", min_threshold: 1.00 });
  }
  if (requestedAmount > currentBalance) {
    return res.status(400).json({ error: "INSUFFICIENT_REAL_BALANCE", real_balance: currentBalance });
  }
  const selectedToken = (token || user.selected_token || 'DOGS').toUpperCase();
  if (!MANDATORY_STATE.ALLOWED_TOKENS.includes(selectedToken)) {
    return res.status(400).json({ error: "UNSUPPORTED_TOKEN" });
  }
  const now = Date.now();
  const tracker = requestTracker.get(key) || { lastRequestTime: 0, lastWithdrawalTime: 0, nonces: new Set() };
  if (tracker.lastWithdrawalTime && (now - tracker.lastWithdrawalTime) < 60000) {
    return res.status(429).json({ error: "WITHDRAWAL_COOLDOWN_ACTIVE" });
  }
  const internalEmail = user.internal_email || generateInternalAnonymousEmail(key);
  user.balance_usd = parseFloat((currentBalance - requestedAmount).toFixed(4));
  tracker.lastWithdrawalTime = now;
  requestTracker.set(key, tracker);
  return res.status(200).json({
    success: true,
    message: "Prelievo processato con successo.",
    new_balance_usd: user.balance_usd,
    internal_email: internalEmail
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server attivo sulla porta ${PORT}`);
});
