const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) { console.error('لازم تضبط ADMIN_PASSWORD'); process.exit(1); }

const DB_FILE = path.join(__dirname, 'db.json');
let db = { users: {}, settings: { freeDailyLimit: 7, monthlyPriceEGP: 40, yearlyPriceEGP: 350 } };
if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE));
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));

const sessions = {};
const adminTokens = new Set();
const today = () => new Date().toISOString().slice(0, 10);

function hashPassword(pw, salt) {
  return crypto.scryptSync(pw, salt, 32).toString('hex');
}

function getUser(email) {
  const u = db.users[email];
  if (u && u.day !== today()) { u.day = today(); u.usedToday = 0; }
  return u;
}

function isPremium(u) {
  return u.plan === 'lifetime' || u.premiumUntil > Date.now();
}

function requireUser(req, res, next) {
  const email = sessions[req.headers['x-token']];
  if (!email || !db.users[email]) return res.status(401).json({ error: 'سجل دخول الأول' });
  req.email = email;
  next();
}

function requireAdmin(req, res, next) {
  const t = req.headers['x-admin-token'];
  if (!t || !adminTokens.has(t)) return res.status(401).json({ error: 'غير مصرح' });
  next();
}

app.post('/api/register', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!email.includes('@') || password.length < 6) {
    return res.status(400).json({ error: 'الإيميل أو كلمة السر (6 حروف على الأقل) غلط' });
  }
  if (db.users[email]) return res.status(400).json({ error: 'الحساب موجود من قبل' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.users[email] = { salt, hash: hashPassword(password, salt), plan: 'free', premiumUntil: 0, usedToday: 0, day: today() };
  save();
  const token = crypto.randomBytes(24).toString('hex');
  sessions[token] = email;
  res.json({ token });
});

app.post('/api/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = db.users[email];
  if (!u) return res.status(401).json({ error: 'بيانات غلط' });
  const given = Buffer.from(hashPassword(String(req.body.password || ''), u.salt));
  const real = Buffer.from(u.hash);
  if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) {
    return res.status(401).json({ error: 'بيانات غلط' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions[token] = email;
  res.json({ token });
});

app.get('/api/status', requireUser, (req, res) => {
  const u = getUser(req.email);
  const premium = isPremium(u);
  res.json({
    email: req.email,
    premium,
    remaining: premium ? null : Math.max(0, db.settings.freeDailyLimit - u.usedToday),
    prices: { monthly: db.settings.monthlyPriceEGP, yearly: db.settings.yearlyPriceEGP }
  });
});

app.post('/api/use', requireUser, (req, res) => {
  const u = getUser(req.email);
  if (!isPremium(u)) {
    if (u.usedToday >= db.settings.freeDailyLimit) {
      return res.status(402).json({ error: 'خلصت الصفحات المجانية النهاردة، اشترك عشان تكمل' });
    }
    u.usedToday++;
    save();
  }
  res.json({ ok: true });
});

app.post('/api/admin/login', (req, res) => {
  const given = Buffer.from(String(req.body.password || ''));
  const real = Buffer.from(ADMIN_PASSWORD);
  if (given.length !== real.length || !crypto.timingSafeEqual(given, real)) {
    return res.status(401).json({ error: 'كلمة السر غلط' });
  }
  const t = crypto.randomBytes(24).toString('hex');
  adminTokens.add(t);
  res.json({ token: t });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const list = Object.entries(db.users).map(([email, u]) => ({
    email, plan: u.plan, premium: isPremium(u), premiumUntil: u.premiumUntil, usedToday: u.usedToday
  }));
  res.json({ users: list, settings: db.settings });
});

app.post('/api/admin/grant', requireAdmin, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = db.users[email];
  if (!u) return res.status(404).json({ error: 'المستخدم مش موجود' });
  if (req.body.lifetime) u.plan = 'lifetime';
  else u.premiumUntil = Math.max(Date.now(), u.premiumUntil) + (Number(req.body.days) || 30) * 86400000;
  save();
  res.json({ ok: true });
});

app.post('/api/admin/revoke', requireAdmin, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = db.users[email];
  if (!u) return res.status(404).json({ error: 'المستخدم مش موجود' });
  u.plan = 'free';
  u.premiumUntil = 0;
  save();
  res.json({ ok: true });
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const { freeDailyLimit, monthlyPriceEGP, yearlyPriceEGP } = req.body;
  if (freeDailyLimit !== undefined) db.settings.freeDailyLimit = Number(freeDailyLimit);
  if (monthlyPriceEGP !== undefined) db.settings.monthlyPriceEGP = Number(monthlyPriceEGP);
  if (yearlyPriceEGP !== undefined) db.settings.yearlyPriceEGP = Number(yearlyPriceEGP);
  save();
  res.json({ ok: true, settings: db.settings });
});

app.listen(process.env.PORT || 3000, () => console.log('السيرفر شغال'));
