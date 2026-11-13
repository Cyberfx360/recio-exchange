require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const store = require('./storage');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true); // Render sits in front of the app; needed for https cookies and visitor addresses
// Browser safety settings for every page and file.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');                      // no other website can load AZAPLUG inside its page
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(), payment=()');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';
// Without SESSION_SECRET we derive a stable one from the database key, so people are not signed out on every restart.
const SESSION_SECRET = process.env.SESSION_SECRET ||
  (process.env.SUPABASE_SERVICE_KEY ? crypto.createHash('sha256').update('azaplug-session:' + process.env.SUPABASE_SERVICE_KEY).digest('hex') : crypto.randomBytes(32).toString('hex'));

if (!process.env.ADMIN_PASSWORD) {
  console.warn('\n⚠️  ADMIN_PASSWORD is not set in .env — using the default "changeme123". Change this before going live.\n');
}

app.use(express.json({ limit: '10mb' })); // receipts + settlement screenshots travel as base64
// Sessions are kept in the database (table "sessions"), so a restart or the server going to sleep does not
// sign anyone out. If the table is not there yet, they are kept in memory like before.
const SESSION_DAYS = 60, ADMIN_DAYS = 400;
const ADMIN_VER = crypto.createHash('sha256').update('azaplug-admin:' + ADMIN_PASSWORD).digest('hex').slice(0, 16);
class SavedSessions extends session.Store {
  constructor() { super(); this.mem = new Map(); this.saved = new Map(); }
  get(sid, cb) {
    const m = this.mem.get(sid);
    if (m) return cb(null, m);
    store.sessionGet(sid).then(d => { if (d) this.mem.set(sid, d); cb(null, d || null); }).catch(() => cb(null, null));
  }
  set(sid, sess, cb) {
    const data = JSON.parse(JSON.stringify(sess));
    this.mem.set(sid, data); this.saved.set(sid, Date.now());
    const exp = data.cookie && data.cookie.expires ? new Date(data.cookie.expires).toISOString() : new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
    store.sessionSet(sid, data, exp).catch(() => {}).then(() => cb && cb(null));
  }
  touch(sid, sess, cb) {   // called on every request: only write to the database once an hour
    if (Date.now() - (this.saved.get(sid) || 0) > 36e5) return this.set(sid, sess, cb);
    cb && cb(null);
  }
  destroy(sid, cb) { this.mem.delete(sid); this.saved.delete(sid); store.sessionDelete(sid).catch(() => {}).then(() => cb && cb(null)); }
}
app.use(session({
  secret: SESSION_SECRET,
  store: new SavedSessions(),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { maxAge: 864e5 * SESSION_DAYS, sameSite: 'lax', httpOnly: true, secure: 'auto' }
}));

// Admin sign-ins belong to the current ADMIN_PASSWORD: change it on Render and every other admin sign-in ends.
app.use((req, res, next) => {
  const s = req.session;
  if (s && s.isAdmin) {
    if (s.adminVer === undefined) s.adminVer = ADMIN_VER;            // signed in before this rule: keep them in
    else if (s.adminVer !== ADMIN_VER) { s.isAdmin = false; s.adminVer = undefined; }
  }
  next();
});

// ============================================================
// CHAT STATUS: online / last seen, typing, and seen ticks.
// Kept in memory and saved to the chat_state table every few seconds (so it survives restarts).
// Keys: 'u:<id>' / 's:<id>' / 'admin' = last seen;  'r:<chat>><side>' = read up to.
// Chats: 'c:<userId>' (customer <-> support, sides 'user' and 'support'), 't:<a>:<b>' (team, sides = 'admin' or a staff id).
// ============================================================
const CS = new Map(), CS_SAVED = new Map(), CS_DIRTY = new Set(), TYPING = new Map();
const ONLINE_MS = 12000, TYPING_MS = 6000;
let csLoaded = false, csTried = 0, csHinted = false;
const csGet = id => CS.get(id) || 0;
function csSet(id, t, saveEvery) {
  if (!(t > csGet(id))) return;
  CS.set(id, t);
  if (t - (CS_SAVED.get(id) || 0) >= (saveEvery || 0)) CS_DIRTY.add(id);
}
async function csLoad() {
  csTried = Date.now();
  try {
    (await store.listChatState()).forEach(r => { const t = Date.parse(r.at); if (t > csGet(r.id)) CS.set(r.id, t); CS_SAVED.set(r.id, t); });
    csLoaded = true;
  } catch (err) {
    if (!csHinted) { csHinted = true; console.log('Chat status is only kept in memory until the chat_state SQL from the README is run.'); }
  }
}
async function csFlush() {
  if (!csLoaded) { if (Date.now() - csTried < 300000) return; await csLoad(); if (!csLoaded) return; }
  if (!CS_DIRTY.size) return;
  const ids = [...CS_DIRTY]; CS_DIRTY.clear();
  try { await store.saveChatState(ids.map(id => ({ id, at: new Date(CS.get(id)).toISOString() }))); ids.forEach(id => CS_SAVED.set(id, CS.get(id))); }
  catch (err) { ids.forEach(id => CS_DIRTY.add(id)); csLoaded = false; }
  for (const [k, v] of TYPING) if (Date.now() - v.t > TYPING_MS) TYPING.delete(k);
}
csLoad();
setInterval(() => csFlush().catch(() => {}), 10000);
// Render stops the old server with SIGTERM when it deploys: save chat status first so nothing is lost.
for (const sig of ['SIGTERM', 'SIGINT']) process.once(sig, () => { Promise.race([csFlush().catch(() => {}), new Promise(r => setTimeout(r, 4000))]).then(() => process.exit(0)); });
// Who is calling the API right now (the same browser can be signed in as customer, staff and admin).
function whoIs(req) {
  const s = req.session || {}, p = req.path, as = String((req.query && req.query.as) || (req.body && req.body.as) || '');
  if (as === 'admin' || p.startsWith('/admin')) return s.isAdmin ? 'admin' : null;
  if (as === 'staff' || p.startsWith('/staff')) return s.staffId ? 's:' + s.staffId : null;
  if (p.startsWith('/team')) return null;
  return s.userId ? 'u:' + s.userId : null;
}
// Apps check for calls every 3 seconds while they are open on screen, so that request means "online".
app.use('/api', (req, res, next) => {
  if (req.path === '/call/incoming' || req.path.startsWith('/peer') || req.method !== 'GET') {
    const me = whoIs(req); if (me) csSet(me, Date.now(), 60000);
  }
  if (req.method === 'POST') { // sending a message ends "typing..."
    let m;
    if (req.path === '/chat/send' && req.session.userId) TYPING.delete('c:' + req.session.userId + '>user');
    else if ((m = req.path.match(/^\/(?:staff|admin)\/chats\/([^/]+)\/send$/))) TYPING.delete('c:' + m[1] + '>support');
    else if ((m = req.path.match(/^\/(staff|admin)\/team\/([^/]+)\/send$/))) { const me = m[1] === 'admin' ? 'admin' : req.session.staffId; if (me) TYPING.delete(teamChatKey(me, m[2]) + '>' + me); }
  }
  next();
});
const teamChatKey = (a, b) => 't:' + [String(a), String(b)].sort().join(':');
const STAFF_C = new Map();
async function staffCached(id) {
  const c = STAFF_C.get(id);
  if (c && Date.now() - c.at < 30000) return c.s;
  const s = await store.findStaffById(id).catch(() => null);
  STAFF_C.set(id, { s, at: Date.now() });
  return s;
}
let SUPPORT = { at: 0, ids: [] };
async function supportIds() { // admin + chat managers (all approved staff before departments are set up)
  if (Date.now() - SUPPORT.at < 60000) return SUPPORT.ids;
  const rolesOn = await roleReady(), staff = await store.listStaff().catch(() => []);
  SUPPORT = { at: Date.now(), ids: ['admin'].concat(staff.filter(s => s.status === 'approved' && (!rolesOn || s.role === 'chat')).map(s => 's:' + s.id)) };
  return SUPPORT.ids;
}
// Works out which chat the request is about. Returns { chat, me, peer, peerIds } or null.
async function peerChat(req) {
  const s = req.session || {}, q = Object.assign({}, req.query, req.body);
  const as = String(q.as || ''), kind = String(q.chat || ''), id = String(q.id || '');
  if (as === 'user' && kind === 'support') return s.userId ? { chat: 'c:' + s.userId, me: 'user', peer: 'support', peerIds: await supportIds() } : null;
  if (as === 'admin' && !s.isAdmin) return null;
  let meStaff = null;
  if (as === 'staff') { meStaff = s.staffId ? await staffCached(s.staffId) : null; if (!meStaff || meStaff.status !== 'approved') return null; }
  if (as !== 'admin' && as !== 'staff') return null;
  if (kind === 'customer' && id) {
    if (meStaff && meStaff.role && meStaff.role !== 'chat' && (await roleReady())) return null; // vendors never see customers
    return { chat: 'c:' + id, me: 'support', peer: 'user', peerIds: ['u:' + id] };
  }
  if (kind !== 'team' || !id) return null;
  if (as === 'admin') { const o = await staffCached(id); return o && o.status === 'approved' ? { chat: teamChatKey('admin', id), me: 'admin', peer: id, peerIds: ['s:' + id] } : null; }
  if (id === 'admin') return { chat: teamChatKey(meStaff.id, 'admin'), me: meStaff.id, peer: 'admin', peerIds: ['admin'] };
  const o = await staffCached(id);
  if (!o || o.status !== 'approved' || o.id === meStaff.id || !canTalk(meStaff, o)) return null;
  return { chat: teamChatKey(meStaff.id, o.id), me: meStaff.id, peer: o.id, peerIds: ['s:' + o.id] };
}
// Polled every 2 seconds while a chat is open: the other person's status, and "I have seen up to here".
app.get('/api/peer', async (req, res) => {
  try {
    const c = await peerChat(req); if (!c) return res.status(403).json({ error: 'Not allowed.' });
    const now = Date.now(), seen = Date.parse(req.query.seen || '');
    if (seen) csSet('r:' + c.chat + '>' + c.me, Math.min(seen, now), 0);
    const last = Math.max(0, ...c.peerIds.map(csGet)), ty = TYPING.get(c.chat + '>' + c.peer);
    res.json({ online: now - last < ONLINE_MS, lastSeen: last || null, typing: ty && now - ty.t < TYPING_MS ? ty.kind : null, readAt: csGet('r:' + c.chat + '>' + c.peer) || null });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load status.' }); }
});
app.post('/api/peer/typing', async (req, res) => {
  try {
    const c = await peerChat(req); if (!c) return res.status(403).json({ error: 'Not allowed.' });
    const kind = (req.body || {}).kind;
    if (kind === 'typing' || kind === 'recording') TYPING.set(c.chat + '>' + c.me, { t: Date.now(), kind }); else TYPING.delete(c.chat + '>' + c.me);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update.' }); }
});

// ============================================================
// MONEY SAFETY: one money action at a time, so a double tap or two requests at the same
// second can never pay, credit or refund twice. Each action waits for the one before it.
// ============================================================
const LOCKS = new Map();
function withLock(key, fn) {
  const prev = LOCKS.get(key) || Promise.resolve();
  const run = prev.catch(() => {}).then(fn), tail = run.catch(() => {});
  LOCKS.set(key, tail);
  tail.then(() => { if (LOCKS.get(key) === tail) LOCKS.delete(key); });
  return run;
}
// Route version: holds the lock until the response has been sent (or 30 seconds, whichever is first).
const moneyLock = keyFn => (req, res, next) => {
  const key = keyFn(req);
  withLock(key, () => new Promise(done => {
    const t = setTimeout(done, 30000);
    const end = () => { clearTimeout(t); done(); };
    res.once('finish', end); res.once('close', end);
    next();
  }));
};
const ADMIN_MONEY = moneyLock(() => 'admin-money');

// Notifications may only be sent to the real phone/browser push services.
const PUSH_HOSTS = /(^|\.)(fcm\.googleapis\.com|android\.googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)$/i;
function pushOk(url) { try { const u = new URL(String(url || '')); return u.protocol === 'https:' && PUSH_HOSTS.test(u.hostname); } catch (e) { return false; } }

// Customer chats are for chat managers only (vendors never see customers). Staff without a department yet keep access.
async function requireChatRole(req, res, next) {
  if ((await roleReady()) && req.staff && req.staff.role && req.staff.role !== 'chat') return res.status(403).json({ error: 'Only chat managers can open customer chats.' });
  next();
}

// Sign-up checks: sensible lengths, a real-looking phone number, and at most 5 new accounts per device each hour.
const PHONE_OK = p => /^\+?\d{10,15}$/.test(String(p || '').replace(/[\s-]/g, ''));
function signupProblem(req, b) {
  if (ipBlocked('signup', req)) return 'Too many new accounts from this device. Try again later.';
  if (!PHONE_OK(b.phone)) return 'Enter a valid phone number.';
  if (String(b.name || '').trim().length > 60) return 'Name is too long.';
  if (b.bankName !== undefined && String(b.bankName).trim().length > 60) return 'Bank name is too long.';
  if (b.accountNumber !== undefined && String(b.accountNumber).trim().length > 30) return 'Account number is too long.';
  return null;
}

// ============================================================
// LOGIN GUARDS: limits per device/network, so nobody can keep guessing.
// ============================================================
const visitorKey = req => String(req.ip || (req.socket && req.socket.remoteAddress) || 'unknown');
const IP_FAILS = new Map();   // visitor -> { n, until, first }
function ipBlocked(kind, req) {
  const t = IP_FAILS.get(kind + '|' + visitorKey(req));
  return t && t.until > Date.now() ? Math.ceil((t.until - Date.now()) / 60000) : 0;
}
function ipFail(kind, req, max, minutes) {
  const k = kind + '|' + visitorKey(req), now = Date.now();
  let t = IP_FAILS.get(k);
  if (!t || now - t.first > minutes * 60000) t = { n: 0, until: 0, first: now };
  t.n += 1;
  if (t.n >= max) t.until = now + minutes * 60000;
  IP_FAILS.set(k, t);
  return t.until > now;
}
setInterval(() => { const now = Date.now(); for (const [k, t] of IP_FAILS) if (t.until < now && now - t.first > 3600000) IP_FAILS.delete(k); }, 600000);
const sameText = (a, b) => crypto.timingSafeEqual(crypto.createHash('sha256').update(String(a)).digest(), crypto.createHash('sha256').update(String(b)).digest());
// ---- Google Authenticator (2-step login) for the admin. Turned on by ADMIN_TOTP_SECRET on Render.
// Lost your phone? Delete ADMIN_TOTP_SECRET on Render and admin login goes back to password only.
const ADMIN_TOTP = String(process.env.ADMIN_TOTP_SECRET || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function b32enc(buf) { let bits = 0, val = 0, out = ''; for (const b of buf) { val = ((val << 8) | b) & 0xffff; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits) out += B32[(val << (5 - bits)) & 31]; return out; }
function b32dec(str) { let bits = 0, val = 0; const out = []; for (const c of String(str || '').toUpperCase().replace(/[^A-Z2-7]/g, '')) { val = ((val << 5) | B32.indexOf(c)) & 0xffff; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return Buffer.from(out); }
function totpAt(secret, step) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(step));
  const h = crypto.createHmac('sha1', b32dec(secret)).update(msg).digest(), o = h[19] & 15;
  return String((((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1000000).padStart(6, '0');
}
// Returns the time step the code belongs to (this one, or 30 seconds either side), or 0 if wrong / already used.
function totpCheck(secret, code, usedStep) {
  code = String(code || '').replace(/\D/g, '');
  if (!secret || code.length !== 6) return 0;
  const now = Math.floor(Date.now() / 30000);
  for (const st of [now, now - 1, now + 1]) if (st > (usedStep || 0) && sameText(totpAt(secret, st), code)) return st;
  return 0;
}
let totpUsed = 0, codeWarned = 0;
let adminWrong = { n: 0, since: Date.now(), warned: 0 }, pinWrong = { n: 0, since: Date.now(), warned: 0 };
function pinWatch() { // many wrong PINs across all accounts = someone may be guessing; tell the admin
  if (Date.now() - pinWrong.since > 900000) pinWrong = { n: 0, since: Date.now(), warned: pinWrong.warned };
  pinWrong.n += 1;
  if (pinWrong.n >= 150 && Date.now() - pinWrong.warned > 3600000) {
    pinWrong.warned = Date.now();
    alertTeam({ admin: true }, 'Warning: many wrong PINs', `${pinWrong.n} wrong PIN tries in the last 15 minutes across customer and staff accounts. Someone may be guessing PINs.`, { admin: 'dash' });
  }
}

// ============================================================
// MIDDLEWARE GUARDS
// ============================================================
function requireUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Please log in first.' });
  next();
}
function requireStaff(req, res, next) {
  if (!req.session.staffId) return res.status(401).json({ error: 'Staff login required.' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) return res.status(401).json({ error: 'Admin login required.' });
  next();
}
async function requireApprovedUser(req, res, next) {
  const user = await store.findUserById(req.session.userId);
  if (!user || user.status !== 'approved') return res.status(403).json({ error: 'Your account is not approved yet.' });
  req.user = user;
  next();
}
async function requireApprovedStaff(req, res, next) {
  const staff = await store.findStaffById(req.session.staffId);
  if (!staff || staff.status !== 'approved') return res.status(403).json({ error: 'Your staff account is not approved yet.' });
  req.staff = staff;
  next();
}

// ============================================================
// CUSTOMER AUTH
// ============================================================
app.post('/api/register', async (req, res) => {
  try {
    const { name, phone, accountNumber, bankName, password } = req.body || {};
    if (!name || !phone || !accountNumber || !bankName || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }
    if (badPin(password)) return res.status(400).json({ error: badPin(password) });
    const sp = signupProblem(req, req.body); if (sp) return res.status(400).json({ error: sp });
    if (await store.findUserByPhone(String(phone).trim())) {
      return res.status(409).json({ error: 'An account with this phone number already exists.' });
    }
    const email = await signupEmail('user', req.body || {});
    if (email.error) return res.status(400).json({ error: email.error });
    const user = await store.createUser({
      name: String(name).trim(), phone: String(phone).trim(),
      accountNumber: String(accountNumber).trim(), bankName: String(bankName).trim(),
      passwordHash: bcrypt.hashSync(password, 10), email: email.value
    });
    ipFail('signup', req, 5, 60);
    req.session.userId = user.id;
    res.json({ ok: true, status: user.status });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { phone, password } = req.body || {};
    const lock = lockedOut('user', phone);
    if (lock) return res.status(429).json({ error: lock });
    const mins = ipBlocked('pin', req);
    if (mins) return res.status(429).json({ error: `Too many wrong tries from this device. Try again in ${mins} minute(s).` });
    const user = await store.findUserByPhone(String(phone || '').trim());
    if (!user || !(await bcrypt.compare(String(password || ''), user.passwordHash))) {
      pinWatch();
      if (ipFail('pin', req, 30, 15)) return res.status(429).json({ error: 'Too many wrong tries from this device. Try again in 15 minutes.' });
      return res.status(401).json({ error: wrongPin('user', phone) });
    }
    clearLock('user', phone);
    req.session.userId = user.id;
    res.json({ ok: true, status: user.status });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/logout', (req, res) => { req.session.userId = null; res.json({ ok: true }); });

app.get('/api/me', async (req, res) => {
  try {
    if (!req.session.userId) return res.json({ loggedIn: false });
    const user = await store.findUserById(req.session.userId);
    if (!user) return res.json({ loggedIn: false });
    res.json({
      loggedIn: true, name: user.name, phone: user.phone, accountNumber: user.accountNumber,
      bankName: user.bankName, status: user.status, balance: user.balance,
      email: user.email, needsPin: (await pinReady()) && user.email === null
    });
  } catch (err) {
    console.error('Me error:', err);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

app.put('/api/me', requireUser, async (req, res) => {
  try {
    const { name, bankName, accountNumber } = req.body || {};
    if (!name || !bankName || !accountNumber) return res.status(400).json({ error: 'Name, bank name and account number are required.' });
    if (String(name).trim().length > 60 || String(bankName).trim().length > 60 || String(accountNumber).trim().length > 30) return res.status(400).json({ error: 'One of the details is too long.' });
    const before = await store.findUserById(req.session.userId);
    await store.updateUser(req.session.userId, {
      name: String(name).trim(), bankName: String(bankName).trim(), accountNumber: String(accountNumber).trim()
    });
    // A changed payout account is the first thing someone does with a stolen account: warn the owner and the admin.
    if (before && (before.accountNumber !== String(accountNumber).trim() || before.bankName !== String(bankName).trim())) {
      csSet('bank:' + before.id, Date.now(), 0);
      notify(before.id, 'tx', 'Payout account changed', `Your withdrawal account is now ${String(bankName).trim()} ${String(accountNumber).trim()}. If you did not do this, contact AZAPLUG support right away.`, { go: 'chat' });
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Update me error:', err);
    res.status(500).json({ error: 'Could not update your details.' });
  }
});

// ============================================================
// STAFF AUTH
// ============================================================
app.post('/api/staff/register', async (req, res) => {
  try {
    const { name, phone, password } = req.body || {};
    if (!name || !phone || !password) return res.status(400).json({ error: 'All fields are required.' });
    if (badPin(password)) return res.status(400).json({ error: badPin(password) });
    const sp = signupProblem(req, req.body); if (sp) return res.status(400).json({ error: sp });
    ipFail('signup', req, 5, 60);
    if (await store.findStaffByPhone(String(phone).trim())) {
      return res.status(409).json({ error: 'A staff account with this phone number already exists.' });
    }
    const email = await signupEmail('staff', req.body || {});
    if (email.error) return res.status(400).json({ error: email.error });
    const staff = await store.createStaff({
      role: (await roleReady()) ? cleanRole((req.body || {}).department) : undefined,
      name: String(name).trim(), phone: String(phone).trim(), passwordHash: bcrypt.hashSync(password, 10), email: email.value
    });
    req.session.staffId = staff.id;
    alertTeam({ admin: true }, 'New staff awaiting approval', `${staff.name} signed up for the Staff portal.`, { admin: 'staff' });
    res.json({ ok: true, status: staff.status });
  } catch (err) {
    console.error('Staff register error:', err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/staff/login', async (req, res) => {
  try {
    const { phone, password } = req.body || {};
    const lock = lockedOut('staff', phone);
    if (lock) return res.status(429).json({ error: lock });
    const mins = ipBlocked('pin', req);
    if (mins) return res.status(429).json({ error: `Too many wrong tries from this device. Try again in ${mins} minute(s).` });
    const staff = await store.findStaffByPhone(String(phone || '').trim());
    if (!staff || !(await bcrypt.compare(String(password || ''), staff.passwordHash))) {
      pinWatch();
      if (ipFail('pin', req, 30, 15)) return res.status(429).json({ error: 'Too many wrong tries from this device. Try again in 15 minutes.' });
      return res.status(401).json({ error: wrongPin('staff', phone) });
    }
    clearLock('staff', phone);
    req.session.staffId = staff.id;
    // Staff who signed up before departments were saved: remember the portal they log in with.
    if (!staff.role && (await roleReady()) && ['vendor', 'chat'].includes((req.body || {}).portal)) await store.setStaffRole(staff.id, req.body.portal).catch(() => {});
    res.json({ ok: true, status: staff.status });
  } catch (err) {
    console.error('Staff login error:', err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/staff/logout', (req, res) => { req.session.staffId = null; res.json({ ok: true }); });

app.get('/api/staff/me', async (req, res) => {
  try {
    if (!req.session.staffId) return res.json({ loggedIn: false });
    const staff = await store.findStaffById(req.session.staffId);
    if (!staff) return res.json({ loggedIn: false });
    res.json({ loggedIn: true, name: staff.name, phone: staff.phone, status: staff.status, email: staff.email, role: staff.role, needsPin: (await pinReady()) && staff.email === null });
  } catch (err) {
    console.error('Staff me error:', err);
    res.status(500).json({ error: 'Something went wrong.' });
  }
});

// ============================================================
// ADMIN AUTH
// ============================================================
// 5 wrong tries from one device/network locks admin login on THAT device for 15 minutes (it never signs anyone out).
// Many wrong passwords in total sends the admin a warning notification.
// With Google Authenticator on, the password alone is not enough: the 6-digit code from the admin's phone is needed too.
app.post('/api/admin/login', (req, res) => {
  const mins = ipBlocked('admin', req);
  if (mins) return res.status(429).json({ error: `Too many wrong tries. Try again in ${mins} minute(s).` });
  const { password, code } = req.body || {};
  if (!password || !sameText(password, ADMIN_PASSWORD)) {
    const locked = ipFail('admin', req, 5, 15);
    if (Date.now() - adminWrong.since > 3600000) adminWrong = { n: 0, since: Date.now(), warned: 0 };
    adminWrong.n += 1;
    if (adminWrong.n >= 10 && Date.now() - adminWrong.warned > 3600000) {
      adminWrong.warned = Date.now();
      alertTeam({ admin: true }, 'Warning: admin password guesses', `${adminWrong.n} wrong admin password tries in the last hour. If this was not you, change ADMIN_PASSWORD on Render.`, { admin: 'dash' });
    }
    return res.status(locked ? 429 : 401).json({ error: locked ? 'Too many wrong tries. Admin login is locked here for 15 minutes.' : 'Wrong admin password.' });
  }
  if (ADMIN_TOTP) {
    if (!code) return res.status(401).json({ needCode: true, error: 'Enter the 6-digit code from Google Authenticator.' });
    // Wrong codes only happen once someone knows the password, so they are limited for everyone (10 per 15 minutes).
    const paused = ipBlocked('admin-code', { ip: 'all' });
    if (paused) return res.status(429).json({ needCode: true, error: `Too many wrong codes. Try again in ${paused} minute(s).` });
    const st = totpCheck(ADMIN_TOTP, code, totpUsed);
    if (!st) {
      const locked = ipFail('admin', req, 5, 15) | ipFail('admin-code', { ip: 'all' }, 10, 15);
      if (Date.now() - codeWarned > 600000) { codeWarned = Date.now(); alertTeam({ admin: true }, 'Admin password used with a wrong code', 'The right admin password was typed with a wrong Google Authenticator code. If this was not you, change ADMIN_PASSWORD on Render now.', { admin: 'dash' }); }
      return res.status(locked ? 429 : 401).json({ needCode: true, error: locked ? 'Too many wrong codes. Try again in 15 minutes.' : 'That code is not right. Type the newest code from Google Authenticator.' });
    }
    totpUsed = st; // each code works only once
  }
  const wasAdmin = !!req.session.isAdmin;
  req.session.isAdmin = true; req.session.adminVer = ADMIN_VER;
  // The admin stays signed in on this device: 400 days (the longest a browser keeps a sign-in), renewed every time
  // the app is used, so the password and Google Authenticator code are only needed on a new device or after "Log out".
  req.session.cookie.maxAge = ADMIN_DAYS * 864e5;
  if (!wasAdmin) alertTeam({ admin: true }, 'New admin sign-in', `Someone signed in to the admin app (${String(req.get('user-agent') || 'unknown device').slice(0, 80)}). If this was not you, change ADMIN_PASSWORD on Render now.`, { admin: 'dash' });
  res.json({ ok: true });
});
// Setting up Google Authenticator from the admin app (Admin Panel -> Two-Step Login).
app.get('/api/admin/2fa', requireAdmin, (req, res) => {
  if (ADMIN_TOTP) return res.json({ on: true });
  if (!req.session.totpSetup) req.session.totpSetup = b32enc(crypto.randomBytes(20));
  const secret = req.session.totpSetup;
  res.json({ on: false, secret, uri: `otpauth://totp/AZAPLUG:Admin?secret=${secret}&issuer=AZAPLUG&algorithm=SHA1&digits=6&period=30` });
});
app.post('/api/admin/2fa/check', requireAdmin, (req, res) => {
  const secret = ADMIN_TOTP || req.session.totpSetup;
  if (!secret) return res.status(400).json({ error: 'Open this page again to get a new setup key.' });
  if (!totpCheck(secret, (req.body || {}).code, 0)) return res.status(400).json({ error: 'That code is not right. Make sure the time on your phone is set automatically, then type the newest code.' });
  res.json({ ok: true, on: !!ADMIN_TOTP, secret: ADMIN_TOTP ? undefined : secret });
});
app.post('/api/admin/logout', (req, res) => { req.session.isAdmin = false; req.session.adminVer = undefined; res.json({ ok: true }); });

// ============================================================
// LOGIN EXTRAS: 6-digit PIN, email codes, forgot PIN, fingerprint
// ============================================================
// --- PIN rules
function badPin(pin) {
  const p = String(pin || '');
  if (!/^\d{6}$/.test(p)) return 'Your PIN must be exactly 6 digits.';
  if (/^(\d)\1{5}$/.test(p) || '0123456789012345'.includes(p) || '9876543210987654'.includes(p) || /^(\d\d)\1\1$/.test(p) || /^(\d{3})\1$/.test(p) ||
      ['112233', '123321', '147258', '159753', '102030', '010203', '111222', '000111', '121314', '696969', '252525', '789456', '456123'].includes(p)) return 'That PIN is too easy to guess. Choose another one.';
  return null;
}
// --- Wrong-PIN lockout: a 6-digit PIN is short, so 5 wrong tries locks that phone number for 15 minutes.
const tries = new Map();
const lockKey = (kind, phone) => kind + ':' + String(phone || '').trim();
function lockedOut(kind, phone) {
  const t = tries.get(lockKey(kind, phone));
  if (t && t.until > Date.now()) return `Too many wrong tries. Try again in ${Math.ceil((t.until - Date.now()) / 60000)} minute(s), or tap "Forgot PIN".`;
  return null;
}
function wrongPin(kind, phone) {
  const k = lockKey(kind, phone), t = tries.get(k) || { n: 0, until: 0 };
  if (t.until && t.until <= Date.now()) { t.n = 0; t.until = 0; }
  t.n += 1;
  if (t.n >= 5) { t.until = Date.now() + 15 * 60000; t.n = 0; }
  tries.set(k, t);
  return t.until ? 'Too many wrong tries. This number is locked for 15 minutes.' : 'Incorrect phone number or PIN.';
}
function clearLock(kind, phone) { tries.delete(lockKey(kind, phone)); }

// --- Is the database ready for PIN + email? (true once the SQL in the README was run)
let pinOk = false, pinChecked = 0;
async function pinReady() {
  if (pinOk || Date.now() - pinChecked < 60000) return pinOk;
  pinChecked = Date.now();
  try { pinOk = await store.hasEmailColumns(); } catch (err) { pinOk = false; }
  return pinOk;
}

// --- Email (Brevo). Needs BREVO_API_KEY and MAIL_FROM (a sender address verified in Brevo).
const MAIL_ON = !!(process.env.BREVO_API_KEY && process.env.MAIL_FROM);
// Email codes at sign-up are switched off for now, so nobody is blocked from joining when an email fails to arrive.
// People still give their email (used for Forgot PIN). Set VERIFY_EMAIL=1 on Render to switch the code step back on.
const VERIFY_ON = MAIL_ON && process.env.VERIFY_EMAIL === '1';
function sendMail(to, subject, html) {
  return new Promise((resolve, reject) => {
    const url = new URL(process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email');
    const body = JSON.stringify({ sender: { name: 'AZAPLUG', email: process.env.MAIL_FROM }, to: [{ email: to }], subject, htmlContent: html });
    const r = require(url.protocol === 'http:' ? 'http' : 'https').request(url, {
      method: 'POST', timeout: 15000,
      headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json', 'content-length': Buffer.byteLength(body) }
    }, resp => {
      let out = ''; resp.on('data', c => { out += c; });
      resp.on('end', () => (resp.statusCode < 300 ? resolve() : reject(new Error('Email service said ' + resp.statusCode + ': ' + out.slice(0, 200)))));
    });
    r.on('timeout', () => r.destroy(new Error('Email service timed out')));
    r.on('error', reject); r.end(body);
  });
}
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e) && e.length <= 120;
const maskEmail = e => e.replace(/^(.{2})[^@]*(@.*)$/, '$1•••$2');
// --- One-time codes (kept in memory for 10 minutes)
const codes = new Map();
const hashCode = c => crypto.createHash('sha256').update(String(c)).digest('hex');
const CODE_SENDS = new Map(); // key -> { n, first }
async function issueCode(key, email, extra) {
  const old = codes.get(key);
  if (old && old.email === email && Date.now() - old.sentAt < 45000) return false;   // one was just sent: keep using it
  let c = CODE_SENDS.get(key); if (!c || Date.now() - c.first > 3600000) c = { n: 0, first: Date.now() };
  if (c.n >= 5) { const e = new Error('Too many codes asked for. Try again in an hour.'); e.status = 429; throw e; }
  c.n += 1; CODE_SENDS.set(key, c);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  codes.set(key, { hash: hashCode(code), exp: Date.now() + 10 * 60000, n: 0, sentAt: Date.now(), email, ...(extra || {}) });
  try {
    await sendMail(email, `${code} is your AZAPLUG code`,
      `<div style="font-family:Arial,sans-serif;max-width:420px;margin:auto;padding:24px"><h2 style="color:#0D4DC7;margin:0 0 12px">AZAPLUG</h2><p style="font-size:15px;color:#111827">Your verification code is</p><p style="font-size:34px;font-weight:700;letter-spacing:8px;color:#111827;margin:8px 0 16px">${code}</p><p style="font-size:13px;color:#6B7280">It works for 10 minutes. If you did not ask for this, ignore this email and do not share the code with anyone.</p></div>`);
  } catch (err) { codes.delete(key); console.error('Email error:', err.message); throw Object.assign(new Error('We could not send the email. Check the address and try again.'), { status: 502 }); }
  return true;
}
function checkCode(key, code, email) {
  const c = codes.get(key);
  if (!c || c.exp < Date.now()) { codes.delete(key); return 'That code has expired. Ask for a new one.'; }
  if (email && c.email !== email) return 'That code was sent to a different email.';
  c.n += 1;
  if (c.n > 5) { codes.delete(key); return 'Too many wrong tries. Ask for a new code.'; }
  if (c.hash !== hashCode(String(code || '').trim())) return 'That code is not correct.';
  codes.delete(key);
  return null;
}
const kindOf = b => ((b || {}).role === 'staff' ? 'staff' : 'user');
const findByPhone = (kind, phone) => (kind === 'staff' ? store.findStaffByPhone(phone) : store.findUserByPhone(phone));
const fail = (res, err, fallback) => { if (!err.status) console.error(err); res.status(err.status || 500).json({ error: err.status ? err.message : fallback }); };

// What the apps should show: PIN + email fields only once the database is ready; the code step only if email is set up.
app.get('/api/auth/config', async (req, res) => { const pin = await pinReady(); res.json({ pin, email: pin && VERIFY_ON }); });

// Checks the email part of a sign-up. Returns { value } (the email to save, or undefined) or { error }.
async function signupEmail(kind, b) {
  if (!(await pinReady())) return {};
  const email = String(b.email || '').trim().toLowerCase();
  if (!email) return { value: '' };   // email is optional for now; it can be added later
  if (!validEmail(email)) return { error: 'That email does not look right. Check it, or leave it empty.' };
  if (await store.findByEmail(kind, email)) return { error: 'That email is already used by another account.' };
  if (VERIFY_ON) { const bad = checkCode(`signup:${kind}:${email}`, b.code, email); if (bad) return { error: bad }; }
  return { value: email };
}
// Step 1 of sign-up: email a code.
app.post('/api/auth/signup-code', async (req, res) => {
  try {
    if (ipBlocked('mail', req)) return res.status(429).json({ error: 'Too many codes asked for from this device. Try again later.' });
    ipFail('mail', req, 15, 60);
    const b0 = req.body || {}, kind = kindOf(b0), email = String(b0.email || '').trim().toLowerCase(), phone = String(b0.phone || '').trim();
    if (!(await pinReady()) || !VERIFY_ON) return res.json({ ok: true, skip: true });   // no code step: the sign-up itself checks everything
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (phone && await findByPhone(kind, phone)) return res.status(409).json({ error: 'An account with this phone number already exists.' });
    if (await store.findByEmail(kind, email)) return res.status(409).json({ error: 'That email is already used by another account.' });
    if (!VERIFY_ON) return res.json({ ok: true, skip: true });
    if (b0.password !== undefined && badPin(b0.password)) return res.status(400).json({ error: badPin(b0.password) });
    const sent = await issueCode(`signup:${kind}:${email}`, email);
    res.json({ ok: true, email: maskEmail(email), wait: !sent });
  } catch (err) { fail(res, err, 'Could not send the code.'); }
});
// People who signed up before PINs: after logging in with the old password they add an email and choose a PIN.
const sessionId = (req, kind) => (kind === 'staff' ? req.session.staffId : req.session.userId);
app.post('/api/auth/setup-code', async (req, res) => {
  try {
    if (ipBlocked('mail', req)) return res.status(429).json({ error: 'Too many codes asked for from this device. Try again later.' });
    ipFail('mail', req, 15, 60);
    const kind = kindOf(req.body), id = sessionId(req, kind), email = String((req.body || {}).email || '').trim().toLowerCase();
    if (!id) return res.status(401).json({ error: 'Please log in first.' });
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    const taken = await store.findByEmail(kind, email);
    if (taken && taken.id !== id) return res.status(409).json({ error: 'That email is already used by another account.' });
    if (!VERIFY_ON) return res.json({ ok: true, skip: true });
    const sent = await issueCode(`setup:${kind}:${id}`, email);
    res.json({ ok: true, email: maskEmail(email), wait: !sent });
  } catch (err) { fail(res, err, 'Could not send the code.'); }
});
app.post('/api/auth/setup', async (req, res) => {
  try {
    const kind = kindOf(req.body), id = sessionId(req, kind), b = req.body || {}, email = String(b.email || '').trim().toLowerCase();
    if (!id) return res.status(401).json({ error: 'Please log in first.' });
    if (!(await pinReady())) return res.status(400).json({ error: 'PIN login is not switched on yet.' });
    if (email && !validEmail(email)) return res.status(400).json({ error: 'That email does not look right. Check it, or leave it empty.' });
    if (badPin(b.pin)) return res.status(400).json({ error: badPin(b.pin) });
    const taken = email ? await store.findByEmail(kind, email) : null;
    if (taken && taken.id !== id) return res.status(409).json({ error: 'That email is already used by another account.' });
    if (VERIFY_ON) { const bad = checkCode(`setup:${kind}:${id}`, b.code, email); if (bad) return res.status(400).json({ error: bad }); }
    await store.setLogin(kind, id, { email, passwordHash: bcrypt.hashSync(String(b.pin), 10) });
    res.json({ ok: true });
  } catch (err) { fail(res, err, 'Could not save your PIN.'); }
});
// Forgot PIN: a code goes to the email on the account, then a new PIN is chosen.
app.post('/api/auth/forgot', async (req, res) => {
  try {
    if (ipBlocked('mail', req)) return res.status(429).json({ error: 'Too many codes asked for from this device. Try again later.' });
    ipFail('mail', req, 15, 60);
    const kind = kindOf(req.body), phone = String((req.body || {}).phone || '').trim();
    const acct = phone ? await findByPhone(kind, phone) : null;
    if (!acct) return res.status(404).json({ error: 'No account uses that phone number.' });
    if (!acct.email) return res.status(400).json({ error: 'This account has no email yet. Log in with your old password, or contact AZAPLUG support.' });
    if (!MAIL_ON) return res.status(400).json({ error: 'Email is not set up yet. Contact AZAPLUG support to reset your PIN.' });
    const sent = await issueCode(`reset:${kind}:${acct.id}`, acct.email);
    res.json({ ok: true, email: maskEmail(acct.email), wait: !sent });
  } catch (err) { fail(res, err, 'Could not send the code.'); }
});
app.post('/api/auth/reset', async (req, res) => {
  try {
    const kind = kindOf(req.body), b = req.body || {}, phone = String(b.phone || '').trim();
    const acct = phone ? await findByPhone(kind, phone) : null;
    if (!acct) return res.status(404).json({ error: 'No account uses that phone number.' });
    if (badPin(b.pin)) return res.status(400).json({ error: badPin(b.pin) });
    const bad = checkCode(`reset:${kind}:${acct.id}`, b.code);
    if (bad) return res.status(400).json({ error: bad });
    await store.setLogin(kind, acct.id, { passwordHash: bcrypt.hashSync(String(b.pin), 10) });
    clearLock(kind, phone);
    if (kind === 'staff') req.session.staffId = acct.id; else req.session.userId = acct.id;
    res.json({ ok: true, status: acct.status });
  } catch (err) { fail(res, err, 'Could not reset your PIN.'); }
});

// --- Fingerprint / Face ID login (passkeys kept on the phone; the server only stores the public key)
const webauthn = require('@simplewebauthn/server');
const b64u = buf => Buffer.from(buf).toString('base64url');
const rpOf = req => { const host = req.get('host') || 'localhost'; return { rpID: host.replace(/:\d+$/, ''), origins: ['https://' + host, 'http://' + host] }; };
const passKind = b => (['user', 'staff', 'admin'].includes((b || {}).kind) ? b.kind : 'user');
const ADMIN_PK = 'admin:' + ADMIN_VER; // admin fingerprints stop working when ADMIN_PASSWORD changes
const passOwner = (req, kind) => (kind === 'admin' ? (req.session.isAdmin ? ADMIN_PK : null) : kind === 'staff' ? req.session.staffId : req.session.userId) || null;
app.post('/api/passkey/register/options', async (req, res) => {
  try {
    const kind = passKind(req.body), owner = passOwner(req, kind);
    if (!owner) return res.status(401).json({ error: 'Please log in first.' });
    const acct = kind === 'admin' ? { phone: 'Admin', name: 'AZAPLUG Admin' } : kind === 'staff' ? await store.findStaffById(owner) : await store.findUserById(owner);
    if (!acct) return res.status(401).json({ error: 'Please log in first.' });
    const options = await webauthn.generateRegistrationOptions({
      rpName: 'AZAPLUG', rpID: rpOf(req).rpID, userName: `${acct.phone} (${kind})`, userDisplayName: acct.name, userID: Buffer.from(kind + ':' + owner),
      attestationType: 'none', authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' }
    });
    req.session.wa = { c: options.challenge, kind, owner };
    res.json(options);
  } catch (err) { console.error('Passkey options error:', err); res.status(500).json({ error: 'Fingerprint login is not available right now.' }); }
});
app.post('/api/passkey/register/verify', async (req, res) => {
  try {
    const kind = passKind(req.body), owner = passOwner(req, kind), wa = req.session.wa; req.session.wa = null;
    if (!owner || !wa || wa.kind !== kind || wa.owner !== owner) return res.status(400).json({ error: 'Start again.' });
    const rp = rpOf(req);
    const v = await webauthn.verifyRegistrationResponse({ response: req.body.response, expectedChallenge: wa.c, expectedOrigin: rp.origins, expectedRPID: rp.rpID, requireUserVerification: true });
    if (!v.verified) return res.status(400).json({ error: 'Your phone did not confirm it. Try again.' });
    const c = v.registrationInfo.credential;
    await store.savePasskey({ id: c.id, kind, ownerId: owner, publicKey: b64u(c.publicKey), counter: c.counter });
    res.json({ ok: true, id: c.id });
  } catch (err) { console.error('Passkey register error:', err); res.status(/passkeys/.test(String(err && err.message)) ? 500 : 400).json({ error: 'Could not turn on fingerprint login on this phone.' }); }
});
app.post('/api/passkey/login/options', async (req, res) => {
  try {
    const pk = await store.findPasskey(String((req.body || {}).id || ''));
    if (!pk || pk.kind !== passKind(req.body) || (pk.kind === 'admin' && pk.ownerId !== ADMIN_PK)) return res.status(404).json({ error: 'Fingerprint login is no longer set up on this phone.', gone: true });
    const options = await webauthn.generateAuthenticationOptions({ rpID: rpOf(req).rpID, allowCredentials: [{ id: pk.id }], userVerification: 'required' });
    req.session.wa = { c: options.challenge, kind: pk.kind };
    res.json(options);
  } catch (err) { console.error('Passkey login options error:', err); res.status(500).json({ error: 'Fingerprint login is not available right now.' }); }
});
app.post('/api/passkey/login/verify', async (req, res) => {
  try {
    const wa = req.session.wa; req.session.wa = null;
    const pk = await store.findPasskey(String(((req.body || {}).response || {}).id || ''));
    if (!wa || !pk || pk.kind !== wa.kind || (pk.kind === 'admin' && pk.ownerId !== ADMIN_PK)) return res.status(400).json({ error: 'Start again.' });
    const rp = rpOf(req);
    const v = await webauthn.verifyAuthenticationResponse({
      response: req.body.response, expectedChallenge: wa.c, expectedOrigin: rp.origins, expectedRPID: rp.rpID, requireUserVerification: true,
      credential: { id: pk.id, publicKey: new Uint8Array(Buffer.from(pk.publicKey, 'base64url')), counter: pk.counter }
    });
    if (!v.verified) return res.status(401).json({ error: 'Your phone did not confirm it. Use your PIN.' });
    store.updatePasskeyCounter(pk.id, v.authenticationInfo.newCounter).catch(() => {});
    if (pk.kind === 'admin') { req.session.isAdmin = true; req.session.adminVer = ADMIN_VER; req.session.cookie.maxAge = ADMIN_DAYS * 864e5; return res.json({ ok: true }); }
    const acct = pk.kind === 'staff' ? await store.findStaffById(pk.ownerId) : await store.findUserById(pk.ownerId);
    if (!acct) { store.deletePasskey(pk.id).catch(() => {}); return res.status(404).json({ error: 'That account no longer exists.', gone: true }); }
    if (pk.kind === 'staff') req.session.staffId = acct.id; else req.session.userId = acct.id;
    res.json({ ok: true, status: acct.status });
  } catch (err) { console.error('Passkey login error:', err); res.status(401).json({ error: 'Fingerprint login did not work. Use your PIN.' }); }
});

// ============================================================
// PUBLIC: rate board + rules
// ============================================================
app.get('/api/rates', async (req, res) => {
  try {
    const accounts = await store.listAccountsPublic();
    const seenTitles = new Set();
    const deduped = [];
    for (const a of accounts) {
      if (seenTitles.has(a.title)) continue;
      seenTitles.add(a.title);
      deduped.push(a);
    }
    res.json({
      rates: deduped.map(a => ({
        id: a.id, title: a.title,
        lowestAmount: a.lowestAmount, lowestRate: a.lowestRate,
        higherAmount: a.higherAmount, higherRate: a.higherRate
      }))
    });
  } catch (err) {
    console.error('Rates error:', err);
    res.status(500).json({ error: 'Could not load rates.' });
  }
});

// Naira price of 1 BTC and 1 USDT, set by the admin. 0 means not set yet.
app.get('/api/crypto-rates', async (req, res) => {
  try { const st = await store.getSettings(); res.json({ btc: st.btcRate || 0, usdt: st.usdtRate || 0 }); }
  catch (err) { console.error('Crypto rates error:', err); res.status(500).json({ error: 'Could not load rates.' }); }
});

app.get('/api/rules', async (req, res) => {
  try {
    const settings = await store.getSettings();
    res.json({ rulesText: settings.rulesText });
  } catch (err) {
    console.error('Rules error:', err);
    res.status(500).json({ error: 'Could not load rules.' });
  }
});

// ============================================================
// CUSTOMER: browse accounts (searchable by country/title)
// ============================================================
app.get('/api/accounts', requireUser, requireApprovedUser, async (req, res) => {
  try {
    const accounts = await store.listAccountsPublic();
    res.json({
      accounts: accounts.map(a => ({
        id: a.id, title: a.title, accountNumber: a.accountNumber, bankName: a.bankName, imageData: a.imageData,
        minAmount: a.minAmount, maxAmount: a.maxAmount,
        lowestAmount: a.lowestAmount, lowestRate: a.lowestRate,
        higherAmount: a.higherAmount, higherRate: a.higherRate
      }))
    });
  } catch (err) {
    console.error('Accounts error:', err);
    res.status(500).json({ error: 'Could not load accounts.' });
  }
});

// ============================================================
// CUSTOMER: trades
// ============================================================
app.post('/api/trades', requireUser, requireApprovedUser, async (req, res) => {
  try {
    const { accountId, intendedAmount, receiptImage } = req.body || {};
    if (!accountId || !intendedAmount || !receiptImage) {
      return res.status(400).json({ error: 'Account, amount and receipt are all required.' });
    }
    if (!(Number(intendedAmount) > 0) || !isFinite(Number(intendedAmount))) return res.status(400).json({ error: 'Enter the amount you sent.' });
    if (badAttachment(receiptImage) || !/^data:image\//i.test(receiptImage)) return res.status(400).json({ error: 'Add a photo of your receipt (JPG or PNG).' });
    const settings = await store.getSettings();
    if (Number(intendedAmount) > settings.maxDeposit) {
      return res.status(400).json({ error: 'This amount is above what we can process directly through the site — please chat with us instead.' });
    }
    const account = await store.findAccountById(accountId);
    if (!account || !account.active) return res.status(404).json({ error: 'That account is no longer available.' });

    const trade = await store.createTrade({
      userId: req.user.id, accountId: account.id, staffId: account.staffId,
      intendedAmount: Number(intendedAmount), receiptImage,
      accountNumberUsed: account.accountNumber, accountTitleUsed: account.title,
      userPayoutAccount: req.user.accountNumber, userPayoutBank: req.user.bankName
    });
    alertTeam({ admin: true, staffId: account.staffId }, 'New receipt', `${req.user.name} sent a ${account.title} receipt for ${plain(intendedAmount)}.`, { admin: 'receipts', staff: 'receipts' });
    res.json({ ok: true, trade });
  } catch (err) {
    console.error('Create trade error:', err);
    res.status(500).json({ error: 'Could not submit your receipt.' });
  }
});

// Crypto receipts go to the admin only: no account and no staff are attached.
const COINS = { BTC: 'Bitcoin (BTC)', USDT: 'USDT' };
app.post('/api/crypto/trades', requireUser, requireApprovedUser, async (req, res) => {
  try {
    const { coin, usdAmount, receiptImage, address } = req.body || {};
    const usd = Number(usdAmount);
    if (!COINS[coin]) return res.status(400).json({ error: 'Choose Bitcoin or USDT.' });
    if (!Number.isFinite(usd) || usd <= 0) return res.status(400).json({ error: 'Enter the amount you sent in dollars.' });
    if (typeof receiptImage !== 'string' || !/^data:image\//i.test(receiptImage) || badAttachment(receiptImage)) return res.status(400).json({ error: 'Add a screenshot of your transfer (JPG or PNG).' });
    const trade = await store.createTrade({
      userId: req.user.id, accountId: null, staffId: null, intendedAmount: usd, receiptImage,
      accountNumberUsed: String(address || '').slice(0, 120), accountTitleUsed: COINS[coin],
      userPayoutAccount: req.user.accountNumber, userPayoutBank: req.user.bankName
    });
    alertTeam({ admin: true }, 'New crypto receipt', `${req.user.name} sent a ${COINS[coin]} receipt for $${plain(usd)}.`, { admin: 'receipts' });
    res.json({ ok: true, trade });
  } catch (err) { console.error('Crypto trade error:', err); res.status(500).json({ error: 'Could not submit your receipt.' }); }
});

app.get('/api/trades', requireUser, requireApprovedUser, async (req, res) => {
  try {
    res.json({ trades: await store.listTradesForUser(req.user.id) });
  } catch (err) {
    console.error('List trades error:', err);
    res.status(500).json({ error: 'Could not load trades.' });
  }
});

// ============================================================
// CUSTOMER: withdrawals
// ============================================================
app.post('/api/withdrawals', requireUser, requireApprovedUser, moneyLock(req => 'user:' + req.session.userId), async (req, res) => {
  try {
    const amount = Math.round(Number((req.body || {}).amount) * 100) / 100;
    if (!amount || !isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Enter a valid amount.' });
    const user = await store.findUserById(req.user.id);
    // Hold the funds first; this refuses if the balance is not enough (even with many requests at once).
    const held = await store.addToBalance(user.id, -amount, { noNegative: true });
    if (!held.ok) return res.status(400).json({ error: 'You cannot withdraw more than your balance.' });
    let withdrawal;
    try {
      withdrawal = await store.createWithdrawal({ userId: user.id, amount, payoutAccount: user.accountNumber, payoutBank: user.bankName });
    } catch (err) { await store.addToBalance(user.id, amount).catch(() => {}); throw err; } // give the money back if saving failed
    alertTeam({ admin: true }, 'Withdrawal request', `${user.name} asked to withdraw ₦${plain(amount)} to ${user.bankName}.`, { admin: 'wds' });
    res.json({ ok: true, withdrawal });
  } catch (err) {
    console.error('Create withdrawal error:', err);
    res.status(500).json({ error: 'Could not submit withdrawal request.' });
  }
});

app.get('/api/withdrawals', requireUser, requireApprovedUser, async (req, res) => {
  try { res.json({ withdrawals: await store.listWithdrawalsForUser(req.user.id) }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load withdrawals.' }); }
});

// ============================================================
// CUSTOMER: chat
// ============================================================
// A chat attachment is a photo or a voice note, sent as a data: URL. Returns an error message, or null if fine.
function badAttachment(data) {
  if (data === undefined || data === null || data === '') return null;
  if (typeof data !== 'string' || !/^data:(image\/(jpeg|jpg|png|webp|gif)|audio\/[a-z0-9.+-]+)[;,]/i.test(data)) return 'Only photos (JPG, PNG, WebP) and voice notes can be sent.';
  if (/^data:audio\//i.test(data) && data.length > 2500000) return 'That voice note is too long. Keep it under 2 minutes.';
  return null;
}
const isVoice = d => typeof d === 'string' && (/^data:audio\//i.test(d) || /^\/api\/media\/[^?]+\?a=1/.test(d));
const isImage = d => typeof d === 'string' && (/^data:image\//i.test(d) || /^\/api\/media\/[^?]+\.(jpg|png|webp|gif)$/.test(d));

// ---- Photos and voice notes stored in Supabase Storage
// pub/ = account pictures (anyone), u/<customerId>/ = that customer + staff + admin, staff/ and team/ = staff + admin.
const mediaCache = new Map(); let mediaCacheSize = 0;
function cacheMedia(path, file) {
  if (file.body.length > 3 * 1024 * 1024) return;
  mediaCache.set(path, file); mediaCacheSize += file.body.length;
  while (mediaCacheSize > 40 * 1024 * 1024) { const [k, v] = mediaCache.entries().next().value; mediaCache.delete(k); mediaCacheSize -= v.body.length; }
}
app.get('/api/media/:scope/:owner/:file', async (req, res) => {
  try {
    const { scope, owner, file } = req.params, path = `${scope}/${owner}/${file}`;
    let ok = scope === 'pub' || !!req.session.isAdmin;
    if (!ok && req.session.staffId) { const st = await store.findStaffById(req.session.staffId); ok = !!st && st.status === 'approved'; }
    if (!ok && scope === 'u' && req.session.userId && req.session.userId === owner) ok = true;
    if (!ok) return res.status(403).end();
    let f = mediaCache.get(path);
    if (!f) { f = await store.getMediaFile(path); if (!f) return res.status(404).end(); cacheMedia(path, f); }
    res.setHeader('Content-Type', f.type);
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox"); // a file can only ever be shown, never run
    res.setHeader('Cache-Control', scope === 'pub' ? 'public, max-age=31536000, immutable' : 'private, max-age=31536000, immutable');
    res.setHeader('Accept-Ranges', 'bytes');
    const total = f.body.length, m = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range || '');
    if (m) {   // iPhone needs byte ranges to play audio
      let start = m[1] === '' ? Math.max(0, total - Number(m[2])) : Number(m[1]), end = m[1] !== '' && m[2] !== '' ? Number(m[2]) : total - 1;
      end = Math.min(end, total - 1);
      if (start > end || start >= total) { res.setHeader('Content-Range', `bytes */${total}`); return res.status(416).end(); }
      res.status(206).setHeader('Content-Range', `bytes ${start}-${end}/${total}`);
      res.setHeader('Content-Length', end - start + 1); return res.end(f.body.subarray(start, end + 1));
    }
    res.setHeader('Content-Length', total); res.end(f.body);
  } catch (err) { console.error('Media error:', err.message || err); res.status(500).end(); }
});
// How many pictures are still inside the database (they move to Storage on their own).
app.get('/api/admin/media-status', requireAdmin, async (req, res) => {
  try { res.json({ storage: await store.mediaReady(), stillInDatabase: await store.mediaLeftInDatabase(), keepChatMediaDays: MEDIA_DAYS }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not check storage.' }); }
});

app.get('/api/chat/messages', requireUser, async (req, res) => {
  try { res.json({ messages: await store.messagesForUser(req.session.userId) }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load messages.' }); }
});
app.post('/api/chat/send', requireUser, async (req, res) => {
  try {
    const { text, imageData } = req.body || {};
    if (!text && !imageData) return res.status(400).json({ error: 'Message is empty.' });
    if (badAttachment(imageData)) return res.status(400).json({ error: badAttachment(imageData) });
    const msg = await store.addMessage({ userId: req.session.userId, sender: 'user', text, imageData });
    const reply = text ? await giveawayEntry(req.session.userId, text, req.body || {}).catch(err => { console.error('Giveaway entry error:', err.message || err); return null; }) : null;
    if (reply) return res.json({ ok: true, message: msg, reply });
    store.findUserById(req.session.userId).then(u => alertTeam({ admin: true, chat: true }, `New message from ${u ? u.name : 'a customer'}`, text ? String(text).slice(0, 140) : isVoice(imageData) ? 'Sent a voice note' : 'Sent a photo', { admin: 'chats', staff: 'chats' })).catch(() => {});
    res.json({ ok: true, message: msg });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not send message.' }); }
});

// ============================================================
// STAFF: own accounts
// ============================================================
app.delete('/api/chat/messages/:id', requireUser, async (req, res) => {
  try {
    const m = await store.findMessageById(req.params.id);
    if (!m || m.userId !== req.session.userId || m.sender !== 'user') return res.status(404).json({ error: 'You can only delete your own messages.' });
    await store.deleteMessage(m.id); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete the message.' }); }
});

app.get('/api/staff/accounts', requireStaff, requireApprovedStaff, async (req, res) => {
  try { res.json({ accounts: await store.listAccountsByStaff(req.staff.id) }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load accounts.' }); }
});

app.post('/api/staff/accounts', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.title || !b.accountNumber || !b.bankName) return res.status(400).json({ error: 'Title, account number and bank are required.' });
    if (b.imageData && badAttachment(b.imageData)) return res.status(400).json({ error: badAttachment(b.imageData) });
    // The whole rate tier (amounts + rates) is admin-only — new accounts start at 0 until an admin sets it.
    // New accounts also start unverified (inactive) — an admin must verify before customers can see them.
    const account = await store.createAccount({
      staffId: req.staff.id, title: b.title, accountNumber: b.accountNumber, bankName: b.bankName,
      imageData: b.imageData || null,
      lowestAmount: 0, lowestRate: 0, higherAmount: 0, higherRate: 0,
      minAmount: Number(b.minAmount) || 0, maxAmount: Number(b.maxAmount) || 0,
      active: false
    });
    alertTeam({ admin: true }, 'Account awaiting verification', `${req.staff.name} added a ${account.title} (${account.bankName}) account.`, { admin: 'accountsAll' });
    res.json({ ok: true, account });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not create account.' }); }
});

app.put('/api/staff/accounts/:id', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const account = await store.findAccountById(req.params.id);
    if (!account || account.staffId !== req.staff.id) return res.status(403).json({ error: 'You can only edit accounts you provided.' });
    // Rate tier fields are admin-only — strip them out even if a staff client tries to send them.
    const b = { ...(req.body || {}) };
    delete b.lowestAmount; delete b.lowestRate; delete b.higherAmount; delete b.higherRate;
    // Verification and ownership are admin-only too — staff cannot verify their own account or reassign it.
    delete b.active; delete b.staffId;
    if (b.imageData && badAttachment(b.imageData)) return res.status(400).json({ error: badAttachment(b.imageData) });
    // Changing where customers send money takes the account off until the admin checks it again.
    const changed = ['accountNumber', 'bankName', 'title'].some(k => b[k] !== undefined && String(b[k]).trim() !== String(account[k] || '').trim());
    if (changed && account.active) b.active = false;
    await store.updateAccount(req.params.id, b);
    if (changed && account.active) alertTeam({ admin: true }, 'Account needs verifying again', `${req.staff.name} changed the details of ${account.title} (${account.bankName}). It is hidden from customers until you verify it.`, { admin: 'accounts' });
    res.json({ ok: true, needsVerify: changed && account.active });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update account.' }); }
});

app.delete('/api/staff/accounts/:id', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const account = await store.findAccountById(req.params.id);
    if (!account || account.staffId !== req.staff.id) return res.status(403).json({ error: 'You can only delete accounts you provided.' });
    await store.deleteAccount(req.params.id);
    notifyAccountGone(account);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete account.' }); }
});

// ============================================================
// STAFF: trades on accounts they provided
// ============================================================
app.get('/api/staff/trades', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const trades = await store.listTradesForStaff(req.staff.id);
    const accounts = await store.listAccountsByStaff(req.staff.id);
    const enriched = trades.map(t => {
      const acc = accounts.find(a => a.id === t.accountId);
      return {
        ...t,
        // A receipt a chat manager passed on from a chat hides the customer from the account's staff.
        ...(t.chatMessageId ? { userId: null, userPayoutAccount: null, userPayoutBank: null, fromChat: true } : {}),
        lowestAmount: acc ? acc.lowestAmount : null, lowestRate: acc ? acc.lowestRate : null,
        higherAmount: acc ? acc.higherAmount : null, higherRate: acc ? acc.higherRate : null
      };
    });
    res.json({ trades: enriched });
  }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load trades.' }); }
});

app.post('/api/staff/trades/:id/mark', requireStaff, requireApprovedStaff, ADMIN_MONEY, async (req, res) => {
  try {
    const trade = await store.findTradeById(req.params.id);
    if (!trade || trade.staffId !== req.staff.id) return res.status(403).json({ error: 'You can only act on receipts for accounts you provided.' });
    const { status, reason, reasonImage, staffCreditedAmount } = req.body || {};
    if (!['seen', 'confirmed', 'approved', 'failed'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
    if (status === 'failed' && !reason) return res.status(400).json({ error: 'A reason is required when marking a payment as failed.' });
    if (status === 'failed' && trade.creditedAmount !== null) {
      return res.status(403).json({ error: 'This trade has already been verified and credited by an admin — only an admin can reverse it now.' });
    }
    if (status === 'approved' && (!staffCreditedAmount || Number(staffCreditedAmount) <= 0)) {
      return res.status(400).json({ error: 'Enter the amount you calculate should be credited (based on the rate) — an admin will verify it before it\'s applied.' });
    }
    // Staff proposes the credited amount here, but it does NOT touch the balance —
    // an admin has to separately verify and confirm it before it's actually credited.
    await store.updateTradeStatus(trade.id, {
      status,
      failReason: status === 'failed' ? reason : trade.failReason,
      failImage: status === 'failed' ? (reasonImage || null) : trade.failImage,
      staffCreditedAmount: status === 'approved' ? Number(staffCreditedAmount) : trade.staffCreditedAmount
    });
    notifyTrade(trade, status, reason);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update trade.' }); }
});

app.post('/api/staff/trades/:id/settlement', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const trade = await store.findTradeById(req.params.id);
    if (!trade || trade.staffId !== req.staff.id) return res.status(403).json({ error: 'Not your trade.' });
    const { screenshot } = req.body || {};
    if (!screenshot) return res.status(400).json({ error: 'Attach a screenshot of your payment.' });
    if (badAttachment(screenshot)) return res.status(400).json({ error: badAttachment(screenshot) });
    await store.setSettlement(trade.id, screenshot);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not save settlement proof.' }); }
});

app.get('/api/staff/settlement-account', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const settings = await store.getSettings();
    res.json({ settlementAccount: settings.settlementAccount, settlementBank: settings.settlementBank });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load settlement account.' }); }
});

// ============================================================
// STAFF: support chat (Chat Manager portal)
// Any approved staff member can read and answer customer chats.
// Replies are stored with sender 'admin' so the customer app shows them as agent messages.
// ============================================================
// A customer chat is "new" until the admin or any chat manager opens it (seen up to its last message).
const supportReadKey = userId => 'r:c:' + userId + '>support';
const withSeen = list => list.map(c => ({ ...c, unread: c.lastSender === 'user' && Date.parse(c.lastAt) > csGet(supportReadKey(c.userId)) }));
function supportSaw(userId, messages) {
  const last = (messages || []).reduce((t, m) => Math.max(t, Date.parse(m.createdAt) || 0), 0);
  if (last) csSet(supportReadKey(userId), Math.min(last, Date.now()), 0);
}
app.get('/api/staff/chats', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try { res.json({ conversations: withSeen(await store.listConversations()) }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversations.' }); }
});
app.get('/api/staff/chats/:userId', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try {
    const user = await store.findUserById(req.params.userId);
    if (!user) return res.status(404).json({ error: 'Customer not found.' });
    const messages = await store.messagesForUser(req.params.userId); supportSaw(req.params.userId, messages);
    res.json({ user: { id: user.id, name: user.name, phone: user.phone }, messages, routed: await routedFor(req.params.userId) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversation.' }); }
});
// Which chat photos were already turned into receipts: { messageId: { title, status, amount } }
async function routedFor(userId) {
  const out = {};
  try { (await store.listTradesForUser(userId)).forEach(t => { if (t.chatMessageId) out[t.chatMessageId] = { title: t.accountTitleUsed, status: t.status, amount: t.intendedAmount }; }); } catch (err) {}
  return out;
}
// Accounts a chat manager can send a chat receipt to.
app.get('/api/staff/route-accounts', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try {
    const [accounts, staffList] = await Promise.all([store.listAllAccounts(), store.listStaff()]);
    res.json({ accounts: accounts.filter(a => a.active).map(a => ({ id: a.id, title: a.title, bankName: a.bankName, accountNumber: a.accountNumber, staffName: (staffList.find(s => s.id === a.staffId) || {}).name || 'Admin' })) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load accounts.' }); }
});
// Chat manager turns a receipt photo from the chat into a receipt on the account the customer paid into.
app.post('/api/staff/chats/:userId/route', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try {
    const { messageId, accountId, amount } = req.body || {}, n = Number(amount);
    const [user, msg, account] = await Promise.all([store.findUserById(req.params.userId), store.findMessageById(messageId), store.findAccountById(accountId)]);
    if (!user) return res.status(404).json({ error: 'Customer not found.' });
    if (!msg || msg.userId !== user.id || msg.sender !== 'user' || !isImage(msg.imageData)) return res.status(400).json({ error: 'Pick a receipt photo the customer sent.' });
    if (!account || !account.active) return res.status(404).json({ error: 'That account is no longer available.' });
    if (!Number.isFinite(n) || n <= 0) return res.status(400).json({ error: 'Enter the amount on the receipt.' });
    if ((await routedFor(user.id))[msg.id]) return res.status(400).json({ error: 'This receipt was already sent to an account.' });
    let trade;
    try {
      trade = await store.createTrade({
        userId: user.id, accountId: account.id, staffId: account.staffId, intendedAmount: n, receiptImage: msg.imageData,
        accountNumberUsed: account.accountNumber, accountTitleUsed: account.title,
        userPayoutAccount: user.accountNumber, userPayoutBank: user.bankName, chatMessageId: msg.id
      });
    } catch (err) {
      if (/chat_message_id/.test(String(err && err.message))) return res.status(500).json({ error: 'Run the chat receipt SQL from the README in Supabase first.' });
      throw err;
    }
    alertTeam({ admin: true, staffId: account.staffId }, 'New receipt', `A ${account.title} receipt for ${plain(n)} came in from chat.`, { admin: 'receipts', staff: 'receipts' });
    res.json({ ok: true, trade: { id: trade.id, status: trade.status } });
  } catch (err) { console.error('Route receipt error:', err); res.status(500).json({ error: 'Could not send the receipt.' }); }
});
async function teamDeleteMessage(req, res) {
  try {
    const m = await store.findMessageById(req.params.id);
    if (!m || m.userId !== req.params.userId) return res.status(404).json({ error: 'Message not found.' });
    await store.deleteMessage(m.id); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete the message.' }); }
}
app.delete('/api/staff/chats/:userId/messages/:id', requireStaff, requireApprovedStaff, requireChatRole, teamDeleteMessage);
app.delete('/api/admin/chats/:userId/messages/:id', requireAdmin, teamDeleteMessage);
app.post('/api/staff/chats/:userId/send', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try {
    const { text, imageData } = req.body || {};
    if (!text && !imageData) return res.status(400).json({ error: 'Message is empty.' });
    if (badAttachment(imageData)) return res.status(400).json({ error: badAttachment(imageData) });
    const user = await store.findUserById(req.params.userId);
    if (!user) return res.status(404).json({ error: 'Customer not found.' });
    const msg = await store.addMessage({ userId: user.id, sender: 'admin', text, imageData });
    notify(user.id, 'chat', 'AZAPLUG Support', text ? String(text).slice(0, 140) : isVoice(imageData) ? 'Sent you a voice note' : 'Sent you a photo', { feed: false, go: 'chat' });
    res.json({ ok: true, message: msg });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not send message.' }); }
});

// Escalations: a chat manager hands a customer chat to the admin; it shows in the admin app's Admin Console.
async function escalationsWithNames() {
  const [list, users, staffList] = await Promise.all([store.listEscalations(), store.listUsers(), store.listStaff()]);
  return list.map(e => {
    const u = users.find(x => x.id === e.userId) || {};
    return { ...e, userName: u.name || 'Unknown', userPhone: u.phone || '',
      staffName: (staffList.find(s => s.id === e.staffId) || {}).name || 'Staff' };
  });
}
app.get('/api/staff/escalations', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try { res.json({ escalations: await escalationsWithNames() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load escalations.' }); }
});
app.post('/api/staff/chats/:userId/escalate', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try {
    const reason = String((req.body || {}).reason || '').trim();
    if (!reason) return res.status(400).json({ error: 'Enter the reason for forwarding this chat.' });
    const user = await store.findUserById(req.params.userId);
    if (!user) return res.status(404).json({ error: 'Customer not found.' });
    const open = (await store.listEscalations()).find(e => e.userId === user.id && e.status === 'open');
    if (open) return res.status(409).json({ error: 'This chat is already with the admin. Wait for their reply.' });
    const escalation = await store.createEscalation({ userId: user.id, staffId: req.staff.id, reason });
    alertTeam({ admin: true }, 'Chat escalated', `${req.staff.name} escalated ${user.name}'s chat: ${reason.slice(0, 110)}`, { admin: 'console' });
    res.json({ ok: true, escalation });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not forward this chat.' }); }
});

// People a staff member can forward a message to: the admin plus other approved staff (names only).
app.get('/api/staff/recipients', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try {
    const staff = (await store.listStaff()).filter(s => s.status === 'approved' && s.id !== req.staff.id);
    res.json({ recipients: [{ id: 'admin', name: 'Admin', role: 'Admin' }].concat(staff.map(s => ({ id: s.id, name: s.name, role: 'Staff' }))) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load recipients.' }); }
});

// ---- Staff-to-staff messages: chat managers <-> vendors only (vendors cannot message vendors)
const cleanRole = r => (r === 'chat' ? 'chat' : 'vendor');
let roleOk = false, roleChecked = 0;
async function roleReady() {
  if (roleOk || Date.now() - roleChecked < 60000) return roleOk;
  roleChecked = Date.now();
  try { roleOk = await store.hasStaffRole(); } catch (err) { roleOk = false; }
  return roleOk;
}
const canTalk = (a, b) => (a.role === 'chat' && b.role === 'vendor') || (a.role === 'vendor' && b.role === 'chat');
async function teamCheck(req, res) {
  if (!(await roleReady())) { res.status(500).json({ error: 'Run the staff department SQL from the README in Supabase first.' }); return null; }
  if (!req.staff.role) { res.status(400).json({ error: 'Log out and log in again so we know your department.' }); return null; }
  return req.staff;
}
app.put('/api/admin/staff/:id/role', requireAdmin, async (req, res) => {
  try {
    if (!(await roleReady())) return res.status(500).json({ error: 'Run the staff department SQL from the README in Supabase first.' });
    const s = await store.findStaffById(req.params.id);
    if (!s) return res.status(404).json({ error: 'Staff not found.' });
    await store.setStaffRole(s.id, cleanRole((req.body || {}).role)); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not change the department.' }); }
});
const teamSqlHint = err => (/team_messages/.test(String(err && err.message)) ? 'Run the team messages SQL from the README in Supabase first.' : null);
// A staff chat has two sides; a side is a staff id, or null for the admin.
const sameSide = (a, b) => (a || null) === (b || null);
const teamOut = (m, me) => ({ id: m.id, sender: sameSide(m.fromStaffId, me) ? 'me' : 'them', text: m.text, imageData: m.imageData, createdAt: m.createdAt });
const between = (msgs, me, other) => msgs.filter(m => (sameSide(m.fromStaffId, me) && sameSide(m.toStaffId, other)) || (sameSide(m.fromStaffId, other) && sameSide(m.toStaffId, me)));
const preview = m => (m ? (m.imageData ? (isVoice(m.imageData) ? 'Voice note' : 'Photo') : m.text) : '');
const adminSqlHint = err => (/from_staff_id|to_staff_id|not-null|null value/.test(String(err && err.message)) ? 'Run the admin-to-staff messages SQL from the README in Supabase first.' : null);
function threadSummary(msgs, me, other, base) {
  const t = between(msgs, me, other), last = t[t.length - 1];
  return { ...base, unread: t.filter(m => sameSide(m.fromStaffId, other) && sameSide(m.toStaffId, me) && !m.readAt).length,
    lastMessage: preview(last), lastAt: last ? last.createdAt : null, lastMine: last ? sameSide(last.fromStaffId, me) : false };
}
async function sendTeam(res, from, to, body, fromName) {
  const text = String((body || {}).text || '').trim().slice(0, 4000), imageData = (body || {}).imageData || null;
  if (!text && !imageData) return res.status(400).json({ error: 'Message is empty.' });
  if (badAttachment(imageData)) return res.status(400).json({ error: badAttachment(imageData) });
  const m = await store.addTeamMessage({ fromStaffId: from, toStaffId: to, text, imageData });
  const what = text ? text.slice(0, 120) : isVoice(imageData) ? 'Sent you a voice note' : 'Sent you a photo';
  if (to) alertTeam({ toStaff: to }, `Message from ${fromName}`, what, { staff: 'team' });
  else alertTeam({ admin: true }, `Message from ${fromName}`, what, { admin: 'chats' });
  res.json({ ok: true, message: teamOut(m, from) });
}
// Staff: Admin is always pinned at the top; chat managers <-> vendors below it.
app.get('/api/staff/team', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const me = req.staff.id, rolesOn = (await roleReady()) && !!req.staff.role;
    const [staff, msgs] = await Promise.all([store.listStaff(), store.listTeamMessagesFor(me)]);
    const people = rolesOn ? staff.filter(s => s.status === 'approved' && s.id !== me && canTalk(req.staff, s)).map(s => threadSummary(msgs, me, s.id, { id: s.id, name: s.name, role: s.role }))
      .sort((a, b) => String(b.lastAt || '').localeCompare(String(a.lastAt || '')) || a.name.localeCompare(b.name)) : [];
    const admin = threadSummary(msgs, me, null, { id: 'admin', name: 'Admin', role: 'admin', pinned: true });
    const list = [admin].concat(people);
    res.json({ people: list, unread: list.reduce((n, p) => n + p.unread, 0) });
  } catch (err) { if (!teamSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || 'Could not load team messages.' }); }
});
// The other side of a staff chat: null = admin, or an allowed staff member. Sends an error and returns undefined if not allowed.
async function staffOther(req, res) {
  if (req.params.id === 'admin') return null;
  if (!(await teamCheck(req, res))) return undefined;
  const other = await store.findStaffById(req.params.id);
  if (!other || other.status !== 'approved' || other.id === req.staff.id || !canTalk(req.staff, other)) { res.status(404).json({ error: 'You can only message the admin and ' + (req.staff.role === 'chat' ? 'vendors' : 'chat managers') + '.' }); return undefined; }
  return other;
}
app.get('/api/staff/team/:id', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const other = await staffOther(req, res); if (other === undefined) return;
    const me = req.staff.id, oid = other ? other.id : null, t = between(await store.listTeamMessagesFor(me), me, oid);
    if (t.some(m => sameSide(m.fromStaffId, oid) && !m.readAt)) await store.markTeamRead(me, oid);
    res.json({ person: other ? { id: other.id, name: other.name, role: other.role } : { id: 'admin', name: 'Admin', role: 'admin' }, messages: t.map(m => teamOut(m, me)) });
  } catch (err) { if (!teamSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || 'Could not load messages.' }); }
});
app.post('/api/staff/team/:id/send', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const other = await staffOther(req, res); if (other === undefined) return;
    await sendTeam(res, req.staff.id, other ? other.id : null, req.body, req.staff.name);
  } catch (err) { if (!teamSqlHint(err) && !adminSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || adminSqlHint(err) || 'Could not send the message.' }); }
});
app.delete('/api/staff/team/:id/messages/:mid', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const m = await store.findTeamMessage(req.params.mid);
    if (!m || m.fromStaffId !== req.staff.id) return res.status(404).json({ error: 'You can only delete your own messages.' });
    await store.deleteTeamMessage(m.id); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete the message.' }); }
});
// Admin <-> every staff member
app.get('/api/admin/team', requireAdmin, async (req, res) => {
  try {
    const [staff, msgs] = await Promise.all([store.listStaff(), store.listAdminTeamMessages()]);
    const people = staff.filter(s => s.status === 'approved').map(s => threadSummary(msgs, null, s.id, { id: s.id, name: s.name, role: s.role || null, phone: s.phone }))
      .sort((a, b) => String(b.lastAt || '').localeCompare(String(a.lastAt || '')) || a.name.localeCompare(b.name));
    res.json({ people, unread: people.reduce((n, p) => n + p.unread, 0) });
  } catch (err) { if (!teamSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || 'Could not load staff messages.' }); }
});
async function adminOther(req, res) {
  const s = await store.findStaffById(req.params.id);
  if (!s || s.status !== 'approved') { res.status(404).json({ error: 'Staff member not found.' }); return null; }
  return s;
}
app.get('/api/admin/team/:id', requireAdmin, async (req, res) => {
  try {
    const s = await adminOther(req, res); if (!s) return;
    const t = between(await store.listAdminTeamMessages(), null, s.id);
    if (t.some(m => m.fromStaffId === s.id && !m.readAt)) await store.markTeamRead(null, s.id);
    res.json({ person: { id: s.id, name: s.name, role: s.role || null, phone: s.phone }, messages: t.map(m => teamOut(m, null)) });
  } catch (err) { if (!teamSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || 'Could not load messages.' }); }
});
app.post('/api/admin/team/:id/send', requireAdmin, async (req, res) => {
  try { const s = await adminOther(req, res); if (!s) return; await sendTeam(res, null, s.id, req.body, 'Admin'); }
  catch (err) { if (!teamSqlHint(err) && !adminSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || adminSqlHint(err) || 'Could not send the message.' }); }
});
app.delete('/api/admin/team/:id/messages/:mid', requireAdmin, async (req, res) => {
  try {
    const m = await store.findTeamMessage(req.params.mid);
    if (!m || m.fromStaffId) return res.status(404).json({ error: 'You can only delete your own messages.' });
    await store.deleteTeamMessage(m.id); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete the message.' }); }
});

// ---- Forward one chat message to one person (the admin or another staff member)
const forwardSqlHint = err => (/forwards/.test(String(err && err.message)) ? 'Run the forwarded messages SQL from the README in Supabase first.' : null);
app.post('/api/staff/chats/:userId/forward-message', requireStaff, requireApprovedStaff, requireChatRole, async (req, res) => {
  try {
    const { messageId, to } = req.body || {};
    const msg = await store.findMessageById(messageId);
    if (!msg || msg.userId !== req.params.userId) return res.status(404).json({ error: 'That message is no longer in the chat.' });
    let toStaff = null;
    if (to !== 'admin') {
      toStaff = await store.findStaffById(String(to || ''));
      if (!toStaff || toStaff.status !== 'approved' || toStaff.id === req.staff.id) return res.status(400).json({ error: 'Choose who to forward to.' });
    }
    await store.createForward({ fromStaffId: req.staff.id, toStaffId: toStaff ? toStaff.id : null, userId: msg.userId, text: msg.text, imageData: msg.imageData, sender: msg.sender });
    const what = msg.text ? String(msg.text).slice(0, 120) : isVoice(msg.imageData) ? 'A voice note' : 'A photo';
    alertTeam(toStaff ? { toStaff: toStaff.id } : { admin: true }, `${req.staff.name} forwarded a message`, what, { admin: 'console', staff: 'inbox' });
    res.json({ ok: true, name: toStaff ? toStaff.name : 'Admin' });
  } catch (err) { console.error('Forward message error:', err); res.status(500).json({ error: forwardSqlHint(err) || 'Could not forward the message.' }); }
});
// A staff member's inbox of forwarded messages. The customer's name and number are not included.
app.get('/api/staff/forwards', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const [list, staffList] = await Promise.all([store.listForwardsTo(req.staff.id), store.listStaff()]);
    res.json({ forwards: list.map(f => ({ id: f.id, text: f.text, imageData: f.imageData, sender: f.sender, status: f.status, createdAt: f.createdAt, fromName: (staffList.find(s => s.id === f.fromStaffId) || {}).name || 'Staff' })) });
  } catch (err) { if (!forwardSqlHint(err)) console.error(err); res.status(500).json({ error: forwardSqlHint(err) || 'Could not load forwarded messages.' }); }
});
app.post('/api/staff/forwards/:id/done', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const f = await store.findForwardById(req.params.id);
    if (!f || f.toStaffId !== req.staff.id) return res.status(404).json({ error: 'Message not found.' });
    await store.setForwardStatus(f.id, 'done'); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update the message.' }); }
});
app.get('/api/admin/forwards', requireAdmin, async (req, res) => {
  try {
    const [list, staffList, users] = await Promise.all([store.listForwardsTo(null), store.listStaff(), store.listUsers()]);
    res.json({ forwards: list.map(f => ({ ...f, fromName: (staffList.find(s => s.id === f.fromStaffId) || {}).name || 'Staff', userName: (users.find(u => u.id === f.userId) || {}).name || 'Unknown' })) });
  } catch (err) { if (!forwardSqlHint(err)) console.error(err); res.status(500).json({ error: forwardSqlHint(err) || 'Could not load forwarded messages.' }); }
});
app.post('/api/admin/forwards/:id/done', requireAdmin, async (req, res) => {
  try {
    const f = await store.findForwardById(req.params.id);
    if (!f || f.toStaffId) return res.status(404).json({ error: 'Message not found.' });
    await store.setForwardStatus(f.id, 'done'); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update the message.' }); }
});

// ============================================================
// ADMIN: users
// ============================================================
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const [users, subs] = await Promise.all([store.listUsers(), store.listPushSubscriptions(null).catch(() => [])]);
    // alerts = how many phones this customer turned notifications on from
    res.json({ users: users.map(u => ({ ...u, alerts: subs.filter(s => s.userId === u.id).length })) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load users.' }); }
});
app.put('/api/admin/users/:id/approve', requireAdmin, async (req, res) => {
  try { await store.setUserStatus(req.params.id, 'approved'); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not approve user.' }); }
});
app.put('/api/admin/users/:id/reject', requireAdmin, async (req, res) => {
  try { await store.setUserStatus(req.params.id, 'rejected'); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not reject user.' }); }
});
app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try { await store.updateUser(req.params.id, req.body || {}); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not update user.' }); }
});
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try { await store.deleteUser(req.params.id); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete user.' }); }
});

// ============================================================
// ADMIN: staff
// ============================================================
app.get('/api/admin/staff', requireAdmin, async (req, res) => {
  try {
    const [staff, subs] = await Promise.all([store.listStaff(), store.listTeamPush().catch(() => [])]);
    res.json({ staff: staff.map(x => ({ ...x, alerts: subs.filter(s => s.staffId === x.id).length })), adminAlerts: subs.filter(s => s.portal === 'admin').length });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load staff.' }); }
});
app.put('/api/admin/staff/:id/approve', requireAdmin, async (req, res) => {
  try { await store.setStaffStatus(req.params.id, 'approved'); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not approve staff.' }); }
});
app.put('/api/admin/staff/:id/reject', requireAdmin, async (req, res) => {
  try { await store.setStaffStatus(req.params.id, 'rejected'); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not reject staff.' }); }
});
app.delete('/api/admin/staff/:id', requireAdmin, async (req, res) => {
  try { await store.deleteStaff(req.params.id); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete staff.' }); }
});

// ============================================================
// ADMIN: accounts (any account, any staff) + rates
// ============================================================
app.get('/api/admin/accounts', requireAdmin, async (req, res) => {
  try { res.json({ accounts: await store.listAllAccounts() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load accounts.' }); }
});
app.post('/api/admin/accounts', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    if (!b.title || !b.accountNumber || !b.bankName) return res.status(400).json({ error: 'Title, account number and bank are required.' });
    if (b.imageData && badAttachment(b.imageData)) return res.status(400).json({ error: badAttachment(b.imageData) });
    const account = await store.createAccount({
      staffId: b.staffId || null, title: b.title, accountNumber: b.accountNumber, bankName: b.bankName,
      imageData: b.imageData || null,
      lowestAmount: Number(b.lowestAmount) || 0, lowestRate: Number(b.lowestRate) || 0,
      higherAmount: Number(b.higherAmount) || 0, higherRate: Number(b.higherRate) || 0,
      minAmount: Number(b.minAmount) || 0, maxAmount: Number(b.maxAmount) || 0
    });
    res.json({ ok: true, account });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not create account.' }); }
});
app.put('/api/admin/accounts/:id', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    const before = await store.findAccountById(req.params.id);
    if (!before) return res.status(404).json({ error: 'Account not found.' });
    // Assigning to a staff member: it must be a real, approved one (or null to un-assign).
    if (b.staffId !== undefined && b.staffId !== null) {
      const owner = await store.findStaffById(b.staffId);
      if (!owner || owner.status !== 'approved') return res.status(400).json({ error: 'Choose an approved staff member.' });
    }
    await store.updateAccount(req.params.id, b);
    if (b.active === false) notifyAccountGone(before); // un-verified = hidden from customers
    if (b.active === true && !before.active && before.staffId) alertTeam({ staffId: before.staffId }, 'Account verified', `Your ${before.title} (${before.bankName}) account is now live for customers.`, { staff: 'acctAll' });
    if (b.staffId && b.staffId !== before.staffId) alertTeam({ staffId: b.staffId }, 'Account assigned to you', `The ${before.title} (${before.bankName}) account is now yours to manage.`, { staff: 'acctAll' });
    res.json({ ok: true });
  }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not update account.' }); }
});
app.delete('/api/admin/accounts/:id', requireAdmin, async (req, res) => {
  try {
    const account = await store.findAccountById(req.params.id);
    await store.deleteAccount(req.params.id);
    notifyAccountGone(account);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete account.' }); }
});

// ============================================================
// ADMIN: trades (full audit view) — the confidential record
// ============================================================
app.get('/api/admin/trades', requireAdmin, async (req, res) => {
  try {
    const trades = await store.listAllTrades();
    const users = await store.listUsers();
    const staffList = await store.listStaff();
    const accounts = await store.listAllAccounts();
    const enriched = trades.map(t => {
      const acc = accounts.find(a => a.id === t.accountId);
      return {
        ...t,
        userName: (users.find(u => u.id === t.userId) || {}).name || 'Unknown',
        userPhone: (users.find(u => u.id === t.userId) || {}).phone || '',
        staffName: (staffList.find(s => s.id === t.staffId) || {}).name || 'Unassigned',
        lowestAmount: acc ? acc.lowestAmount : null, lowestRate: acc ? acc.lowestRate : null,
        higherAmount: acc ? acc.higherAmount : null, higherRate: acc ? acc.higherRate : null
      };
    });
    res.json({ trades: enriched });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load trades.' }); }
});

app.post('/api/admin/trades/:id/mark', requireAdmin, ADMIN_MONEY, async (req, res) => {
  try {
    const trade = await store.findTradeById(req.params.id);
    if (!trade) return res.status(404).json({ error: 'Trade not found.' });
    const { status, reason, reasonImage } = req.body || {};
    if (!['seen', 'confirmed', 'approved', 'failed'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
    if (status === 'failed' && !reason) return res.status(400).json({ error: 'A reason is required when marking a payment as failed.' });

    const wasCredited = trade.creditedAmount !== null;
    await store.updateTradeStatus(trade.id, {
      status,
      failReason: status === 'failed' ? reason : trade.failReason,
      failImage: status === 'failed' ? (reasonImage || null) : trade.failImage
    });

    // If this trade had already been verified & credited, and admin is now reversing it to failed,
    // refund exactly what was credited and clear the credited amount so it can be re-verified fresh later.
    if (wasCredited && status === 'failed') {
      await store.addToBalance(trade.userId, -trade.creditedAmount);
      await store.updateTradeStatus(trade.id, { status: 'failed', creditedAmount: null });
    }
    notifyTrade(trade, status, reason);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update trade.' }); }
});

// Admin-only second step: verify a staff-approved trade and actually credit the balance.
// This is also the moment the customer's CURRENT payout account/bank gets locked into the
// trade record permanently — even if the user later changes or deletes their account.
app.post('/api/admin/trades/:id/credit', requireAdmin, ADMIN_MONEY, async (req, res) => {
  try {
    const trade = await store.findTradeById(req.params.id);
    if (!trade) return res.status(404).json({ error: 'Trade not found.' });
    if (trade.status !== 'approved') return res.status(400).json({ error: 'Only staff-approved trades can be verified and credited.' });
    if (trade.creditedAmount !== null) return res.status(400).json({ error: 'This trade has already been credited.' });
    const { creditedAmount } = req.body || {};
    if (!creditedAmount || Number(creditedAmount) <= 0) {
      return res.status(400).json({ error: 'Enter the final amount to credit to the customer\'s balance.' });
    }

    const user = await store.findUserById(trade.userId);
    await store.updateTradeStatus(trade.id, {
      status: 'approved',
      creditedAmount: Number(creditedAmount),
      userPayoutAccount: user ? user.accountNumber : trade.userPayoutAccount,
      userPayoutBank: user ? user.bankName : trade.userPayoutBank
    });
    // Loan repayment: whatever the customer owes comes out of this credit first.
    let repay = 0;
    try {
      const loan = (await store.listLoansForUser(trade.userId)).find(l => l.status === 'active' && l.outstanding > 0);
      if (loan) {
        repay = Math.min(loan.outstanding, Number(creditedAmount));
        const left = loan.outstanding - repay;
        await store.updateLoan(loan.id, { outstanding: left, status: left <= 0 ? 'repaid' : 'active' });
      }
    } catch (err) { console.error('Loan repayment skipped:', err.message || err); repay = 0; }
    await store.addToBalance(trade.userId, Number(creditedAmount) - repay);
    const forWhat = `for your ${trade.accountTitleUsed || ''} receipt`.replace('  ', ' ');
    notify(trade.userId, 'tx', 'Balance credited', repay
      ? `₦${plain(creditedAmount)} was credited ${forWhat}. ₦${plain(repay)} went to your loan and ₦${plain(Number(creditedAmount) - repay)} was added to your balance.`
      : `₦${plain(creditedAmount)} has been added to your balance ${forWhat}.`);
    res.json({ ok: true, repaid: repay });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not credit trade.' }); }
});

// ============================================================
// ADMIN: withdrawals
// ============================================================
app.get('/api/admin/withdrawals', requireAdmin, async (req, res) => {
  try {
    const withdrawals = await store.listAllWithdrawals();
    const users = await store.listUsers();
    const enriched = withdrawals.map(w => ({
      ...w,
      userName: (users.find(u => u.id === w.userId) || {}).name || 'Unknown',
      userPhone: (users.find(u => u.id === w.userId) || {}).phone || '',
      bankChangedAt: csGet('bank:' + w.userId) || null   // the customer changed their payout account at this time
    }));
    res.json({ withdrawals: enriched });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load withdrawals.' }); }
});

app.post('/api/admin/withdrawals/:id/mark', requireAdmin, ADMIN_MONEY, async (req, res) => {
  try {
    const withdrawal = await store.findWithdrawalById(req.params.id);
    if (!withdrawal) return res.status(404).json({ error: 'Withdrawal not found.' });
    if (withdrawal.status !== 'pending') return res.status(400).json({ error: 'This withdrawal has already been handled.' });
    const { status, reason, reasonImage } = req.body || {};
    if (!['paid', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
    if (status === 'rejected' && !reason) return res.status(400).json({ error: 'A reason is required when rejecting a withdrawal.' });

    const patch = { status, reason, reasonImage: status === 'rejected' ? (reasonImage || null) : undefined };
    // Lock in exactly which account this was paid to, at the moment of payment —
    // permanent even if the customer later changes or deletes their bank details.
    if (status === 'paid') {
      const user = await store.findUserById(withdrawal.userId);
      if (user) { patch.payoutAccount = user.accountNumber; patch.payoutBank = user.bankName; }
    }
    await store.updateWithdrawalStatus(withdrawal.id, patch);
    if (status === 'rejected') await store.addToBalance(withdrawal.userId, withdrawal.amount); // refund the hold
    if (status === 'paid') notify(withdrawal.userId, 'tx', 'Withdrawal paid', `Your withdrawal of ₦${plain(withdrawal.amount)} has been paid to ${patch.payoutBank || withdrawal.payoutBank}.`);
    else notify(withdrawal.userId, 'tx', 'Withdrawal cancelled', `Your withdrawal of ₦${plain(withdrawal.amount)} was cancelled: ${reason}. The money is back in your balance.`);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update withdrawal.' }); }
});

// ============================================================
// ADMIN: rules + settings
// ============================================================
app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  try { res.json(await store.getSettings()); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load settings.' }); }
});
app.put('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {}, patch = {};
    ['rulesText', 'settlementAccount', 'settlementBank', 'maxDeposit'].forEach(k => { if (b[k] !== undefined) patch[k] = b[k]; });
    for (const k of ['btcRate', 'usdtRate']) {
      if (b[k] === undefined) continue;
      const n = Number(b[k]);
      if (!Number.isFinite(n) || n < 0) return res.status(400).json({ error: 'Enter the rate as a number, like 1650.' });
      patch[k] = n;
    }
    await store.updateSettings(patch); res.json({ ok: true });
  } catch (err) {
    console.error(err);
    const cryptoCols = /btc_rate|usdt_rate/.test(String(err && err.message));
    res.status(500).json({ error: cryptoCols ? 'Run the BTC/USDT rates SQL from the README in Supabase first.' : 'Could not update settings.' });
  }
});

// ============================================================
// ADMIN: Admin Console — chats escalated by staff
// ============================================================
app.get('/api/admin/escalations', requireAdmin, async (req, res) => {
  try { res.json({ escalations: await escalationsWithNames() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load escalations.' }); }
});
app.post('/api/admin/escalations/:id/resolve', requireAdmin, async (req, res) => {
  try {
    const esc = await store.findEscalationById(req.params.id);
    if (!esc) return res.status(404).json({ error: 'Escalation not found.' });
    if (esc.status !== 'open') return res.status(400).json({ error: 'This escalation has already been resolved.' });
    await store.resolveEscalation(esc.id, String((req.body || {}).feedback || '').trim());
    alertTeam({ chat: true }, 'Returned from Admin', String((req.body || {}).feedback || '').trim() || 'An escalated chat was resolved.', { staff: 'chats' });
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not resolve this escalation.' }); }
});

// ============================================================
// ADMIN: chat inbox
// ============================================================
app.get('/api/admin/chats', requireAdmin, async (req, res) => {
  try { res.json({ conversations: withSeen(await store.listConversations()) }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversations.' }); }
});
app.get('/api/admin/chats/:userId', requireAdmin, async (req, res) => {
  try {
    const user = await store.findUserById(req.params.userId);
    const messages = await store.messagesForUser(req.params.userId); supportSaw(req.params.userId, messages);
    res.json({ user, messages });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversation.' }); }
});
app.post('/api/admin/chats/:userId/send', requireAdmin, async (req, res) => {
  try {
    const { text, imageData } = req.body || {};
    if (!text && !imageData) return res.status(400).json({ error: 'Message is empty.' });
    if (badAttachment(imageData)) return res.status(400).json({ error: badAttachment(imageData) });
    const msg = await store.addMessage({ userId: req.params.userId, sender: 'admin', text, imageData });
    notify(req.params.userId, 'chat', 'AZAPLUG Support', text ? String(text).slice(0, 140) : isVoice(imageData) ? 'Sent you a voice note' : 'Sent you a photo', { feed: false, go: 'chat' });
    res.json({ ok: true, message: msg });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not send message.' }); }
});

// ============================================================
// PUSH NOTIFICATIONS + in-app notification feed (customers)
// The key pair is created once and kept in the push_keys table, so there is nothing to configure.
// Nothing in here is allowed to break the request that triggered it.
// ============================================================
let webpush = null;
try { webpush = require('web-push'); } catch (e) { console.warn('web-push is not installed, push notifications are off.'); }
let pushKeysPromise = null;
function pushKeys() {
  if (!webpush) return Promise.resolve(null);
  if (!pushKeysPromise) {
    pushKeysPromise = (async () => {
      let keys = await store.getPushKeys();
      if (!keys) keys = await store.savePushKeys(webpush.generateVAPIDKeys());
      webpush.setVapidDetails(process.env.PUSH_CONTACT || 'https://recio-exchange.onrender.com', keys.publicKey, keys.privateKey);
      return keys;
    })().catch(err => { pushKeysPromise = null; throw err; });
  }
  return pushKeysPromise;
}
async function sendPush(subs, payload, forget) {
  const drop = forget || store.deletePushSubscription;
  if (!subs.length || !(await pushKeys())) return;
  await Promise.all(subs.map(s =>
    webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, JSON.stringify(payload), { TTL: 86400 })
      .catch(err => {
        // 404 / 410 = the browser dropped this subscription; forget it.
        if (err.statusCode === 404 || err.statusCode === 410) return drop(s.endpoint).catch(() => {});
        console.error('Push failed:', err.statusCode || err.message);
      })));
}
// Tells a customer something: saved to their in-app Notifications (unless feed is false) and pushed to their devices.
// userId null = every customer. Runs in the background and never throws.
function notify(userId, kind, title, body, opts) {
  const o = opts || {};
  if (o.feed !== false) store.addNotification({ userId, kind, title, body }).catch(err => console.error('Notification save error:', err.message || err));
  store.listPushSubscriptions(userId).then(subs => sendPush(subs, { title, body, go: o.go || 'notifications' }))
    .catch(err => console.error('Push error:', err.message || err));
}
const plain = n => Number(n || 0).toLocaleString('en-NG');
function notifyTrade(trade, status, reason) {
  const what = `${trade.accountTitleUsed || 'your'} receipt for ${plain(trade.intendedAmount)}`;
  if (status === 'seen') notify(trade.userId, 'tx', 'Receipt seen', `We have seen your ${what} and are checking it.`);
  if (status === 'confirmed') notify(trade.userId, 'tx', 'Payment confirmed', `Your ${what} has been confirmed.`);
  if (status === 'approved') notify(trade.userId, 'tx', 'Receipt approved', `Your ${what} was approved. Your balance will be credited shortly.`);
  if (status === 'failed') notify(trade.userId, 'tx', 'Receipt failed', `Your ${what} failed: ${reason}`);
}
// An account customers could see has been removed or hidden: warn everyone to stop paying into it.
function notifyAccountGone(account) {
  if (!account || !account.active) return;
  notify(null, 'alert', `Stop using ${account.title} (${account.bankName})`,
    `This ${account.title} account is no longer in use. Do not send money to it. Open AZAPLUG and check Get Account for the current one.`);
}

app.get('/api/push/key', requireUser, async (req, res) => {
  try {
    const keys = await pushKeys();
    if (!keys) return res.status(503).json({ error: 'Push notifications are not available right now.' });
    res.json({ publicKey: keys.publicKey });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Push notifications are not set up yet.' }); }
});
app.post('/api/push/subscribe', requireUser, async (req, res) => {
  try {
    const b = req.body || {}, k = b.keys || {};
    if (!pushOk(b.endpoint) || !k.p256dh || !k.auth) return res.status(400).json({ error: 'Invalid subscription.' });
    await store.savePushSubscription({ endpoint: b.endpoint, userId: req.session.userId, p256dh: k.p256dh, auth: k.auth });
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not turn on notifications.' }); }
});
app.post('/api/push/unsubscribe', requireUser, async (req, res) => {
  try {
    const endpoint = (req.body || {}).endpoint;
    const mine = (await store.listPushSubscriptions(req.session.userId)).some(s => s.endpoint === endpoint);
    if (mine) await store.deletePushSubscription(endpoint);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not turn off notifications.' }); }
});
app.get('/api/notifications', requireUser, async (req, res) => {
  try {
    const user = await store.findUserById(req.session.userId);
    if (!user) return res.status(401).json({ error: 'Please log in first.' });
    res.json({ notifications: await store.listNotificationsForUser(user.id, user.createdAt) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load notifications.' }); }
});
// Admin "Write": an announcement to every customer.
app.post('/api/admin/announce', requireAdmin, async (req, res) => {
  try {
    const title = String((req.body || {}).title || '').trim(), body = String((req.body || {}).body || '').trim();
    if (!title || !body) return res.status(400).json({ error: 'Enter a title and a message.' });
    if (title.length > 80 || body.length > 400) return res.status(400).json({ error: 'That announcement is too long.' });
    await store.addNotification({ userId: null, kind: 'info', title, body });
    notify(null, 'info', title, body, { feed: false });
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not send the announcement. Is the notifications table set up?' }); }
});

// ============================================================
// TEAM ALERTS: push to the admin's and staff's own devices.
// who: { admin: true, chat: true, staffId: '<vendor who owns it>' }.  go: which screen a tap opens in each app.
// Runs in the background and never throws.
// ============================================================
function requireTeam(req, res, next) {
  if (!req.session.isAdmin && !req.session.staffId) return res.status(401).json({ error: 'Login required.' });
  next();
}
function alertTeam(who, title, body, go) {
  const g = go || {};
  store.listTeamPush().then(subs => {
    const admin = subs.filter(s => who.admin && s.portal === 'admin');
    const staff = subs.filter(s => (who.chat && s.portal === 'chat') || (who.staffId && s.portal === 'vendor' && s.staffId === who.staffId) || (who.toStaff && s.staffId === who.toStaff));
    return Promise.all([
      sendPush(admin, { title, body, go: g.admin || 'dash', app: '/admin-app.html' }, store.deleteTeamPush),
      sendPush(staff, { title, body, go: g.staff || '', app: '/staff-app.html' }, store.deleteTeamPush)
    ]);
  }).catch(err => console.error('Team alert error:', err.message || err));
}
function validSub(b) { const k = (b || {}).keys || {}; return b && pushOk(b.endpoint) && k.p256dh && k.auth; }
app.get('/api/team/push/key', requireTeam, async (req, res) => {
  try {
    const keys = await pushKeys();
    if (!keys) return res.status(503).json({ error: 'Alerts are not available right now.' });
    res.json({ publicKey: keys.publicKey });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Alerts are not set up yet.' }); }
});
app.post('/api/admin/push/subscribe', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {};
    if (!validSub(b)) return res.status(400).json({ error: 'Invalid subscription.' });
    await store.saveTeamPush({ endpoint: b.endpoint, staffId: null, portal: 'admin', p256dh: b.keys.p256dh, auth: b.keys.auth });
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not turn on alerts.' }); }
});
app.post('/api/staff/push/subscribe', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const b = req.body || {};
    if (!validSub(b)) return res.status(400).json({ error: 'Invalid subscription.' });
    await store.saveTeamPush({ endpoint: b.endpoint, staffId: req.staff.id, portal: b.portal === 'chat' ? 'chat' : 'vendor', p256dh: b.keys.p256dh, auth: b.keys.auth });
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not turn on alerts.' }); }
});
app.post('/api/team/push/unsubscribe', requireTeam, async (req, res) => {
  try { await store.deleteTeamPush(String((req.body || {}).endpoint || '')); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not turn off alerts.' }); }
});

// ============================================================
// LOANS (Borrow)
// A customer may request up to the admin's limit, one loan at a time. Approving adds the money to their
// balance. Repayment is automatic: each time a receipt is credited, what is owed is taken out first.
// ============================================================
// A customer can only borrow after this much naira has been credited to them from receipts.
// ---- Top Traders (trust board): first 3 letters of the name + total traded through approved trades.
let TOP = { at: 0, data: null };
// ---- December Challenge: the top 3 traders win prizes. Receipts SENT between start and end (Lagos time) count,
// even if they are approved later. The banner shows in the app until showUntil.
const CHALLENGE = { id: 'dec2026', title: 'December Top Traders', start: Date.parse('2026-12-01T00:00:00+01:00'), end: Date.parse('2026-12-23T16:00:00+01:00'),
  showUntil: Date.parse('2027-01-05T00:00:00+01:00'), prizes: [20000, 15000, 10000] };
const inChallenge = t => { const c = Date.parse(t.createdAt); return c >= CHALLENGE.start && c < CHALLENGE.end; };
const chalPaidKey = rank => 'chal:' + CHALLENGE.id + ':' + rank;
const maskName = n => { const w = String(n || '').replace(/[^\p{L}\p{N}]/gu, ''); return (w.slice(0, 3) || 'Cus').replace(/^./, c => c.toUpperCase()) + '***'; };
const lagosMonth = d => new Intl.DateTimeFormat('en-CA', { timeZone: 'Africa/Lagos', year: 'numeric', month: '2-digit' }).format(new Date(d));
async function topTraders(fresh) {
  if (!fresh && TOP.data && Date.now() - TOP.at < 300000) return TOP.data; // worked out at most every 5 minutes
  const [trades, users] = await Promise.all([store.listApprovedTradeTotals(), store.listUsers()]);
  const ok = new Map(users.filter(u => u.status === 'approved').map(u => [u.id, u]));
  const month = lagosMonth(Date.now()), all = new Map(), mon = new Map(), chal = new Map();
  const add = (m, t) => { const v = m.get(t.userId) || { total: 0, n: 0 }; v.total += t.creditedAmount; v.n++; m.set(t.userId, v); };
  let total = 0, count = 0;
  for (const t of trades) {
    if (!ok.has(t.userId) || !(t.creditedAmount > 0)) continue;
    total += t.creditedAmount; count++; add(all, t);
    if (lagosMonth(t.createdAt) === month) add(mon, t);
    if (inChallenge(t)) add(chal, t);
  }
  const rank = m => [...m.entries()].map(([id, v]) => ({ id, name: maskName(ok.get(id).name), total: Math.round(v.total), trades: v.n }))
    .sort((a, b) => b.total - a.total).slice(0, 10);
  const chalFull = [...chal.entries()].map(([id, v]) => ({ id, name: ok.get(id).name, phone: ok.get(id).phone, total: Math.round(v.total), trades: v.n }))
    .sort((a, b) => b.total - a.total || a.trades - b.trades).slice(0, 10);
  TOP = { at: Date.now(), data: { month: rank(mon), all: rank(all), chal: chalFull.map(r => ({ ...r, name: maskName(r.name), phone: undefined })), chalFull, totalTraded: Math.round(total), trades: count, customers: all.size } };
  return TOP.data;
}
app.get('/api/top-traders', requireUser, async (req, res) => {
  try {
    const d = await topTraders(), me = req.session.userId;
    const out = list => list.map((r, i) => ({ rank: i + 1, name: r.name, total: r.total, trades: r.trades, me: r.id === me }));
    const now = Date.now(), c = CHALLENGE;
    res.json({ month: out(d.month), all: out(d.all), totalTraded: d.totalTraded, trades: d.trades, customers: d.customers,
      challenge: now < c.showUntil ? { title: c.title, start: c.start, end: c.end, prizes: c.prizes, now, board: now >= c.start ? out(d.chal) : [] } : null });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load top traders.' }); }
});

// Admin: the real names and numbers of the challenge leaders, and paying the top 3 prizes into their balance.
app.get('/api/admin/challenge', requireAdmin, async (req, res) => {
  try {
    const d = await topTraders(true), c = CHALLENGE, now = Date.now();
    res.json({ title: c.title, start: c.start, end: c.end, prizes: c.prizes, now, ended: now >= c.end,
      board: d.chalFull.map((r, i) => ({ rank: i + 1, userId: r.id, name: r.name, phone: r.phone, total: r.total, trades: r.trades, prize: c.prizes[i] || 0, paidAt: i < 3 ? csGet(chalPaidKey(i + 1)) || null : null })) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load the challenge.' }); }
});
app.post('/api/admin/challenge/pay', requireAdmin, ADMIN_MONEY, async (req, res) => {
  try {
    const rank = Number((req.body || {}).rank), c = CHALLENGE;
    if (Date.now() < c.end) return res.status(400).json({ error: 'The challenge has not ended yet.' });
    if (![1, 2, 3].includes(rank)) return res.status(400).json({ error: 'Only the top 3 get a prize.' });
    if (csGet(chalPaidKey(rank))) return res.status(400).json({ error: 'This prize has already been paid.' });
    const winner = (await topTraders(true)).chalFull[rank - 1];
    if (!winner) return res.status(400).json({ error: 'Nobody is in that position.' });
    if (req.body.userId && req.body.userId !== winner.id) return res.status(409).json({ error: 'The board changed. Open the page again.' });
    // Mark it paid (and saved) first, so it can never be paid twice.
    csSet(chalPaidKey(rank), Date.now(), 0); await csFlush();
    if (CS_SAVED.get(chalPaidKey(rank)) !== CS.get(chalPaidKey(rank))) { CS.delete(chalPaidKey(rank)); return res.status(500).json({ error: 'Run the chat_state SQL from the README in Supabase first.' }); }
    const prize = c.prizes[rank - 1];
    await store.addToBalance(winner.id, prize);
    notify(winner.id, 'tx', `You won ${['1st', '2nd', '3rd'][rank - 1]} place!`, `Congratulations! ₦${plain(prize)} from the ${c.title} has been added to your balance.`);
    res.json({ ok: true, paid: prize, name: winner.name });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not pay the prize.' }); }
});

const LOAN_MIN_TRADED = 70000;
async function tradedTotal(userId) {
  return (await store.listTradesForUser(userId)).reduce((sum, t) => sum + (t.status === 'approved' && t.creditedAmount ? t.creditedAmount : 0), 0);
}
app.get('/api/loans', requireUser, async (req, res) => {
  try {
    const [limit, loans, traded] = await Promise.all([store.getLoanLimit(), store.listLoansForUser(req.session.userId), tradedTotal(req.session.userId)]);
    res.json({ limit, loans, traded, required: LOAN_MIN_TRADED, eligible: traded >= LOAN_MIN_TRADED });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Borrowing is not available right now.' }); }
});
app.post('/api/loans', requireUser, requireApprovedUser, moneyLock(req => 'user:' + req.session.userId), async (req, res) => {
  try {
    const amount = Number((req.body || {}).amount);
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Enter a valid amount.' });
    const [limit, loans] = await Promise.all([store.getLoanLimit(), store.listLoansForUser(req.user.id)]);
    const traded = await tradedTotal(req.user.id);
    if (traded < LOAN_MIN_TRADED) return res.status(400).json({ error: `You can borrow after trading ₦${plain(LOAN_MIN_TRADED)}. You have traded ₦${plain(traded)} so far.` });
    if (amount > limit) return res.status(400).json({ error: `The most you can borrow is ₦${plain(limit)}.` });
    if (loans.some(l => l.status === 'pending')) return res.status(400).json({ error: 'You already have a loan request being reviewed.' });
    if (loans.some(l => l.status === 'active')) return res.status(400).json({ error: 'Repay your current loan before asking for another.' });
    const loan = await store.createLoan({ userId: req.user.id, amount });
    alertTeam({ admin: true }, 'Loan request', `${req.user.name} asked to borrow ₦${plain(amount)}.`, { admin: 'loans' });
    res.json({ ok: true, loan });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not send your loan request.' }); }
});
app.get('/api/admin/loans', requireAdmin, async (req, res) => {
  try {
    const [limit, loans, users] = await Promise.all([store.getLoanLimit(), store.listLoans(), store.listUsers()]);
    res.json({ limit, loans: loans.map(l => { const u = users.find(x => x.id === l.userId) || {}; return { ...l, userName: u.name || 'Unknown', userPhone: u.phone || '', userBalance: u.balance || 0 }; }) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load loans.' }); }
});
app.put('/api/admin/loans/limit', requireAdmin, async (req, res) => {
  try {
    const limit = Number((req.body || {}).limit);
    if (!(limit >= 0)) return res.status(400).json({ error: 'Enter a valid limit.' });
    await store.setLoanLimit(limit);
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not save the loan limit.' }); }
});
app.post('/api/admin/loans/:id/decide', requireAdmin, ADMIN_MONEY, async (req, res) => {
  try {
    const loan = await store.findLoanById(req.params.id);
    if (!loan) return res.status(404).json({ error: 'Loan request not found.' });
    if (loan.status !== 'pending') return res.status(400).json({ error: 'This request has already been decided.' });
    if ((req.body || {}).decision === 'approve') {
      // Mark it first so a repeated tap can never pay the same loan out twice.
      await store.updateLoan(loan.id, { status: 'active', outstanding: loan.amount });
      await store.addToBalance(loan.userId, loan.amount);
      notify(loan.userId, 'tx', 'Loan approved', `₦${plain(loan.amount)} has been added to your balance. It will be taken from your next credited receipts.`);
    } else if ((req.body || {}).decision === 'decline') {
      await store.updateLoan(loan.id, { status: 'declined' });
      notify(loan.userId, 'tx', 'Loan request declined', `Your request to borrow ₦${plain(loan.amount)} was not approved this time.`);
    } else return res.status(400).json({ error: 'Choose approve or decline.' });
    res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not update the loan.' }); }
});

// ============================================================
// STATIC PAGES
// ============================================================
// The apps ask for this when they come back to the screen; if it changed (a new deploy), they reload themselves.
const BUILD = process.env.RENDER_GIT_COMMIT || String(Date.now());
app.get('/api/version', (req, res) => res.json({ v: BUILD }));
// The old website pages are retired: everyone goes to the new apps (which require notifications).
const OLD_PAGES = { '/': '/app.html', '/index.html': '/app.html', '/login.html': '/app.html', '/dashboard.html': '/app.html', '/pending.html': '/app.html',
  '/account-center.html': '/app.html', '/staff.html': '/staff-app.html', '/staff-login.html': '/staff-app.html', '/admin.html': '/admin-app.html' };
app.get(Object.keys(OLD_PAGES), (req, res) => res.redirect(302, OLD_PAGES[req.path] + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '')));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, file) { if (/\.(html|js|webmanifest)$/.test(file)) res.setHeader('Cache-Control', 'no-cache'); }
}));

// ============================================================
// GIVEAWAYS — the first N customers to say the keyword (e.g. "hi") in chat after the start time win.
// They must be using the installed app (sent by the app as `installed`). The admin credits winners in one tap.
// ============================================================
const gaSqlHint = err => (/giveaway/.test(String(err && err.message)) ? 'Run the giveaway SQL from the README in Supabase first.' : null);
const keywordHit = (text, kw) => new RegExp('^\\W*' + String(kw || 'hi').toLowerCase().replace(/[^a-z0-9]/g, '') + '+\\b', 'i').test(String(text).trim());
async function currentGiveaway() {
  const list = await store.listGiveaways();
  return list.find(g => g.status === 'open') || null;
}
// Returns the automatic reply message (also saved in the chat) when the text is a giveaway entry, or null.
async function giveawayEntry(userId, text, body) {
  let g; try { g = await currentGiveaway(); } catch (err) { return null; }
  if (!g || Date.now() < new Date(g.startsAt).getTime() || !keywordHit(text, g.keyword)) return null;
  const entries = await store.listEntries(g.id);
  if (entries.some(e => e.userId === userId)) return null;   // already answered once
  const say = t => store.addMessage({ userId, sender: 'admin', text: t });
  if (!body.installed) return say(`You are early for the ${g.title}! To qualify, open AZAPLUG from the app installed on your home screen (Profile → Install app), turn on notifications, then say "${g.keyword}" again.`);
  const winnersSoFar = entries.filter(e => e.won).length;
  const entry = await store.addEntry({ giveawayId: g.id, userId, installed: true, alertsOn: !!body.alertsOn, won: winnersSoFar < g.winners });
  if (!entry) return null;
  if (entry.won) {   // two people at the same second: only the first N by time keep their spot
    const pos = (await store.listEntries(g.id)).filter(e => e.won).findIndex(e => e.id === entry.id) + 1;
    if (pos > g.winners || pos === 0) { await store.updateEntry(entry.id, { won: false }); entry.won = false; }
    else {
      alertTeam({ admin: true }, `Giveaway winner #${pos}`, `A customer just won the ${g.title}.`, { admin: 'giveaway' });
      return say(`Congratulations! You are winner #${pos} of ${g.winners} in the ${g.title}. ₦${plain(g.amount)} will be added to your balance shortly.`);
    }
  }
  return say(`Thanks for joining the ${g.title}! All ${g.winners} spots are taken this time. Keep notifications on so you don't miss the next one.`);
}
app.get('/api/giveaway', requireUser, async (req, res) => {
  try {
    const g = await currentGiveaway(); if (!g) return res.json({ giveaway: null });
    const entries = await store.listEntries(g.id), mine = entries.find(e => e.userId === req.session.userId);
    const won = entries.filter(e => e.won);
    res.json({ giveaway: { id: g.id, title: g.title, amount: g.amount, winners: g.winners, keyword: g.keyword, startsAt: g.startsAt, live: Date.now() >= new Date(g.startsAt).getTime(), spotsLeft: Math.max(0, g.winners - won.length) },
      mine: mine ? { won: mine.won, position: mine.won ? won.findIndex(e => e.id === mine.id) + 1 : null, credited: mine.credited } : null });
  } catch (err) { if (!gaSqlHint(err)) console.error(err); res.json({ giveaway: null }); }
});
app.get('/api/admin/giveaways', requireAdmin, async (req, res) => {
  try {
    const [list, users] = await Promise.all([store.listGiveaways(), store.listUsers()]);
    const out = [];
    for (const g of list.slice(0, 10)) {
      const entries = await store.listEntries(g.id);
      out.push({ ...g, live: Date.now() >= new Date(g.startsAt).getTime(),
        entries: entries.map(e => { const u = users.find(x => x.id === e.userId) || {}; return { ...e, name: u.name || 'Deleted customer', phone: u.phone || '' }; }) });
    }
    res.json({ giveaways: out });
  } catch (err) { if (!gaSqlHint(err)) console.error(err); res.status(500).json({ error: gaSqlHint(err) || 'Could not load giveaways.' }); }
});
app.post('/api/admin/giveaways', requireAdmin, async (req, res) => {
  try {
    const b = req.body || {}, amount = Number(b.amount), winners = Math.round(Number(b.winners)), start = new Date(b.startsAt);
    const keyword = String(b.keyword || 'hi').trim().toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20) || 'hi';
    if (!(amount > 0)) return res.status(400).json({ error: 'Enter the amount each winner gets.' });
    if (!(winners > 0 && winners <= 1000)) return res.status(400).json({ error: 'Enter how many winners (1 to 1000).' });
    if (isNaN(start.getTime())) return res.status(400).json({ error: 'Choose the start date and time.' });
    if (await currentGiveaway()) return res.status(409).json({ error: 'End the current giveaway before starting a new one.' });
    const title = String(b.title || '').trim().slice(0, 60) || `₦${plain(amount)} Giveaway`;
    const id = await store.createGiveaway({ title, amount, winners, keyword, startsAt: start.toISOString() });
    if (b.announce) {
      const when = start.toLocaleString('en-NG', { timeZone: 'Africa/Lagos', weekday: 'short', hour: 'numeric', minute: '2-digit' });
      notify(null, 'announce', title, `${when}: the first ${winners} people to say "${keyword}" in the AZAPLUG app chat win ₦${plain(amount)}. Use the installed app with notifications on.`, { go: 'home' });
    }
    res.json({ ok: true, id });
  } catch (err) { if (!gaSqlHint(err)) console.error(err); res.status(500).json({ error: gaSqlHint(err) || 'Could not create the giveaway.' }); }
});
app.post('/api/admin/giveaways/:id/end', requireAdmin, async (req, res) => {
  try { await store.setGiveawayStatus(req.params.id, 'closed'); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not end the giveaway.' }); }
});
// Adds the prize to every winner not yet paid (or one winner with entryId).
app.post('/api/admin/giveaways/:id/credit', requireAdmin, ADMIN_MONEY, async (req, res) => {
  try {
    const g = (await store.listGiveaways()).find(x => x.id === req.params.id);
    if (!g) return res.status(404).json({ error: 'Giveaway not found.' });
    const only = (req.body || {}).entryId;
    const todo = (await store.listEntries(g.id)).filter(e => e.won && !e.credited && (!only || e.id === only));
    let paid = 0;
    for (const e of todo) {
      await store.updateEntry(e.id, { credited: true });   // mark first so a double tap can never pay twice
      try { await store.addToBalance(e.userId, g.amount); paid++; notify(e.userId, 'trade', 'Giveaway prize added', `₦${plain(g.amount)} from the ${g.title} has been added to your balance.`, { go: 'home' }); }
      catch (err) { await store.updateEntry(e.id, { credited: false }).catch(() => {}); console.error('Giveaway credit error:', err.message); }
    }
    res.json({ ok: true, paid, total: paid * g.amount });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not credit the winners.' }); }
});

// ============================================================
// IN-APP CALLS (voice and video over the internet, WebRTC)
// The server only passes call setup messages between the two phones; the sound and video go phone to phone
// (or through a TURN relay when mobile networks block a direct link: set CF_TURN_KEY_ID + CF_TURN_API_TOKEN, or METERED_DOMAIN + METERED_API_KEY, on Render).
// Who can call whom: customer -> AZAPLUG Support (rings the admin and every chat manager);
// admin -> customers and staff; chat manager -> customers, vendors, admin; vendor -> chat managers, admin.
// ============================================================
const CALLS = new Map();
const RING_MS = 45000;
let iceCache = null;
async function iceServers() {
  if (iceCache && iceCache.exp > Date.now()) return iceCache.v;
  let v = [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }];
  if (process.env.CF_TURN_KEY_ID && process.env.CF_TURN_API_TOKEN) {   // Cloudflare TURN (1,000 GB free)
    try {
      const r = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(process.env.CF_TURN_KEY_ID)}/credentials/generate-ice-servers`, {
        method: 'POST', headers: { Authorization: `Bearer ${process.env.CF_TURN_API_TOKEN}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ ttl: 86400 })
      });
      if (r.ok) {
        const j = await r.json();
        // port 53 addresses often time out in browsers, so leave them out
        const list = (j.iceServers || []).map(x => ({ ...x, urls: [].concat(x.urls || []).filter(u => !/:53(\?|$)/.test(u)) })).filter(x => x.urls.length);
        if (list.length) { iceCache = { v: list, exp: Date.now() + 12 * 3600e3 }; return list; }
      } else console.error('Cloudflare TURN error:', r.status);
    } catch (err) { console.error('Cloudflare TURN error:', err.message); }
  }
  if (process.env.TURN_URLS) v.push({ urls: process.env.TURN_URLS.split(',').map(x => x.trim()), username: process.env.TURN_USERNAME, credential: process.env.TURN_CREDENTIAL });
  else if (process.env.METERED_DOMAIN && process.env.METERED_API_KEY) {
    try {
      const domain = process.env.METERED_DOMAIN.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      const r = await fetch(`https://${domain}/api/v1/turn/credentials?apiKey=${encodeURIComponent(process.env.METERED_API_KEY)}`);
      if (r.ok) { const j = await r.json(); if (Array.isArray(j) && j.length) v = j; }
      else console.error('TURN credentials error:', r.status);
    } catch (err) { console.error('TURN credentials error:', err.message); }
  }
  iceCache = { v, exp: Date.now() + (v.length > 1 ? 3600e3 : 300e3) };
  return v;
}
async function callMe(req) {
  const as = (req.body && req.body.as) || req.query.as;
  if (as === 'admin' && req.session.isAdmin) return { key: 'admin', kind: 'admin', name: 'Admin' };
  if (as === 'staff' && req.session.staffId) {
    const s = await store.findStaffById(req.session.staffId);
    if (s && s.status === 'approved') return { key: 's:' + s.id, kind: 'staff', id: s.id, role: s.role, name: s.name };
  }
  if (as === 'user' && req.session.userId) {
    const u = await store.findUserById(req.session.userId);
    if (u && u.status === 'approved') return { key: 'u:' + u.id, kind: 'user', id: u.id, name: u.name };
  }
  return null;
}
// Works out who a call rings, or returns { error }.
async function callTargets(me, to) {
  to = String(to || '');
  if (me.kind === 'user') {
    if (to !== 'support') return { error: 'You can call AZAPLUG Support.' };
    const chat = (await store.listStaff()).filter(s => s.status === 'approved' && s.role === 'chat').map(s => 's:' + s.id);
    return { keys: ['admin'].concat(chat), label: 'AZAPLUG Support', userId: me.id };
  }
  if (to === 'admin') {
    if (me.kind !== 'staff') return { error: 'Choose who to call.' };
    return { keys: ['admin'], label: 'Admin' };
  }
  if (to.startsWith('u:')) {
    if (!(me.kind === 'admin' || (me.kind === 'staff' && me.role === 'chat'))) return { error: 'Only the admin and chat managers can call customers.' };
    const u = await store.findUserById(to.slice(2));
    if (!u) return { error: 'Customer not found.' };
    return { keys: [to], label: u.name, userId: u.id };
  }
  if (to.startsWith('s:')) {
    const s = await store.findStaffById(to.slice(2));
    if (!s || s.status !== 'approved' || (me.kind === 'staff' && s.id === me.id)) return { error: 'Staff member not found.' };
    if (me.kind === 'staff' && !canTalk(me, s)) return { error: 'You can call the admin and ' + (me.role === 'chat' ? 'vendors' : 'chat managers') + '.' };
    return { keys: [to], label: s.name };
  }
  return { error: 'Choose who to call.' };
}
const inCall = key => [...CALLS.values()].some(c => (c.state === 'ringing' || c.state === 'active') && (c.from.key === key || c.by === key));
// What the other person sees as the caller's name. Customers always see "AZAPLUG Support" for staff and admin.
const shownName = (c, viewer) => (viewer.startsWith('u:') && c.from.kind !== 'user' ? 'AZAPLUG Support' : c.from.kind === 'admin' ? 'Admin' : c.from.name);
const mmss = ms => { const s = Math.max(1, Math.round(ms / 1000)); return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0'); };
function finishCall(c, state, by) {
  if (c.state === 'ended' || c.state === 'declined' || c.state === 'missed') return;
  const wasActive = c.state === 'active';
  c.state = wasActive ? 'ended' : state; c.endedAt = Date.now(); c.endedBy = by || null;
  if (c.userId) {   // leave a note in the customer chat, like WhatsApp
    const kind = c.video ? 'video' : 'voice';
    const text = wasActive ? `${c.video ? 'Video' : 'Voice'} call · ${mmss(c.endedAt - c.answeredAt)}` : `Missed ${kind} call`;
    store.addMessage({ userId: c.userId, sender: c.from.kind === 'user' ? 'user' : 'admin', text }).catch(err => console.error('Call note error:', err.message));
    if (!wasActive && c.from.kind !== 'user') notify(c.userId, 'chat', 'Missed call', `AZAPLUG Support tried to call you.`, { feed: false, go: 'chat' });
  }
}
setInterval(() => {
  const now = Date.now();
  for (const [id, c] of CALLS) {
    if (c.state === 'ringing' && now - c.created > RING_MS) finishCall(c, 'missed');
    if (c.state === 'active' && (now - c.seen.a > 25000 || now - c.seen.b > 25000)) finishCall(c, 'ended');   // a phone went offline
    if (c.endedAt && now - c.endedAt > 90000) CALLS.delete(id);
  }
}, 5000);
app.get('/api/call/ice', async (req, res) => {
  if (!(await callMe(req))) return res.status(401).json({ error: 'Please log in.' });
  res.json({ iceServers: await iceServers() });
});
app.post('/api/call/start', async (req, res) => {
  try {
    const me = await callMe(req); if (!me) return res.status(401).json({ error: 'Please log in.' });
    const b = req.body || {};
    if (!b.sdp || typeof b.sdp !== 'object' || b.sdp.type !== 'offer') return res.status(400).json({ error: 'Could not start the call.' });
    const t = await callTargets(me, b.to); if (t.error) return res.status(400).json({ error: t.error });
    if (inCall(me.key)) return res.status(409).json({ error: 'You are already on a call.' });
    const keys = t.keys.filter(k => k !== me.key);
    if (!keys.length) return res.status(400).json({ error: 'There is nobody to call right now.' });
    if (keys.length === 1 && inCall(keys[0])) return res.status(409).json({ error: `${t.label} is on another call. Try again soon.` });
    const id = crypto.randomUUID(), now = Date.now();
    const c = { id, from: me, keys, label: t.label, userId: t.userId || null, video: !!b.video, offer: b.sdp, answer: null, state: 'ringing', by: null, ice: { a: [], b: [] }, created: now, seen: { a: now, b: now } };
    CALLS.set(id, c);
    const title = c.video ? 'Incoming video call' : 'Incoming voice call';
    for (const k of keys) {
      const body = `${shownName(c, k)} is calling you`;
      if (k === 'admin') alertTeam({ admin: true }, title, body, { admin: 'dash' });
      else if (k.startsWith('s:')) alertTeam({ toStaff: k.slice(2) }, title, body, { staff: '' });
      else if (k.startsWith('u:')) notify(k.slice(2), 'chat', title, body, { feed: false, go: 'chat' });
    }
    res.json({ ok: true, id, label: t.label });
  } catch (err) { console.error('Call start error:', err); res.status(500).json({ error: 'Could not start the call.' }); }
});
app.get('/api/call/incoming', async (req, res) => {
  const me = await callMe(req); if (!me) return res.json({ calls: [] });
  const calls = [...CALLS.values()].filter(c => c.state === 'ringing' && c.keys.includes(me.key) && c.from.key !== me.key)
    .map(c => ({ id: c.id, name: shownName(c, me.key), video: c.video, offer: c.offer, fromKind: c.from.kind }));
  res.json({ calls });
});
function callSide(c, me) { if (c.from.key === me.key) return 'a'; if (c.by === me.key || (c.state === 'ringing' && c.keys.includes(me.key))) return 'b'; return null; }
app.get('/api/call/:id', async (req, res) => {
  const me = await callMe(req), c = CALLS.get(req.params.id);
  if (!me || !c) return res.json({ state: 'ended' });
  const side = callSide(c, me); if (!side) return res.json({ state: c.by ? 'answered-elsewhere' : 'ended' });
  c.seen[side] = Date.now();
  const other = side === 'a' ? 'b' : 'a', since = Math.max(0, Number(req.query.since) || 0);
  res.json({ state: c.state, answer: side === 'a' ? c.answer : null, ice: c.ice[other].slice(since), iceTotal: c.ice[other].length, answeredAt: c.answeredAt || null });
});
app.post('/api/call/:id/accept', async (req, res) => {
  const me = await callMe(req), c = CALLS.get(req.params.id);
  if (!me || !c) return res.status(404).json({ error: 'This call has ended.' });
  if (c.state !== 'ringing' || !c.keys.includes(me.key)) return res.status(409).json({ error: c.by ? 'Someone else answered this call.' : 'This call has ended.' });
  const sdp = (req.body || {}).sdp;
  if (!sdp || sdp.type !== 'answer') return res.status(400).json({ error: 'Could not answer the call.' });
  c.by = me.key; c.byName = me.name; c.answer = sdp; c.state = 'active'; c.answeredAt = Date.now(); c.seen.b = Date.now();
  res.json({ ok: true });
});
app.post('/api/call/:id/decline', async (req, res) => {
  const me = await callMe(req), c = CALLS.get(req.params.id);
  if (!me || !c || c.state !== 'ringing') return res.json({ ok: true });
  c.keys = c.keys.filter(k => k !== me.key);   // a support call keeps ringing the others
  if (!c.keys.length) finishCall(c, 'declined', me.key);
  res.json({ ok: true });
});
app.post('/api/call/:id/ice', async (req, res) => {
  const me = await callMe(req), c = CALLS.get(req.params.id);
  if (!me || !c) return res.json({ ok: false });
  const side = callSide(c, me), cand = (req.body || {}).c;
  if (side && cand && typeof cand === 'object' && c.ice[side].length < 200) c.ice[side].push(cand);
  res.json({ ok: true });
});
app.post('/api/call/:id/end', async (req, res) => {
  const me = await callMe(req), c = CALLS.get(req.params.id);
  if (me && c && callSide(c, me)) finishCall(c, c.state === 'ringing' ? 'missed' : 'ended', me.key);
  res.json({ ok: true });
});

// ---- Background storage jobs
// 1) Move old pictures out of the database into Storage, a few at a time.
// 2) Remove chat photos and voice notes older than MEDIA_DAYS (default 90). Receipts are never removed.
const MEDIA_DAYS = Math.max(7, Number(process.env.MEDIA_DAYS) || 90);
async function mediaJobs() {
  try {
    let total = 0;
    for (let i = 0; i < 40; i++) { const r = await store.migrateMediaBatch(); total += r.moved; if (!r.left) break; }
    if (total) console.log(`Moved ${total} pictures from the database to Storage.`);
    const removed = await store.cleanOldChatMedia(MEDIA_DAYS);
    if (removed) console.log(`Removed ${removed} chat photos/voice notes older than ${MEDIA_DAYS} days.`);
  } catch (err) { console.error('Storage job error:', err.message || err); }
}
setTimeout(mediaJobs, 20000);
setInterval(mediaJobs, 30 * 60000);

app.listen(PORT, () => {
  console.log(`\nRECIO EXCHANGE backend running at http://localhost:${PORT}`);
  console.log(`Staff portal at                http://localhost:${PORT}/staff-login.html`);
  console.log(`Admin dashboard at             http://localhost:${PORT}/admin.html\n`);
});
