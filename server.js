require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const store = require('./storage');

const app = express();
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
const SESSION_DAYS = 60;
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
    const exp = new Date(Date.now() + SESSION_DAYS * 864e5).toISOString();
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
  cookie: { maxAge: 864e5 * SESSION_DAYS, sameSite: 'lax' }
}));

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
    const user = await store.findUserByPhone(String(phone || '').trim());
    if (!user || !bcrypt.compareSync(String(password || ''), user.passwordHash)) {
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
    await store.updateUser(req.session.userId, {
      name: String(name).trim(), bankName: String(bankName).trim(), accountNumber: String(accountNumber).trim()
    });
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
    const staff = await store.findStaffByPhone(String(phone || '').trim());
    if (!staff || !bcrypt.compareSync(String(password || ''), staff.passwordHash)) {
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
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body || {};
  if (password !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Wrong admin password.' });
  req.session.isAdmin = true;
  res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => { req.session.isAdmin = false; res.json({ ok: true }); });

// ============================================================
// LOGIN EXTRAS: 6-digit PIN, email codes, forgot PIN, fingerprint
// ============================================================
// --- PIN rules
function badPin(pin) {
  const p = String(pin || '');
  if (!/^\d{6}$/.test(p)) return 'Your PIN must be exactly 6 digits.';
  if (/^(\d)\1{5}$/.test(p) || '0123456789012345'.includes(p) || '9876543210987654'.includes(p)) return 'That PIN is too easy to guess. Choose another one.';
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
async function issueCode(key, email, extra) {
  const old = codes.get(key);
  if (old && old.email === email && Date.now() - old.sentAt < 45000) return false;   // one was just sent: keep using it
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
const passOwner = (req, kind) => (kind === 'admin' ? (req.session.isAdmin ? 'admin' : null) : kind === 'staff' ? req.session.staffId : req.session.userId) || null;
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
    if (!pk || pk.kind !== passKind(req.body)) return res.status(404).json({ error: 'Fingerprint login is no longer set up on this phone.', gone: true });
    const options = await webauthn.generateAuthenticationOptions({ rpID: rpOf(req).rpID, allowCredentials: [{ id: pk.id }], userVerification: 'required' });
    req.session.wa = { c: options.challenge, kind: pk.kind };
    res.json(options);
  } catch (err) { console.error('Passkey login options error:', err); res.status(500).json({ error: 'Fingerprint login is not available right now.' }); }
});
app.post('/api/passkey/login/verify', async (req, res) => {
  try {
    const wa = req.session.wa; req.session.wa = null;
    const pk = await store.findPasskey(String(((req.body || {}).response || {}).id || ''));
    if (!wa || !pk || pk.kind !== wa.kind) return res.status(400).json({ error: 'Start again.' });
    const rp = rpOf(req);
    const v = await webauthn.verifyAuthenticationResponse({
      response: req.body.response, expectedChallenge: wa.c, expectedOrigin: rp.origins, expectedRPID: rp.rpID, requireUserVerification: true,
      credential: { id: pk.id, publicKey: new Uint8Array(Buffer.from(pk.publicKey, 'base64url')), counter: pk.counter }
    });
    if (!v.verified) return res.status(401).json({ error: 'Your phone did not confirm it. Use your PIN.' });
    store.updatePasskeyCounter(pk.id, v.authenticationInfo.newCounter).catch(() => {});
    if (pk.kind === 'admin') { req.session.isAdmin = true; return res.json({ ok: true }); }
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
    if (typeof receiptImage !== 'string' || !/^data:image\//i.test(receiptImage)) return res.status(400).json({ error: 'Add a screenshot of your transfer.' });
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
app.post('/api/withdrawals', requireUser, requireApprovedUser, async (req, res) => {
  try {
    const amount = Number((req.body || {}).amount);
    if (!amount || amount <= 0) return res.status(400).json({ error: 'Enter a valid amount.' });
    const user = await store.findUserById(req.user.id);
    if (amount > user.balance) return res.status(400).json({ error: 'You cannot withdraw more than your balance.' });

    const withdrawal = await store.createWithdrawal({
      userId: user.id, amount, payoutAccount: user.accountNumber, payoutBank: user.bankName
    });
    await store.addToBalance(user.id, -amount); // hold the funds until this is paid or rejected
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
  if (typeof data !== 'string' || !/^data:(image|audio)\/[a-z0-9.+-]+[;,]/i.test(data)) return 'Only photos and voice notes can be sent.';
  if (/^data:audio\//i.test(data) && data.length > 2500000) return 'That voice note is too long. Keep it under 2 minutes.';
  return null;
}
const isVoice = d => typeof d === 'string' && /^data:audio\//i.test(d);

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
    await store.updateAccount(req.params.id, b);
    res.json({ ok: true });
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

app.post('/api/staff/trades/:id/mark', requireStaff, requireApprovedStaff, async (req, res) => {
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
app.get('/api/staff/chats', requireStaff, requireApprovedStaff, async (req, res) => {
  try { res.json({ conversations: await store.listConversations() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversations.' }); }
});
app.get('/api/staff/chats/:userId', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const user = await store.findUserById(req.params.userId);
    if (!user) return res.status(404).json({ error: 'Customer not found.' });
    res.json({ user: { id: user.id, name: user.name, phone: user.phone }, messages: await store.messagesForUser(req.params.userId), routed: await routedFor(req.params.userId) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversation.' }); }
});
// Which chat photos were already turned into receipts: { messageId: { title, status, amount } }
async function routedFor(userId) {
  const out = {};
  try { (await store.listTradesForUser(userId)).forEach(t => { if (t.chatMessageId) out[t.chatMessageId] = { title: t.accountTitleUsed, status: t.status, amount: t.intendedAmount }; }); } catch (err) {}
  return out;
}
// Accounts a chat manager can send a chat receipt to.
app.get('/api/staff/route-accounts', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const [accounts, staffList] = await Promise.all([store.listAllAccounts(), store.listStaff()]);
    res.json({ accounts: accounts.filter(a => a.active).map(a => ({ id: a.id, title: a.title, bankName: a.bankName, accountNumber: a.accountNumber, staffName: (staffList.find(s => s.id === a.staffId) || {}).name || 'Admin' })) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load accounts.' }); }
});
// Chat manager turns a receipt photo from the chat into a receipt on the account the customer paid into.
app.post('/api/staff/chats/:userId/route', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const { messageId, accountId, amount } = req.body || {}, n = Number(amount);
    const [user, msg, account] = await Promise.all([store.findUserById(req.params.userId), store.findMessageById(messageId), store.findAccountById(accountId)]);
    if (!user) return res.status(404).json({ error: 'Customer not found.' });
    if (!msg || msg.userId !== user.id || msg.sender !== 'user' || !/^data:image\//i.test(msg.imageData || '')) return res.status(400).json({ error: 'Pick a receipt photo the customer sent.' });
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
app.delete('/api/staff/chats/:userId/messages/:id', requireStaff, requireApprovedStaff, teamDeleteMessage);
app.delete('/api/admin/chats/:userId/messages/:id', requireAdmin, teamDeleteMessage);
app.post('/api/staff/chats/:userId/send', requireStaff, requireApprovedStaff, async (req, res) => {
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
app.get('/api/staff/escalations', requireStaff, requireApprovedStaff, async (req, res) => {
  try { res.json({ escalations: await escalationsWithNames() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load escalations.' }); }
});
app.post('/api/staff/chats/:userId/escalate', requireStaff, requireApprovedStaff, async (req, res) => {
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
app.get('/api/staff/recipients', requireStaff, requireApprovedStaff, async (req, res) => {
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
const teamOut = (m, me) => ({ id: m.id, sender: m.fromStaffId === me ? 'me' : 'them', text: m.text, imageData: m.imageData, createdAt: m.createdAt });
app.get('/api/staff/team', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    if (!(await teamCheck(req, res))) return;
    const me = req.staff.id;
    const [staff, msgs] = await Promise.all([store.listStaff(), store.listTeamMessagesFor(me)]);
    const people = staff.filter(s => s.status === 'approved' && s.id !== me && canTalk(req.staff, s)).map(s => {
      const mine = msgs.filter(m => m.fromStaffId === s.id || m.toStaffId === s.id), last = mine[mine.length - 1];
      return { id: s.id, name: s.name, unread: mine.filter(m => m.fromStaffId === s.id && !m.readAt).length,
        lastMessage: last ? (last.imageData ? (isVoice(last.imageData) ? '🎤 Voice note' : '📷 Photo') : last.text) : '', lastAt: last ? last.createdAt : null, lastMine: last ? last.fromStaffId === me : false };
    }).sort((a, b) => String(b.lastAt || '').localeCompare(String(a.lastAt || '')) || a.name.localeCompare(b.name));
    res.json({ people, unread: people.reduce((n, p) => n + p.unread, 0) });
  } catch (err) { if (!teamSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || 'Could not load team messages.' }); }
});
app.get('/api/staff/team/:id', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    if (!(await teamCheck(req, res))) return;
    const me = req.staff.id, other = await store.findStaffById(req.params.id);
    if (!other || other.status !== 'approved' || other.id === me || !canTalk(req.staff, other)) return res.status(404).json({ error: 'You can only message ' + (req.staff.role === 'chat' ? 'vendors' : 'chat managers') + '.' });
    const msgs = (await store.listTeamMessagesFor(me)).filter(m => m.fromStaffId === other.id || m.toStaffId === other.id);
    if (msgs.some(m => m.fromStaffId === other.id && !m.readAt)) await store.markTeamRead(me, other.id);
    res.json({ person: { id: other.id, name: other.name, phone: other.phone }, messages: msgs.map(m => teamOut(m, me)) });
  } catch (err) { if (!teamSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || 'Could not load messages.' }); }
});
app.post('/api/staff/team/:id/send', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    if (!(await teamCheck(req, res))) return;
    const me = req.staff.id, other = await store.findStaffById(req.params.id);
    if (!other || other.status !== 'approved' || other.id === me || !canTalk(req.staff, other)) return res.status(404).json({ error: 'You can only message ' + (req.staff.role === 'chat' ? 'vendors' : 'chat managers') + '.' });
    const text = String((req.body || {}).text || '').trim().slice(0, 4000), imageData = (req.body || {}).imageData || null;
    if (!text && !imageData) return res.status(400).json({ error: 'Message is empty.' });
    if (badAttachment(imageData)) return res.status(400).json({ error: badAttachment(imageData) });
    const m = await store.addTeamMessage({ fromStaffId: me, toStaffId: other.id, text, imageData });
    alertTeam({ toStaff: other.id }, `Message from ${req.staff.name}`, text ? text.slice(0, 120) : isVoice(imageData) ? 'Sent you a voice note' : 'Sent you a photo', { staff: 'team' });
    res.json({ ok: true, message: teamOut(m, me) });
  } catch (err) { if (!teamSqlHint(err)) console.error(err); res.status(500).json({ error: teamSqlHint(err) || 'Could not send the message.' }); }
});
app.delete('/api/staff/team/:id/messages/:mid', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const m = await store.findTeamMessage(req.params.mid);
    if (!m || m.fromStaffId !== req.staff.id) return res.status(404).json({ error: 'You can only delete your own messages.' });
    await store.deleteTeamMessage(m.id); res.json({ ok: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not delete the message.' }); }
});

// ---- Forward one chat message to one person (the admin or another staff member)
const forwardSqlHint = err => (/forwards/.test(String(err && err.message)) ? 'Run the forwarded messages SQL from the README in Supabase first.' : null);
app.post('/api/staff/chats/:userId/forward-message', requireStaff, requireApprovedStaff, async (req, res) => {
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

app.post('/api/admin/trades/:id/mark', requireAdmin, async (req, res) => {
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
app.post('/api/admin/trades/:id/credit', requireAdmin, async (req, res) => {
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
      userPhone: (users.find(u => u.id === w.userId) || {}).phone || ''
    }));
    res.json({ withdrawals: enriched });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load withdrawals.' }); }
});

app.post('/api/admin/withdrawals/:id/mark', requireAdmin, async (req, res) => {
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
  try { res.json({ conversations: await store.listConversations() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversations.' }); }
});
app.get('/api/admin/chats/:userId', requireAdmin, async (req, res) => {
  try {
    const user = await store.findUserById(req.params.userId);
    res.json({ user, messages: await store.messagesForUser(req.params.userId) });
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
    if (!b.endpoint || !/^https:\/\//.test(b.endpoint) || !k.p256dh || !k.auth) return res.status(400).json({ error: 'Invalid subscription.' });
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
function validSub(b) { const k = (b || {}).keys || {}; return b && b.endpoint && /^https:\/\//.test(b.endpoint) && k.p256dh && k.auth; }
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
app.post('/api/loans', requireUser, requireApprovedUser, async (req, res) => {
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
app.post('/api/admin/loans/:id/decide', requireAdmin, async (req, res) => {
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
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, file) { if (/\.(html|js|webmanifest)$/.test(file)) res.setHeader('Cache-Control', 'no-cache'); }
}));

app.listen(PORT, () => {
  console.log(`\nRECIO EXCHANGE backend running at http://localhost:${PORT}`);
  console.log(`Staff portal at                http://localhost:${PORT}/staff-login.html`);
  console.log(`Admin dashboard at             http://localhost:${PORT}/admin.html\n`);
});
