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
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

if (!process.env.ADMIN_PASSWORD) {
  console.warn('\n⚠️  ADMIN_PASSWORD is not set in .env — using the default "changeme123". Change this before going live.\n');
}

app.use(express.json({ limit: '10mb' })); // receipts + settlement screenshots travel as base64
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 30 }
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
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    if (await store.findUserByPhone(String(phone).trim())) {
      return res.status(409).json({ error: 'An account with this phone number already exists.' });
    }
    const user = await store.createUser({
      name: String(name).trim(), phone: String(phone).trim(),
      accountNumber: String(accountNumber).trim(), bankName: String(bankName).trim(),
      passwordHash: bcrypt.hashSync(password, 10)
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
    const user = await store.findUserByPhone(String(phone || '').trim());
    if (!user || !bcrypt.compareSync(String(password || ''), user.passwordHash)) {
      return res.status(401).json({ error: 'Incorrect phone number or password.' });
    }
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
      bankName: user.bankName, status: user.status, balance: user.balance
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
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    if (await store.findStaffByPhone(String(phone).trim())) {
      return res.status(409).json({ error: 'A staff account with this phone number already exists.' });
    }
    const staff = await store.createStaff({
      name: String(name).trim(), phone: String(phone).trim(), passwordHash: bcrypt.hashSync(password, 10)
    });
    req.session.staffId = staff.id;
    res.json({ ok: true, status: staff.status });
  } catch (err) {
    console.error('Staff register error:', err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/staff/login', async (req, res) => {
  try {
    const { phone, password } = req.body || {};
    const staff = await store.findStaffByPhone(String(phone || '').trim());
    if (!staff || !bcrypt.compareSync(String(password || ''), staff.passwordHash)) {
      return res.status(401).json({ error: 'Incorrect phone number or password.' });
    }
    req.session.staffId = staff.id;
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
    res.json({ loggedIn: true, name: staff.name, phone: staff.phone, status: staff.status });
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
    res.json({ ok: true, trade });
  } catch (err) {
    console.error('Create trade error:', err);
    res.status(500).json({ error: 'Could not submit your receipt.' });
  }
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
app.get('/api/chat/messages', requireUser, async (req, res) => {
  try { res.json({ messages: await store.messagesForUser(req.session.userId) }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load messages.' }); }
});
app.post('/api/chat/send', requireUser, async (req, res) => {
  try {
    const { text, imageData } = req.body || {};
    if (!text && !imageData) return res.status(400).json({ error: 'Message is empty.' });
    const msg = await store.addMessage({ userId: req.session.userId, sender: 'user', text, imageData });
    res.json({ ok: true, message: msg });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not send message.' }); }
});

// ============================================================
// STAFF: own accounts
// ============================================================
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
    res.json({ user: { id: user.id, name: user.name, phone: user.phone }, messages: await store.messagesForUser(req.params.userId) });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Could not load conversation.' }); }
});
app.post('/api/staff/chats/:userId/send', requireStaff, requireApprovedStaff, async (req, res) => {
  try {
    const { text, imageData } = req.body || {};
    if (!text && !imageData) return res.status(400).json({ error: 'Message is empty.' });
    const user = await store.findUserById(req.params.userId);
    if (!user) return res.status(404).json({ error: 'Customer not found.' });
    const msg = await store.addMessage({ userId: user.id, sender: 'admin', text, imageData });
    notify(user.id, 'chat', 'AZAPLUG Support', text ? String(text).slice(0, 140) : 'Sent you a photo', { feed: false, go: 'chat' });
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

// ============================================================
// ADMIN: users
// ============================================================
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try { res.json({ users: await store.listUsers() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load users.' }); }
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
  try { res.json({ staff: await store.listStaff() }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not load staff.' }); }
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
    const before = await store.findAccountById(req.params.id);
    await store.updateAccount(req.params.id, req.body || {});
    if ((req.body || {}).active === false) notifyAccountGone(before); // un-verified = hidden from customers
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
    await store.addToBalance(trade.userId, Number(creditedAmount));
    notify(trade.userId, 'tx', 'Balance credited', `₦${plain(creditedAmount)} has been added to your balance for your ${trade.accountTitleUsed || ''} receipt.`.replace('  ', ' '));
    res.json({ ok: true });
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
  try { await store.updateSettings(req.body || {}); res.json({ ok: true }); }
  catch (err) { console.error(err); res.status(500).json({ error: 'Could not update settings.' }); }
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
    const msg = await store.addMessage({ userId: req.params.userId, sender: 'admin', text, imageData });
    notify(req.params.userId, 'chat', 'AZAPLUG Support', text ? String(text).slice(0, 140) : 'Sent you a photo', { feed: false, go: 'chat' });
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
async function sendPush(subs, payload) {
  if (!subs.length || !(await pushKeys())) return;
  await Promise.all(subs.map(s =>
    webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, JSON.stringify(payload), { TTL: 86400 })
      .catch(err => {
        // 404 / 410 = the browser dropped this subscription; forget it.
        if (err.statusCode === 404 || err.statusCode === 410) return store.deletePushSubscription(s.endpoint).catch(() => {});
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
// STATIC PAGES
// ============================================================
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`\nRECIO EXCHANGE backend running at http://localhost:${PORT}`);
  console.log(`Staff portal at                http://localhost:${PORT}/staff-login.html`);
  console.log(`Admin dashboard at             http://localhost:${PORT}/admin.html\n`);
});
