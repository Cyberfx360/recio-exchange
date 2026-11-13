// storage.js
// All data lives in Supabase — required for this project.

const crypto = require('crypto');

if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error('\n❌ SUPABASE_URL / SUPABASE_SERVICE_KEY are missing from your .env file.');
  console.error('   Set up Supabase first — see README.md.\n');
  process.exit(1);
}

const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function uid() { return crypto.randomUUID(); }

// ============================================================
// USERS (customers)
// ============================================================

function userRow(r) {
  return {
    id: r.id, name: r.name, phone: r.phone,
    accountNumber: r.account_number, bankName: r.bank_name,
    passwordHash: r.password_hash, status: r.status, email: r.email == null ? null : r.email,
    balance: Number(r.balance), createdAt: r.created_at
  };
}

async function createUser({ name, phone, accountNumber, bankName, passwordHash, email }) {
  const id = uid();
  const { error } = await supabase.from('users').insert({
    id, name, phone, account_number: accountNumber, bank_name: bankName,
    password_hash: passwordHash, status: 'approved', balance: 0, ...(email !== undefined ? { email } : {})
  });
  if (error) throw error;
  return findUserById(id);
}
async function findUserByPhone(phone) {
  const { data, error } = await supabase.from('users').select('*').eq('phone', phone).maybeSingle();
  if (error) throw error;
  return data ? userRow(data) : null;
}
async function findUserById(id) {
  const { data, error } = await supabase.from('users').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? userRow(data) : null;
}
async function listUsers() {
  const { data, error } = await supabase.from('users').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(userRow);
}
async function setUserStatus(id, status) {
  const { error } = await supabase.from('users').update({ status }).eq('id', id);
  if (error) throw error;
}
async function updateUser(id, fields) {
  const patch = {};
  if (fields.name !== undefined) patch.name = fields.name;
  if (fields.bankName !== undefined) patch.bank_name = fields.bankName;
  if (fields.accountNumber !== undefined) patch.account_number = fields.accountNumber;
  const { error } = await supabase.from('users').update(patch).eq('id', id);
  if (error) throw error;
}
// Clears rows in a table that may not exist on older setups (so a missing table never blocks a delete).
async function clearOptional(table, column, id, setNull) {
  try {
    const q = setNull ? supabase.from(table).update({ [column]: null }).eq(column, id) : supabase.from(table).delete().eq(column, id);
    const { error } = await q;
    if (error) console.error(`Cleanup of ${table} skipped:`, error.message);
  } catch (err) { console.error(`Cleanup of ${table} skipped:`, err.message); }
}
// Deleting a customer removes everything that belongs to them first (receipts, withdrawals, chat,
// loans, notifications) — otherwise the database refuses to delete the user.
async function deleteUser(id) {
  for (const table of ['withdrawals', 'messages', 'trades']) {
    const r = await supabase.from(table).delete().eq('user_id', id);
    if (r.error) throw r.error;
  }
  for (const table of ['escalations', 'loans', 'notifications', 'push_subscriptions']) await clearOptional(table, 'user_id', id);
  const { error } = await supabase.from('users').delete().eq('id', id);
  if (error) throw error;
}
async function addToBalance(id, amount) {
  const user = await findUserById(id);
  if (!user) return;
  const { error } = await supabase.from('users').update({ balance: user.balance + amount }).eq('id', id);
  if (error) throw error;
}

// ============================================================
// STAFF
// ============================================================

function staffRow(r) {
  return { id: r.id, name: r.name, phone: r.phone, passwordHash: r.password_hash, status: r.status, email: r.email == null ? null : r.email, role: r.role || null, createdAt: r.created_at };
}
async function createStaff({ name, phone, passwordHash, email, role }) {
  const id = uid();
  const { error } = await supabase.from('staff').insert({ id, name, phone, password_hash: passwordHash, status: 'pending', ...(email !== undefined ? { email } : {}), ...(role ? { role } : {}) });
  if (error) throw error;
  return findStaffById(id);
}
async function findStaffByPhone(phone) {
  const { data, error } = await supabase.from('staff').select('*').eq('phone', phone).maybeSingle();
  if (error) throw error;
  return data ? staffRow(data) : null;
}
async function findStaffById(id) {
  const { data, error } = await supabase.from('staff').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? staffRow(data) : null;
}
async function listStaff() {
  const { data, error } = await supabase.from('staff').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(staffRow);
}
async function setStaffStatus(id, status) {
  const { error } = await supabase.from('staff').update({ status }).eq('id', id);
  if (error) throw error;
}
// Deleting a staff member keeps their accounts and receipts: they are handed back to the admin.
async function deleteStaff(id) {
  for (const table of ['accounts', 'trades']) {
    const r = await supabase.from(table).update({ staff_id: null }).eq('staff_id', id);
    if (r.error) throw r.error;
  }
  await clearOptional('escalations', 'staff_id', id, true);
  await clearOptional('team_push_subscriptions', 'staff_id', id);
  await clearOptional('team_messages', 'from_staff_id', id);
  await clearOptional('team_messages', 'to_staff_id', id);
  const { error } = await supabase.from('staff').delete().eq('id', id);
  if (error) throw error;
}

// ============================================================
// ACCOUNTS (the country-labeled deposit accounts)
// ============================================================

function accountRow(r) {
  return {
    id: r.id, staffId: r.staff_id, title: r.title,
    accountNumber: r.account_number, bankName: r.bank_name, imageData: r.image_data,
    lowestAmount: Number(r.lowest_amount), lowestRate: Number(r.lowest_rate),
    higherAmount: Number(r.higher_amount), higherRate: Number(r.higher_rate),
    minAmount: Number(r.min_amount), maxAmount: Number(r.max_amount),
    active: r.active, createdAt: r.created_at, updatedAt: r.updated_at
  };
}
async function listAccountsPublic() {
  const { data, error } = await supabase.from('accounts').select('*').eq('active', true).order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(accountRow);
}
async function listAccountsForAmount(amount) {
  const { data, error } = await supabase.from('accounts').select('*')
    .eq('active', true).lte('min_amount', amount).gte('max_amount', amount)
    .order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(accountRow);
}
async function listAllAccounts() {
  const { data, error } = await supabase.from('accounts').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(accountRow);
}
async function listAccountsByStaff(staffId) {
  const { data, error } = await supabase.from('accounts').select('*').eq('staff_id', staffId).order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(accountRow);
}
async function findAccountById(id) {
  const { data, error } = await supabase.from('accounts').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? accountRow(data) : null;
}
async function createAccount(a) {
  const id = uid();
  const { error } = await supabase.from('accounts').insert({
    id, staff_id: a.staffId || null, title: a.title, account_number: a.accountNumber, bank_name: a.bankName,
    image_data: a.imageData || null, lowest_amount: a.lowestAmount, lowest_rate: a.lowestRate,
    higher_amount: a.higherAmount, higher_rate: a.higherRate, min_amount: a.minAmount, max_amount: a.maxAmount,
    active: a.active !== undefined ? a.active : true
  });
  if (error) throw error;
  return findAccountById(id);
}
async function updateAccount(id, a) {
  const patch = { updated_at: new Date().toISOString() };
  var map = { title:'title', accountNumber:'account_number', bankName:'bank_name', imageData:'image_data',
    lowestAmount:'lowest_amount', lowestRate:'lowest_rate', higherAmount:'higher_amount', higherRate:'higher_rate',
    minAmount:'min_amount', maxAmount:'max_amount', active:'active', staffId:'staff_id' };
  Object.keys(map).forEach(function(k){
    if (a[k] === undefined) return;
    patch[map[k]] = a[k];
  });
  const { error } = await supabase.from('accounts').update(patch).eq('id', id);
  if (error) throw error;
}
// Deleting an account keeps its receipts: each one already stores the account title and number it used.
async function deleteAccount(id) {
  const r = await supabase.from('trades').update({ account_id: null }).eq('account_id', id);
  if (r.error) throw r.error;
  const { error } = await supabase.from('accounts').delete().eq('id', id);
  if (error) throw error;
}

// ============================================================
// TRADES
// ============================================================

function tradeRow(r) {
  return {
    id: r.id, userId: r.user_id, accountId: r.account_id, staffId: r.staff_id,
    intendedAmount: Number(r.intended_amount), creditedAmount: r.credited_amount === null ? null : Number(r.credited_amount),
    staffCreditedAmount: r.staff_credited_amount === null ? null : Number(r.staff_credited_amount),
    receiptImage: r.receipt_image,
    status: r.status, failReason: r.fail_reason, failImage: r.fail_image,
    accountNumberUsed: r.account_number_used, accountTitleUsed: r.account_title_used,
    userPayoutAccount: r.user_payout_account, userPayoutBank: r.user_payout_bank,
    settlementScreenshot: r.settlement_screenshot, settlementStatus: r.settlement_status,
    chatMessageId: r.chat_message_id || null,   // set when a chat manager turned a chat photo into this receipt
    createdAt: r.created_at, updatedAt: r.updated_at
  };
}
async function createTrade(t) {
  const id = uid();
  const { error } = await supabase.from('trades').insert({
    id, user_id: t.userId, account_id: t.accountId, staff_id: t.staffId,
    intended_amount: t.intendedAmount, receipt_image: t.receiptImage,
    status: 'checking', account_number_used: t.accountNumberUsed, account_title_used: t.accountTitleUsed,
    user_payout_account: t.userPayoutAccount, user_payout_bank: t.userPayoutBank,
    settlement_status: 'pending',
    ...(t.chatMessageId ? { chat_message_id: t.chatMessageId } : {})
  });
  if (error) throw error;
  return findTradeById(id);
}
async function findTradeById(id) {
  const { data, error } = await supabase.from('trades').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? tradeRow(data) : null;
}
async function listTradesForUser(userId) {
  const { data, error } = await supabase.from('trades').select('*').eq('user_id', userId).order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(tradeRow);
}
async function listTradesForStaff(staffId) {
  const { data, error } = await supabase.from('trades').select('*').eq('staff_id', staffId).order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(tradeRow);
}
async function listAllTrades() {
  const { data, error } = await supabase.from('trades').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(tradeRow);
}
async function updateTradeStatus(id, opts) {
  const patch = { status: opts.status, updated_at: new Date().toISOString() };
  if (opts.failReason !== undefined) patch.fail_reason = opts.failReason;
  if (opts.failImage !== undefined) patch.fail_image = opts.failImage;
  if (opts.creditedAmount !== undefined) patch.credited_amount = opts.creditedAmount;
  if (opts.staffCreditedAmount !== undefined) patch.staff_credited_amount = opts.staffCreditedAmount;
  if (opts.userPayoutAccount !== undefined) patch.user_payout_account = opts.userPayoutAccount;
  if (opts.userPayoutBank !== undefined) patch.user_payout_bank = opts.userPayoutBank;
  const { error } = await supabase.from('trades').update(patch).eq('id', id);
  if (error) throw error;
}
async function setSettlement(id, screenshot) {
  const { error } = await supabase.from('trades').update({
    settlement_screenshot: screenshot, settlement_status: 'done', updated_at: new Date().toISOString()
  }).eq('id', id);
  if (error) throw error;
}

// ============================================================
// SETTINGS (single row)
// ============================================================

async function getSettings() {
  const { data, error } = await supabase.from('settings').select('*').eq('id', 1).maybeSingle();
  if (error) throw error;
  if (!data) {
    const defaults = {
      id: 1, rules_text: 'No scam money allowed. We do not support scam money.',
      settlement_account: '', settlement_bank: '', max_deposit: 3000000
    };
    await supabase.from('settings').insert(defaults);
    return { rulesText: defaults.rules_text, settlementAccount: '', settlementBank: '', maxDeposit: 3000000, btcRate: 0, usdtRate: 0 };
  }
  return {
    rulesText: data.rules_text, settlementAccount: data.settlement_account,
    settlementBank: data.settlement_bank, maxDeposit: Number(data.max_deposit),
    btcRate: Number(data.btc_rate) || 0, usdtRate: Number(data.usdt_rate) || 0   // naira for 1 BTC / 1 USDT; 0 = not set
  };
}
async function updateSettings(fields) {
  const patch = {};
  if (fields.rulesText !== undefined) patch.rules_text = fields.rulesText;
  if (fields.settlementAccount !== undefined) patch.settlement_account = fields.settlementAccount;
  if (fields.settlementBank !== undefined) patch.settlement_bank = fields.settlementBank;
  if (fields.maxDeposit !== undefined) patch.max_deposit = fields.maxDeposit;
  if (fields.btcRate !== undefined) patch.btc_rate = fields.btcRate;
  if (fields.usdtRate !== undefined) patch.usdt_rate = fields.usdtRate;
  if (!Object.keys(patch).length) return;
  const { error } = await supabase.from('settings').update(patch).eq('id', 1);
  if (error) throw error;
}

// ============================================================
// CHAT (customer <-> admin)
// ============================================================

function msgRow(r) {
  return { id: r.id, userId: r.user_id, sender: r.sender, text: r.text, imageData: r.image_data, createdAt: r.created_at };
}
async function addMessage(m) {
  const id = uid();
  const { error } = await supabase.from('messages').insert({
    id, user_id: m.userId, sender: m.sender, text: m.text || '', image_data: m.imageData || null
  });
  if (error) throw error;
  const { data } = await supabase.from('messages').select('*').eq('id', id).single();
  return msgRow(data);
}
async function messagesForUser(userId) {
  const { data, error } = await supabase.from('messages').select('*').eq('user_id', userId).order('created_at', { ascending: true });
  if (error) throw error;
  return data.map(msgRow);
}
async function findMessageById(id) {
  const { data, error } = await supabase.from('messages').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? msgRow(data) : null;
}
async function deleteMessage(id) {
  const { error } = await supabase.from('messages').delete().eq('id', id);
  if (error) throw error;
}
async function listConversations() {
  const { data, error } = await supabase.from('messages').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  const seen = new Map();
  for (const m of data) if (!seen.has(m.user_id)) seen.set(m.user_id, m);
  const users = await Promise.all([...seen.keys()].map(findUserById));
  return [...seen.entries()].map(function(entry) {
    var userId = entry[0], lastMsg = entry[1];
    const user = users.find(function(u){ return u && u.id === userId; });
    return {
      userId: userId, name: user ? user.name : 'Unknown', phone: user ? user.phone : '',
      lastMessage: lastMsg.image_data ? (/^data:audio\//i.test(lastMsg.image_data) ? '🎤 Voice note' : '📷 Photo') : lastMsg.text,
      lastSender: lastMsg.sender, lastAt: lastMsg.created_at
    };
  });
}

// ============================================================
// WITHDRAWALS
// ============================================================

function withdrawalRow(r) {
  return {
    id: r.id, userId: r.user_id, amount: Number(r.amount),
    payoutAccount: r.payout_account, payoutBank: r.payout_bank,
    status: r.status, reason: r.reason, reasonImage: r.reason_image,
    createdAt: r.created_at, updatedAt: r.updated_at
  };
}
async function createWithdrawal(w) {
  const id = uid();
  const { error } = await supabase.from('withdrawals').insert({
    id, user_id: w.userId, amount: w.amount,
    payout_account: w.payoutAccount, payout_bank: w.payoutBank, status: 'pending'
  });
  if (error) throw error;
  const { data } = await supabase.from('withdrawals').select('*').eq('id', id).single();
  return withdrawalRow(data);
}
async function findWithdrawalById(id) {
  const { data, error } = await supabase.from('withdrawals').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? withdrawalRow(data) : null;
}
async function listWithdrawalsForUser(userId) {
  const { data, error } = await supabase.from('withdrawals').select('*').eq('user_id', userId).order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(withdrawalRow);
}
async function listAllWithdrawals() {
  const { data, error } = await supabase.from('withdrawals').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(withdrawalRow);
}
async function updateWithdrawalStatus(id, opts) {
  const patch = { status: opts.status, updated_at: new Date().toISOString() };
  if (opts.reason !== undefined) patch.reason = opts.reason;
  if (opts.reasonImage !== undefined) patch.reason_image = opts.reasonImage;
  if (opts.payoutAccount !== undefined) patch.payout_account = opts.payoutAccount;
  if (opts.payoutBank !== undefined) patch.payout_bank = opts.payoutBank;
  const { error } = await supabase.from('withdrawals').update(patch).eq('id', id);
  if (error) throw error;
}

// ============================================================
// ESCALATIONS (chat manager -> admin console)
// ============================================================
function escRow(r) {
  return { id: r.id, userId: r.user_id, staffId: r.staff_id, reason: r.reason, status: r.status,
    adminFeedback: r.admin_feedback, createdAt: r.created_at, updatedAt: r.updated_at };
}
async function findEscalationById(id) {
  const { data, error } = await supabase.from('escalations').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? escRow(data) : null;
}
async function createEscalation(e) {
  const id = uid();
  const { error } = await supabase.from('escalations').insert({
    id, user_id: e.userId, staff_id: e.staffId || null, reason: e.reason, status: 'open'
  });
  if (error) throw error;
  return findEscalationById(id);
}
async function listEscalations() {
  const { data, error } = await supabase.from('escalations').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(escRow);
}
async function resolveEscalation(id, feedback) {
  const { error } = await supabase.from('escalations')
    .update({ status: 'resolved', admin_feedback: feedback || null, updated_at: new Date().toISOString() }).eq('id', id);
  if (error) throw error;
}

// ============================================================
// PUSH NOTIFICATIONS + in-app notification feed (customers)
// ============================================================
async function getPushKeys() {
  const { data, error } = await supabase.from('push_keys').select('*').eq('id', 1).maybeSingle();
  if (error) throw error;
  return data ? { publicKey: data.public_key, privateKey: data.private_key } : null;
}
// Stores the server's push key pair once. If another instance saved one first, that one is kept and returned.
async function savePushKeys(k) {
  const { error } = await supabase.from('push_keys')
    .upsert({ id: 1, public_key: k.publicKey, private_key: k.privateKey }, { onConflict: 'id', ignoreDuplicates: true });
  if (error) throw error;
  return getPushKeys();
}
async function savePushSubscription(s) {
  const { error } = await supabase.from('push_subscriptions')
    .upsert({ endpoint: s.endpoint, user_id: s.userId, p256dh: s.p256dh, auth: s.auth }, { onConflict: 'endpoint' });
  if (error) throw error;
}
async function deletePushSubscription(endpoint) {
  const { error } = await supabase.from('push_subscriptions').delete().eq('endpoint', endpoint);
  if (error) throw error;
}
// userId null = every customer's devices
async function listPushSubscriptions(userId) {
  let q = supabase.from('push_subscriptions').select('*');
  if (userId) q = q.eq('user_id', userId);
  const { data, error } = await q;
  if (error) throw error;
  return data.map(r => ({ endpoint: r.endpoint, userId: r.user_id, p256dh: r.p256dh, auth: r.auth }));
}
function noteRow(r) {
  return { id: r.id, userId: r.user_id, kind: r.kind, title: r.title, body: r.body, createdAt: r.created_at };
}
// userId null = shown to every customer
async function addNotification(n) {
  const { error } = await supabase.from('notifications')
    .insert({ id: uid(), user_id: n.userId || null, kind: n.kind || 'info', title: n.title, body: n.body });
  if (error) throw error;
}
async function listNotificationsForUser(userId, since) {
  const mine = await supabase.from('notifications').select('*').eq('user_id', userId)
    .order('created_at', { ascending: false }).limit(50);
  if (mine.error) throw mine.error;
  const everyone = await supabase.from('notifications').select('*').is('user_id', null).gte('created_at', since)
    .order('created_at', { ascending: false }).limit(50);
  if (everyone.error) throw everyone.error;
  return mine.data.concat(everyone.data).map(noteRow)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 50);
}

// ============================================================
// TEAM ALERTS (push to admin and staff devices)
// portal: 'admin' | 'vendor' | 'chat'. staff_id is empty for the admin.
// ============================================================
async function saveTeamPush(s) {
  const { error } = await supabase.from('team_push_subscriptions')
    .upsert({ endpoint: s.endpoint, staff_id: s.staffId || null, portal: s.portal, p256dh: s.p256dh, auth: s.auth }, { onConflict: 'endpoint' });
  if (error) throw error;
}
async function deleteTeamPush(endpoint) {
  const { error } = await supabase.from('team_push_subscriptions').delete().eq('endpoint', endpoint);
  if (error) throw error;
}
async function listTeamPush() {
  const { data, error } = await supabase.from('team_push_subscriptions').select('*');
  if (error) throw error;
  return data.map(r => ({ endpoint: r.endpoint, staffId: r.staff_id, portal: r.portal, p256dh: r.p256dh, auth: r.auth }));
}

// ============================================================
// LOANS (Borrow)
// status: pending -> declined, or active (approved, still owed) -> repaid
// ============================================================
function loanRow(r) {
  return { id: r.id, userId: r.user_id, amount: Number(r.amount), outstanding: Number(r.outstanding),
    status: r.status, createdAt: r.created_at, updatedAt: r.updated_at };
}
async function findLoanById(id) {
  const { data, error } = await supabase.from('loans').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? loanRow(data) : null;
}
async function createLoan(l) {
  const id = uid();
  const { error } = await supabase.from('loans').insert({ id, user_id: l.userId, amount: l.amount, outstanding: 0, status: 'pending' });
  if (error) throw error;
  return findLoanById(id);
}
async function listLoans() {
  const { data, error } = await supabase.from('loans').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(loanRow);
}
async function listLoansForUser(userId) {
  const { data, error } = await supabase.from('loans').select('*').eq('user_id', userId).order('created_at', { ascending: false });
  if (error) throw error;
  return data.map(loanRow);
}
async function updateLoan(id, fields) {
  const patch = { updated_at: new Date().toISOString() };
  if (fields.status !== undefined) patch.status = fields.status;
  if (fields.outstanding !== undefined) patch.outstanding = fields.outstanding;
  const { error } = await supabase.from('loans').update(patch).eq('id', id);
  if (error) throw error;
}
// The most any customer may borrow. One number, set by the admin.
async function getLoanLimit() {
  const { data, error } = await supabase.from('loan_config').select('*').eq('id', 1).maybeSingle();
  if (error) throw error;
  return data ? Number(data.loan_limit) : 5000;
}
async function setLoanLimit(n) {
  const { error } = await supabase.from('loan_config').upsert({ id: 1, loan_limit: n }, { onConflict: 'id' });
  if (error) throw error;
}

// ============================================================
// LOGIN EXTRAS: email + PIN, saved sessions, fingerprint (passkeys)
// ============================================================
const authTable = kind => (kind === 'staff' ? 'staff' : 'users');
// True once the email columns exist (the PIN + email SQL was run). Until then the apps keep the old login.
async function hasEmailColumns() {
  const a = await supabase.from('users').select('email').limit(1);
  const b = await supabase.from('staff').select('email').limit(1);
  return !a.error && !b.error;
}
async function findByEmail(kind, email) {
  const { data, error } = await supabase.from(authTable(kind)).select('*').ilike('email', email).limit(1);
  if (error) throw error;
  return data && data[0] ? (kind === 'staff' ? staffRow(data[0]) : userRow(data[0])) : null;
}
async function setLogin(kind, id, fields) {
  const patch = {};
  if (fields.email !== undefined) patch.email = fields.email;
  if (fields.passwordHash !== undefined) patch.password_hash = fields.passwordHash;
  const { error } = await supabase.from(authTable(kind)).update(patch).eq('id', id);
  if (error) throw error;
}
async function sessionGet(sid) {
  const { data, error } = await supabase.from('sessions').select('data, expires_at').eq('sid', sid).maybeSingle();
  if (error) throw error;
  return data && new Date(data.expires_at) > new Date() ? data.data : null;
}
async function sessionSet(sid, data, expiresAt) {
  const { error } = await supabase.from('sessions').upsert({ sid, data, expires_at: expiresAt });
  if (error) throw error;
}
async function sessionDelete(sid) {
  const { error } = await supabase.from('sessions').delete().eq('sid', sid);
  if (error) throw error;
}
async function savePasskey(p) {
  const { error } = await supabase.from('passkeys').upsert({ id: p.id, kind: p.kind, owner_id: p.ownerId, public_key: p.publicKey, counter: p.counter || 0 });
  if (error) throw error;
}
async function findPasskey(id) {
  const { data, error } = await supabase.from('passkeys').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? { id: data.id, kind: data.kind, ownerId: data.owner_id, publicKey: data.public_key, counter: Number(data.counter) || 0 } : null;
}
async function updatePasskeyCounter(id, counter) {
  const { error } = await supabase.from('passkeys').update({ counter }).eq('id', id);
  if (error) throw error;
}
async function deletePasskey(id) {
  const { error } = await supabase.from('passkeys').delete().eq('id', id);
  if (error) throw error;
}

// Messages a chat manager passed on to one person (a staff member, or the admin when to_staff_id is null).
function forwardRow(r) {
  return { id: r.id, fromStaffId: r.from_staff_id, toStaffId: r.to_staff_id, userId: r.user_id, text: r.message_text, imageData: r.image_data, sender: r.sender, status: r.status, createdAt: r.created_at };
}
async function createForward(f) {
  const id = uid();
  const { error } = await supabase.from('forwards').insert({ id, from_staff_id: f.fromStaffId, to_staff_id: f.toStaffId || null, user_id: f.userId, message_text: f.text || null, image_data: f.imageData || null, sender: f.sender });
  if (error) throw error;
  return id;
}
async function listForwardsTo(staffId) {
  let q = supabase.from('forwards').select('*').order('created_at', { ascending: false }).limit(60);
  q = staffId ? q.eq('to_staff_id', staffId) : q.is('to_staff_id', null);
  const { data, error } = await q;
  if (error) throw error;
  return data.map(forwardRow);
}
async function findForwardById(id) {
  const { data, error } = await supabase.from('forwards').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? forwardRow(data) : null;
}
async function setForwardStatus(id, status) {
  const { error } = await supabase.from('forwards').update({ status }).eq('id', id);
  if (error) throw error;
}

// Staff-to-staff messages (chat manager <-> vendors).
function teamMsgRow(r) {
  return { id: r.id, fromStaffId: r.from_staff_id, toStaffId: r.to_staff_id, text: r.message_text, imageData: r.image_data, readAt: r.read_at, createdAt: r.created_at };
}
async function addTeamMessage(m) {
  const id = uid();
  const { error } = await supabase.from('team_messages').insert({ id, from_staff_id: m.fromStaffId, to_staff_id: m.toStaffId, message_text: m.text || null, image_data: m.imageData || null });
  if (error) throw error;
  const { data } = await supabase.from('team_messages').select('*').eq('id', id).maybeSingle();
  return data ? teamMsgRow(data) : { id, ...m, createdAt: new Date().toISOString() };
}
async function listTeamMessagesFor(staffId) {
  const { data, error } = await supabase.from('team_messages').select('*').or(`from_staff_id.eq.${staffId},to_staff_id.eq.${staffId}`).order('created_at', { ascending: true }).limit(2000);
  if (error) throw error;
  return data.map(teamMsgRow);
}
async function markTeamRead(toStaffId, fromStaffId) {
  const { error } = await supabase.from('team_messages').update({ read_at: new Date().toISOString() }).eq('to_staff_id', toStaffId).eq('from_staff_id', fromStaffId).is('read_at', null);
  if (error) throw error;
}
async function findTeamMessage(id) {
  const { data, error } = await supabase.from('team_messages').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? teamMsgRow(data) : null;
}
async function deleteTeamMessage(id) {
  const { error } = await supabase.from('team_messages').delete().eq('id', id);
  if (error) throw error;
}

// Staff department: 'vendor' or 'chat' (chat manager). True once the role column exists.
async function hasStaffRole() { const { error } = await supabase.from('staff').select('role').limit(1); return !error; }
async function setStaffRole(id, role) {
  const { error } = await supabase.from('staff').update({ role }).eq('id', id);
  if (error) throw error;
}

module.exports = {
  hasStaffRole, setStaffRole,
  addTeamMessage, listTeamMessagesFor, markTeamRead, findTeamMessage, deleteTeamMessage,
  createForward, listForwardsTo, findForwardById, setForwardStatus,
  hasEmailColumns, findByEmail, setLogin, sessionGet, sessionSet, sessionDelete, savePasskey, findPasskey, updatePasskeyCounter, deletePasskey,
  saveTeamPush, deleteTeamPush, listTeamPush,
  createLoan, findLoanById, listLoans, listLoansForUser, updateLoan, getLoanLimit, setLoanLimit,
  getPushKeys, savePushKeys, savePushSubscription, deletePushSubscription, listPushSubscriptions,
  addNotification, listNotificationsForUser,
  createEscalation, findEscalationById, listEscalations, resolveEscalation,
  createUser, findUserByPhone, findUserById, listUsers, setUserStatus, updateUser, deleteUser, addToBalance,
  createStaff, findStaffByPhone, findStaffById, listStaff, setStaffStatus, deleteStaff,
  listAccountsPublic, listAccountsForAmount, listAllAccounts, listAccountsByStaff, findAccountById, createAccount, updateAccount, deleteAccount,
  createTrade, findTradeById, listTradesForUser, listTradesForStaff, listAllTrades, updateTradeStatus, setSettlement,
  getSettings, updateSettings,
  addMessage, messagesForUser, listConversations, findMessageById, deleteMessage,
  createWithdrawal, findWithdrawalById, listWithdrawalsForUser, listAllWithdrawals, updateWithdrawalStatus
};
