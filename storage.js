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
    passwordHash: r.password_hash, status: r.status,
    balance: Number(r.balance), createdAt: r.created_at
  };
}

async function createUser({ name, phone, accountNumber, bankName, passwordHash }) {
  const id = uid();
  const { error } = await supabase.from('users').insert({
    id, name, phone, account_number: accountNumber, bank_name: bankName,
    password_hash: passwordHash, status: 'approved', balance: 0
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
  // accountNumber intentionally NOT editable after signup, per business rule
  const { error } = await supabase.from('users').update(patch).eq('id', id);
  if (error) throw error;
}
async function deleteUser(id) {
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
  return { id: r.id, name: r.name, phone: r.phone, passwordHash: r.password_hash, status: r.status, createdAt: r.created_at };
}
async function createStaff({ name, phone, passwordHash }) {
  const id = uid();
  const { error } = await supabase.from('staff').insert({ id, name, phone, password_hash: passwordHash, status: 'pending' });
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
async function deleteStaff(id) {
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
    active: true
  });
  if (error) throw error;
  return findAccountById(id);
}
async function updateAccount(id, a) {
  const patch = { updated_at: new Date().toISOString() };
  var map = { title:'title', accountNumber:'account_number', bankName:'bank_name', imageData:'image_data',
    lowestAmount:'lowest_amount', lowestRate:'lowest_rate', higherAmount:'higher_amount', higherRate:'higher_rate',
    minAmount:'min_amount', maxAmount:'max_amount', active:'active' };
  Object.keys(map).forEach(function(k){
    if (a[k] === undefined) return;
    patch[map[k]] = a[k];
  });
  const { error } = await supabase.from('accounts').update(patch).eq('id', id);
  if (error) throw error;
}
async function deleteAccount(id) {
  const { error } = await supabase.from('accounts').delete().eq('id', id);
  if (error) throw error;
}

// ============================================================
// TRADES
// ============================================================

function tradeRow(r) {
  return {
    id: r.id, userId: r.user_id, accountId: r.account_id, staffId: r.staff_id,
    intendedAmount: Number(r.intended_amount), receiptImage: r.receipt_image,
    status: r.status, failReason: r.fail_reason,
    accountNumberUsed: r.account_number_used, accountTitleUsed: r.account_title_used,
    userPayoutAccount: r.user_payout_account, userPayoutBank: r.user_payout_bank,
    settlementScreenshot: r.settlement_screenshot, settlementStatus: r.settlement_status,
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
    settlement_status: 'pending'
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
    return { rulesText: defaults.rules_text, settlementAccount: '', settlementBank: '', maxDeposit: 3000000 };
  }
  return {
    rulesText: data.rules_text, settlementAccount: data.settlement_account,
    settlementBank: data.settlement_bank, maxDeposit: Number(data.max_deposit)
  };
}
async function updateSettings(fields) {
  const patch = {};
  if (fields.rulesText !== undefined) patch.rules_text = fields.rulesText;
  if (fields.settlementAccount !== undefined) patch.settlement_account = fields.settlementAccount;
  if (fields.settlementBank !== undefined) patch.settlement_bank = fields.settlementBank;
  if (fields.maxDeposit !== undefined) patch.max_deposit = fields.maxDeposit;
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
      lastMessage: lastMsg.image_data ? '📷 Photo' : lastMsg.text,
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
    status: r.status, reason: r.reason,
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
  const { error } = await supabase.from('withdrawals').update(patch).eq('id', id);
  if (error) throw error;
}

module.exports = {
  createUser, findUserByPhone, findUserById, listUsers, setUserStatus, updateUser, deleteUser, addToBalance,
  createStaff, findStaffByPhone, findStaffById, listStaff, setStaffStatus, deleteStaff,
  listAccountsPublic, listAccountsForAmount, listAllAccounts, listAccountsByStaff, findAccountById, createAccount, updateAccount, deleteAccount,
  createTrade, findTradeById, listTradesForUser, listTradesForStaff, listAllTrades, updateTradeStatus, setSettlement,
  getSettings, updateSettings,
  addMessage, messagesForUser, listConversations,
  createWithdrawal, findWithdrawalById, listWithdrawalsForUser, listAllWithdrawals, updateWithdrawalStatus
};
