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
  dropMediaFolder('u/' + safeOwner(id));   // their receipts, chat photos and voice notes
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
    accountNumber: r.account_number, bankName: r.bank_name, imageData: pubMedia(r.image_data),
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
  if (a.imageData) a = { ...a, imageData: await toRef(a.imageData, 'pub/a') };
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
  if (a.imageData) a = { ...a, imageData: await toRef(a.imageData, 'pub/a') };
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
// MEDIA: photos and voice notes live in Supabase Storage (bucket "media"), not in the database.
// The database keeps a short reference like "media:u/<userId>/<id>.jpg;dur=5;w=..." (dur/w only for voice notes).
// The apps receive "/api/media/u/<userId>/<id>.jpg" (voice: "...m4a?a=1&dur=5&w=...") and the server streams the file.
// If Storage is not available, pictures are kept in the database like before, so nothing breaks.
// ============================================================
const MEDIA_BUCKET = 'media';
const MEDIA_EXT = { 'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif',
  'audio/mp4': 'm4a', 'audio/x-m4a': 'm4a', 'audio/aac': 'm4a', 'audio/webm': 'webm', 'audio/ogg': 'ogg', 'audio/mpeg': 'mp3' };
const MEDIA_TYPE = { jpg: 'image/jpeg', png: 'image/png', webp: 'image/webp', gif: 'image/gif', m4a: 'audio/mp4', webm: 'audio/webm', ogg: 'audio/ogg', mp3: 'audio/mpeg' };
const AUDIO_EXT = /\.(m4a|webm|ogg|mp3)$/;
const MEDIA_PATH = /^(u|pub|staff|team)\/[A-Za-z0-9-]+\/[A-Za-z0-9-]+\.(jpg|png|webp|gif|m4a|webm|ogg|mp3)$/;
let mediaOk = null, mediaRetry = 0;
async function mediaReady() {
  if (mediaOk === true) return true;
  if (mediaOk === false && Date.now() < mediaRetry) return false;
  try {
    const got = await supabase.storage.getBucket(MEDIA_BUCKET);
    if (got.error) {
      const made = await supabase.storage.createBucket(MEDIA_BUCKET, { public: false, fileSizeLimit: 6 * 1024 * 1024 });
      if (made.error && !/exist/i.test(made.error.message)) throw made.error;
    }
    mediaOk = true;
  } catch (err) {
    console.error('Supabase Storage not available, keeping pictures in the database for now:', err.message || err);
    mediaOk = false; mediaRetry = Date.now() + 10 * 60000;
  }
  return mediaOk;
}
// "media:path;dur=5;w=..." -> { path, meta }
function parseRef(ref) {
  if (typeof ref !== 'string' || !ref.startsWith('media:')) return null;
  const parts = ref.slice(6).split(';'), path = parts.shift();
  if (!MEDIA_PATH.test(path)) return null;
  const meta = {}; parts.forEach(p => { const [k, v] = p.split('='); if (/^(dur|w)$/.test(k) && /^\d+$/.test(v || '')) meta[k] = v; });
  return { path, meta };
}
// Database value -> what the apps receive
function pubMedia(v) {
  const r = parseRef(v);
  if (!r) return v;
  if (!AUDIO_EXT.test(r.path)) return '/api/media/' + r.path;
  return '/api/media/' + r.path + '?a=1' + (r.meta.dur ? '&dur=' + r.meta.dur : '') + (r.meta.w ? '&w=' + r.meta.w : '');
}
// App value (data: URL, or an /api/media/ link being reused) -> database value. Uploads new files to Storage.
async function toRef(v, folder) {
  if (typeof v !== 'string' || !v) return v || null;
  if (v.startsWith('/api/media/')) {
    const [p, q] = v.slice(11).split('?'), qs = new URLSearchParams(q || '');
    if (!MEDIA_PATH.test(p)) return null;
    return 'media:' + p + (qs.get('dur') ? ';dur=' + qs.get('dur') : '') + (qs.get('w') ? ';w=' + qs.get('w') : '');
  }
  if (v.startsWith('media:')) return v;
  if (!v.startsWith('data:') || !(await mediaReady())) return v;
  const i = v.indexOf(','), head = v.slice(5, i).split(';'), type = (head[0] || '').toLowerCase(), ext = MEDIA_EXT[type];
  if (!ext || i < 0) return v;
  const meta = head.filter(h => /^(dur|w)=\d+$/.test(h));
  const path = `${folder}/${uid()}.${ext}`;
  const { error } = await supabase.storage.from(MEDIA_BUCKET).upload(path, Buffer.from(v.slice(i + 1), 'base64'), { contentType: MEDIA_TYPE[ext], upsert: false });
  if (error) { console.error('Upload to Storage failed, keeping it in the database:', error.message); return v; }
  return 'media:' + path + (meta.length ? ';' + meta.join(';') : '');
}
const safeOwner = id => String(id || 'x').replace(/[^A-Za-z0-9-]/g, '').slice(0, 40) || 'x';
async function getMediaFile(path) {
  if (!MEDIA_PATH.test(path)) return null;
  const { data, error } = await supabase.storage.from(MEDIA_BUCKET).download(path);
  if (error || !data) return null;
  return { body: Buffer.from(await data.arrayBuffer()), type: MEDIA_TYPE[path.split('.').pop()] || 'application/octet-stream' };
}
// Is this stored file still used by any row? (a receipt made from a chat photo shares the same file)
async function refUsed(ref) {
  const r = parseRef(ref); if (!r) return true;
  const like = 'media:' + r.path + '%';
  const checks = [
    supabase.from('trades').select('id').or(`receipt_image.like.${like},fail_image.like.${like},settlement_screenshot.like.${like}`).limit(1),
    supabase.from('messages').select('id').like('image_data', like).limit(1),
    supabase.from('withdrawals').select('id').like('reason_image', like).limit(1),
    supabase.from('accounts').select('id').like('image_data', like).limit(1),
    supabase.from('team_messages').select('id').like('image_data', like).limit(1),
    supabase.from('forwards').select('id').like('image_data', like).limit(1)
  ];
  for (const q of checks) { const { data, error } = await q; if (!error && data && data.length) return true; if (error && !/does not exist/i.test(error.message)) return true; }
  return false;
}
async function dropMedia(ref) {
  try { const r = parseRef(ref); if (r && !(await refUsed(ref))) await supabase.storage.from(MEDIA_BUCKET).remove([r.path]); }
  catch (err) { console.error('Could not remove a stored file:', err.message); }
}
async function dropMediaFolder(folder) {
  try {
    const { data } = await supabase.storage.from(MEDIA_BUCKET).list(folder, { limit: 1000 });
    if (data && data.length) await supabase.storage.from(MEDIA_BUCKET).remove(data.map(f => folder + '/' + f.name));
  } catch (err) { console.error('Could not remove stored files:', err.message); }
}

// Moves pictures that are still inside the database into Storage, a few at a time (runs in the background).
const MIGRATE = [
  { table: 'trades', col: 'receipt_image', folder: r => 'u/' + safeOwner(r.user_id), extra: 'user_id' },
  { table: 'trades', col: 'fail_image', folder: r => 'u/' + safeOwner(r.user_id), extra: 'user_id' },
  { table: 'trades', col: 'settlement_screenshot', folder: () => 'staff/s' },
  { table: 'messages', col: 'image_data', folder: r => 'u/' + safeOwner(r.user_id), extra: 'user_id' },
  { table: 'withdrawals', col: 'reason_image', folder: r => 'u/' + safeOwner(r.user_id), extra: 'user_id' },
  { table: 'accounts', col: 'image_data', folder: () => 'pub/a' },
  { table: 'forwards', col: 'image_data', folder: () => 'staff/f' },
  { table: 'team_messages', col: 'image_data', folder: r => 'team/' + safeOwner(r.from_staff_id), extra: 'from_staff_id' }
];
async function migrateMediaBatch() {
  if (!(await mediaReady())) return { moved: 0, left: true };
  let moved = 0, left = false;
  for (const m of MIGRATE) {
    const { data, error } = await supabase.from(m.table).select(['id', m.col].concat(m.extra ? [m.extra] : []).join(',')).like(m.col, 'data:%').limit(5);
    if (error) continue;   // table not created yet
    if (data.length === 5) left = true;
    for (const row of data) {
      const ref = await toRef(row[m.col], m.folder(row));
      if (typeof ref === 'string' && ref.startsWith('media:')) {
        const u = await supabase.from(m.table).update({ [m.col]: ref }).eq('id', row.id);
        if (!u.error) moved++;
      } else left = false;   // Storage refused: stop for now, try again later
    }
  }
  return { moved, left };
}
async function mediaLeftInDatabase() {
  const out = {};
  for (const m of MIGRATE) {
    const { count, error } = await supabase.from(m.table).select('id', { count: 'exact', head: true }).like(m.col, 'data:%');
    if (!error && count) out[m.table + '.' + m.col] = count;
  }
  return out;
}
// Chat photos and voice notes older than `days` are removed (receipts are kept forever).
async function cleanOldChatMedia(days) {
  const cutoff = new Date(Date.now() - days * 864e5).toISOString();
  let removed = 0;
  for (const t of [{ table: 'messages', text: 'text' }, { table: 'team_messages', text: 'message_text' }, { table: 'forwards', text: 'message_text' }]) {
    const { data, error } = await supabase.from(t.table).select(`id,image_data,${t.text}`).not('image_data', 'is', null).lt('created_at', cutoff).limit(100);
    if (error || !data) continue;
    for (const row of data) {
      const voice = /^data:audio\//i.test(row.image_data) || AUDIO_EXT.test((parseRef(row.image_data) || {}).path || '');
      const note = `${voice ? 'Voice note' : 'Photo'} removed after ${days} days`;
      const u = await supabase.from(t.table).update({ image_data: null, [t.text]: row[t.text] ? row[t.text] + '\n(' + note + ')' : note }).eq('id', row.id);
      if (u.error) continue;
      removed++;
      if (parseRef(row.image_data)) await dropMedia(row.image_data);
    }
  }
  return removed;
}

// ============================================================
// TRADES
// ============================================================

function tradeRow(r) {
  return {
    id: r.id, userId: r.user_id, accountId: r.account_id, staffId: r.staff_id,
    intendedAmount: Number(r.intended_amount), creditedAmount: r.credited_amount === null ? null : Number(r.credited_amount),
    staffCreditedAmount: r.staff_credited_amount === null ? null : Number(r.staff_credited_amount),
    receiptImage: pubMedia(r.receipt_image),
    status: r.status, failReason: r.fail_reason, failImage: pubMedia(r.fail_image),
    accountNumberUsed: r.account_number_used, accountTitleUsed: r.account_title_used,
    userPayoutAccount: r.user_payout_account, userPayoutBank: r.user_payout_bank,
    settlementScreenshot: pubMedia(r.settlement_screenshot), settlementStatus: r.settlement_status,
    chatMessageId: r.chat_message_id || null,   // set when a chat manager turned a chat photo into this receipt
    createdAt: r.created_at, updatedAt: r.updated_at
  };
}
async function createTrade(t) {
  const id = uid();
  t = { ...t, receiptImage: await toRef(t.receiptImage, 'u/' + safeOwner(t.userId)) };
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
  if (opts.failImage) {
    const { data: row } = await supabase.from('trades').select('user_id').eq('id', id).maybeSingle();
    patch.fail_image = await toRef(opts.failImage, 'u/' + safeOwner(row && row.user_id));
  } else if (opts.failImage !== undefined) patch.fail_image = opts.failImage;
  if (opts.creditedAmount !== undefined) patch.credited_amount = opts.creditedAmount;
  if (opts.staffCreditedAmount !== undefined) patch.staff_credited_amount = opts.staffCreditedAmount;
  if (opts.userPayoutAccount !== undefined) patch.user_payout_account = opts.userPayoutAccount;
  if (opts.userPayoutBank !== undefined) patch.user_payout_bank = opts.userPayoutBank;
  const { error } = await supabase.from('trades').update(patch).eq('id', id);
  if (error) throw error;
}
async function setSettlement(id, screenshot) {
  screenshot = await toRef(screenshot, 'staff/s');
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
  return { id: r.id, userId: r.user_id, sender: r.sender, text: r.text, imageData: pubMedia(r.image_data), createdAt: r.created_at };
}
async function addMessage(m) {
  const id = uid();
  if (m.imageData) m = { ...m, imageData: await toRef(m.imageData, 'u/' + safeOwner(m.userId)) };
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
  const { data: row } = await supabase.from('messages').select('image_data').eq('id', id).maybeSingle();
  const { error } = await supabase.from('messages').delete().eq('id', id);
  if (error) throw error;
  if (row && parseRef(row.image_data)) dropMedia(row.image_data);
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
      lastMessage: lastMsg.image_data ? (/^data:audio\//i.test(lastMsg.image_data) || AUDIO_EXT.test((parseRef(lastMsg.image_data) || {}).path || '') ? 'Voice note' : 'Photo') : String(lastMsg.text || '').replace(/^[\u{1F300}-\u{1FAFF}\u2600-\u27BF\uFE0F\s]+/u, ''),
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
    status: r.status, reason: r.reason, reasonImage: pubMedia(r.reason_image),
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
  if (opts.reasonImage) {
    const { data: row } = await supabase.from('withdrawals').select('user_id').eq('id', id).maybeSingle();
    patch.reason_image = await toRef(opts.reasonImage, 'u/' + safeOwner(row && row.user_id));
  } else if (opts.reasonImage !== undefined) patch.reason_image = opts.reasonImage;
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
  return { id: r.id, fromStaffId: r.from_staff_id, toStaffId: r.to_staff_id, userId: r.user_id, text: r.message_text, imageData: pubMedia(r.image_data), sender: r.sender, status: r.status, createdAt: r.created_at };
}
async function createForward(f) {
  const id = uid();
  if (f.imageData) f = { ...f, imageData: await toRef(f.imageData, 'staff/f') };
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
  return { id: r.id, fromStaffId: r.from_staff_id, toStaffId: r.to_staff_id, text: r.message_text, imageData: pubMedia(r.image_data), readAt: r.read_at, createdAt: r.created_at };
}
async function addTeamMessage(m) {
  const id = uid();
  if (m.imageData) m = { ...m, imageData: await toRef(m.imageData, 'team/' + safeOwner(m.fromStaffId)) };
  const { error } = await supabase.from('team_messages').insert({ id, from_staff_id: m.fromStaffId || null, to_staff_id: m.toStaffId || null, message_text: m.text || null, image_data: m.imageData || null });
  if (error) throw error;
  const { data } = await supabase.from('team_messages').select('*').eq('id', id).maybeSingle();
  return data ? teamMsgRow(data) : { id, ...m, createdAt: new Date().toISOString() };
}
async function listTeamMessagesFor(staffId) {
  const { data, error } = await supabase.from('team_messages').select('*').or(`from_staff_id.eq.${staffId},to_staff_id.eq.${staffId}`).order('created_at', { ascending: true }).limit(2000);
  if (error) throw error;
  return data.map(teamMsgRow);
}
// Admin's side of staff chats: rows where one side is empty (null = the admin).
async function listAdminTeamMessages() {
  const { data, error } = await supabase.from('team_messages').select('*').or('from_staff_id.is.null,to_staff_id.is.null').order('created_at', { ascending: true }).limit(4000);
  if (error) throw error;
  return data.map(teamMsgRow);
}
const eqOrNull = (q, col, v) => (v ? q.eq(col, v) : q.is(col, null));
async function markTeamRead(toStaffId, fromStaffId) {   // either side may be null (= admin)
  let q = supabase.from('team_messages').update({ read_at: new Date().toISOString() }).is('read_at', null);
  q = eqOrNull(eqOrNull(q, 'to_staff_id', toStaffId), 'from_staff_id', fromStaffId);
  const { error } = await q;
  if (error) throw error;
}
async function findTeamMessage(id) {
  const { data, error } = await supabase.from('team_messages').select('*').eq('id', id).maybeSingle();
  if (error) throw error;
  return data ? teamMsgRow(data) : null;
}
async function deleteTeamMessage(id) {
  const { data: row } = await supabase.from('team_messages').select('image_data').eq('id', id).maybeSingle();
  const { error } = await supabase.from('team_messages').delete().eq('id', id);
  if (error) throw error;
  if (row && parseRef(row.image_data)) dropMedia(row.image_data);
}

// Staff department: 'vendor' or 'chat' (chat manager). True once the role column exists.
async function hasStaffRole() { const { error } = await supabase.from('staff').select('role').limit(1); return !error; }
async function setStaffRole(id, role) {
  const { error } = await supabase.from('staff').update({ role }).eq('id', id);
  if (error) throw error;
}

// ============================================================
// GIVEAWAYS: "first N customers to say hi after the start time win"
// ============================================================
function giveawayRow(r) {
  return { id: r.id, title: r.title, amount: Number(r.amount), winners: Number(r.winners), keyword: r.keyword, startsAt: r.starts_at, status: r.status, createdAt: r.created_at };
}
function entryRow(r) {
  return { id: r.id, giveawayId: r.giveaway_id, userId: r.user_id, installed: !!r.installed, alertsOn: !!r.alerts_on, won: !!r.won, credited: !!r.credited, createdAt: r.created_at };
}
async function createGiveaway(g) {
  const id = uid();
  const { error } = await supabase.from('giveaways').insert({ id, title: g.title, amount: g.amount, winners: g.winners, keyword: g.keyword, starts_at: g.startsAt, status: 'open' });
  if (error) throw error;
  return id;
}
async function listGiveaways() {
  const { data, error } = await supabase.from('giveaways').select('*').order('created_at', { ascending: false }).limit(30);
  if (error) throw error;
  return data.map(giveawayRow);
}
async function setGiveawayStatus(id, status) {
  const { error } = await supabase.from('giveaways').update({ status }).eq('id', id);
  if (error) throw error;
}
async function listEntries(giveawayId) {
  const { data, error } = await supabase.from('giveaway_entries').select('*').eq('giveaway_id', giveawayId).order('created_at', { ascending: true });
  if (error) throw error;
  return data.map(entryRow);
}
async function addEntry(e) {
  const { data, error } = await supabase.from('giveaway_entries').insert({ id: uid(), giveaway_id: e.giveawayId, user_id: e.userId, installed: !!e.installed, alerts_on: !!e.alertsOn, won: !!e.won }).select('*').maybeSingle();
  if (error) { if (/duplicate|unique/i.test(error.message)) return null; throw error; }
  return data ? entryRow(data) : null;
}
async function updateEntry(id, patch) {
  const p = {};
  if (patch.won !== undefined) p.won = patch.won;
  if (patch.credited !== undefined) p.credited = patch.credited;
  const { error } = await supabase.from('giveaway_entries').update(p).eq('id', id);
  if (error) throw error;
}

module.exports = {
  createGiveaway, listGiveaways, setGiveawayStatus, listEntries, addEntry, updateEntry,
  mediaReady, getMediaFile, migrateMediaBatch, mediaLeftInDatabase, cleanOldChatMedia,
  hasStaffRole, setStaffRole,
  addTeamMessage, listTeamMessagesFor, listAdminTeamMessages, markTeamRead, findTeamMessage, deleteTeamMessage,
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
