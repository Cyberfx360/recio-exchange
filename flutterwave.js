// ============================================================
// Flutterwave payouts (bank transfers) for auto-paying withdrawals.
//
// Keys live ONLY in environment variables (set them in Render, never in code):
//   FLW_SECRET_KEY    - your Flutterwave secret key (FLWSECK-...)
//   FLW_WEBHOOK_HASH  - the "Secret hash" you set in the Flutterwave dashboard
//   FLW_MOCK=1        - test mode: no real network calls, deterministic fakes
//
// Safety: there is NO silent fake. If FLW_MOCK is not set and there is no
// secret key, every call throws, so a misconfigured server REFUSES to pay
// rather than pretending a payout succeeded.
// ============================================================
const crypto = require('crypto');

const BASE = process.env.FLW_BASE || 'https://api.flutterwave.com';
const key = () => process.env.FLW_SECRET_KEY || '';
const isMock = () => process.env.FLW_MOCK === '1';
function configured() { return isMock() || !!key(); }

function must() {
  if (isMock()) return;
  if (!key()) { const e = new Error('Flutterwave is not set up. Add FLW_SECRET_KEY in Render first.'); e.code = 'FLW_UNCONFIGURED'; throw e; }
}

async function flw(path, { method = 'GET', body } = {}) {
  must();
  const r = await fetch(BASE + path, {
    method,
    headers: { authorization: 'Bearer ' + key(), 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = null;
  try { data = await r.json(); } catch (e) {}
  if (!r.ok || !data || data.status === 'error') {
    const msg = (data && data.message) || ('Flutterwave error (' + r.status + ')');
    const e = new Error(msg); e.flw = data || null; e.http = r.status; throw e;
  }
  return data;
}

// ---- Bank name -> Flutterwave bank code (Nigeria) --------------------------
let BANKS = null, BANKS_AT = 0;
const MOCK_BANKS = [
  { code: '044', name: 'Access Bank' }, { code: '058', name: 'Guaranty Trust Bank' },
  { code: '057', name: 'Zenith Bank' }, { code: '033', name: 'United Bank For Africa' },
  { code: '011', name: 'First Bank of Nigeria' }, { code: '232', name: 'Sterling Bank' },
  { code: '070', name: 'Fidelity Bank' }, { code: '032', name: 'Union Bank' },
  { code: '999992', name: 'OPay' }, { code: '999991', name: 'PalmPay' },
  { code: '50211', name: 'Kuda Bank' }, { code: '50515', name: 'Moniepoint MFB' }
];

async function banks() {
  if (isMock()) return MOCK_BANKS;
  if (BANKS && Date.now() - BANKS_AT < 24 * 3600 * 1000) return BANKS;
  const d = await flw('/v3/banks/NG');
  BANKS = (d.data || []).map(b => ({ code: String(b.code), name: String(b.name) }));
  BANKS_AT = Date.now();
  return BANKS;
}

const norm = s => String(s || '').toLowerCase().replace(/\(.*?\)/g, ' ')
  .replace(/\b(bank|plc|limited|ltd|nigeria|ng|mfb|microfinance)\b/g, ' ')
  .replace(/[^a-z0-9]+/g, '').trim();

// Common ways customers write their bank, mapped to a canonical token.
const ALIAS = {
  gtb: 'guarantytrust', gtbank: 'guarantytrust', guarantytrust: 'guarantytrust', gt: 'guarantytrust',
  uba: 'unitedbankforafrica', firstbank: 'first', fbn: 'first',
  zenith: 'zenith', access: 'access', accessdiamond: 'access', diamond: 'access',
  union: 'union', fidelity: 'fidelity', sterling: 'sterling',
  opay: 'opay', paycom: 'opay', palmpay: 'palmpay', kuda: 'kuda',
  moniepoint: 'moniepoint', monie: 'moniepoint'
};
const canon = s => { const n = norm(s); return ALIAS[n] || n; };

// Resolve a free-text bank name to a Flutterwave { code, name }, or null if unsure.
async function bankCode(bankName) {
  const want = canon(bankName);
  if (!want) return null;
  const list = await banks();
  // exact canonical match first
  let hit = list.find(b => canon(b.name) === want);
  if (hit) return { code: hit.code, name: hit.name };
  // then a safe contains match (both directions), to catch "Access" vs "Access Bank"
  hit = list.find(b => { const c = canon(b.name); return c && (c.includes(want) || want.includes(c)) && Math.min(c.length, want.length) >= 4; });
  return hit ? { code: hit.code, name: hit.name } : null;
}

// ---- Account name check (optional safety) ----------------------------------
async function resolveAccount(accountNumber, bankCode) {
  if (isMock()) {
    if (String(accountNumber).startsWith('000')) { const e = new Error('Could not resolve account'); e.http = 400; throw e; }
    return { account_number: accountNumber, account_name: 'MOCK ACCOUNT HOLDER' };
  }
  const d = await flw('/v3/accounts/resolve', { method: 'POST', body: { account_number: String(accountNumber), account_bank: String(bankCode) } });
  return d.data || null;
}

// ---- Create a transfer -----------------------------------------------------
// ref MUST be unique per attempt. Returns { id, reference, status }.
async function createTransfer({ accountNumber, bankCode, amount, reference, narration }) {
  if (isMock()) return { id: 'mock_' + reference, reference, status: 'NEW' };
  const d = await flw('/v3/transfers', { method: 'POST', body: {
    account_bank: String(bankCode), account_number: String(accountNumber),
    amount: Number(amount), currency: 'NGN', debit_currency: 'NGN',
    reference: String(reference), narration: narration || 'AZAPLUG withdrawal'
  } });
  const t = d.data || {};
  return { id: t.id != null ? String(t.id) : null, reference: t.reference || reference, status: t.status || 'NEW' };
}

async function fetchTransfer(id) {
  if (isMock()) return { id, status: 'SUCCESSFUL' };
  const d = await flw('/v3/transfers/' + encodeURIComponent(id));
  return d.data || null;
}

// ---- Webhook verification --------------------------------------------------
// Flutterwave sends a static header "verif-hash" equal to your dashboard secret hash.
function verifyWebhook(req) {
  const expected = process.env.FLW_WEBHOOK_HASH || '';
  if (!expected) return false;
  const got = String(req.headers['verif-hash'] || req.headers['verif_hash'] || '');
  if (!got || got.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(got), Buffer.from(expected)); } catch (e) { return false; }
}

module.exports = { configured, isMock, banks, bankCode, resolveAccount, createTransfer, fetchTransfer, verifyWebhook };
