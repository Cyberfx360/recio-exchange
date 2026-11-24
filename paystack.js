// ============================================================
// Paystack payouts (bank transfers) for auto-paying withdrawals.
//
// Same shape as flutterwave.js so the server can use either one.
// Keys live ONLY in environment variables (set them in Render, never in code):
//   PAYSTACK_SECRET_KEY - your Paystack secret key (sk_live_... or sk_test_...)
//   PAYSTACK_MOCK=1      - test mode: no real network calls, deterministic fakes
//
// Paystack notes that differ from Flutterwave:
//   - amounts are sent in KOBO (naira * 100)
//   - a transfer needs a "recipient" first (we create it inside createTransfer)
//   - webhooks are signed with HMAC-SHA512 of the raw body using the secret key
//   - to auto-pay without a code each time, OTP must be disabled in the dashboard
//
// Safety: there is NO silent fake. If PAYSTACK_MOCK is not set and there is no
// secret key, every call throws, so a misconfigured server REFUSES to pay
// rather than pretending a payout succeeded.
// ============================================================
const crypto = require('crypto');

const name = 'Paystack';
const BASE = process.env.PAYSTACK_BASE || 'https://api.paystack.co';
const key = () => process.env.PAYSTACK_SECRET_KEY || '';
const isMock = () => process.env.PAYSTACK_MOCK === '1';
function configured() { return isMock() || !!key(); }

function must() {
  if (isMock()) return;
  if (!key()) { const e = new Error('Paystack is not set up. Add PAYSTACK_SECRET_KEY in Render first.'); e.code = 'PAYSTACK_UNCONFIGURED'; throw e; }
}

async function ps(path, { method = 'GET', body } = {}) {
  must();
  const r = await fetch(BASE + path, {
    method,
    headers: { authorization: 'Bearer ' + key(), 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  let data = null;
  try { data = await r.json(); } catch (e) {}
  if (!r.ok || !data || data.status === false) {
    const msg = (data && data.message) || ('Paystack error (' + r.status + ')');
    const e = new Error(msg); e.ps = data || null; e.http = r.status; throw e;
  }
  return data;
}

// Paystack transfer status -> the uppercase status the server already understands.
function mapStatus(s) {
  const x = String(s || '').toLowerCase();
  if (x === 'success') return 'SUCCESSFUL';
  if (x === 'failed' || x === 'abandoned' || x === 'reversed') return 'FAILED';
  return 'PENDING'; // pending, received, otp, etc.
}

// ---- Bank name -> Paystack bank code (Nigeria) -----------------------------
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
  const d = await ps('/bank?currency=NGN');
  BANKS = (d.data || []).map(b => ({ code: String(b.code), name: String(b.name) }));
  BANKS_AT = Date.now();
  return BANKS;
}

const norm = s => String(s || '').toLowerCase().replace(/\(.*?\)/g, ' ')
  .replace(/\b(bank|plc|limited|ltd|nigeria|ng|mfb|microfinance)\b/g, ' ')
  .replace(/[^a-z0-9]+/g, '').trim();

const ALIAS = {
  gtb: 'guarantytrust', gtbank: 'guarantytrust', guarantytrust: 'guarantytrust', gt: 'guarantytrust',
  uba: 'unitedbankforafrica', firstbank: 'first', fbn: 'first',
  zenith: 'zenith', access: 'access', accessdiamond: 'access', diamond: 'access',
  union: 'union', fidelity: 'fidelity', sterling: 'sterling',
  opay: 'opay', paycom: 'opay', palmpay: 'palmpay', kuda: 'kuda',
  moniepoint: 'moniepoint', monie: 'moniepoint'
};
const canon = s => { const n = norm(s); return ALIAS[n] || n; };

async function bankCode(bankName) {
  const want = canon(bankName);
  if (!want) return null;
  const list = await banks();
  let hit = list.find(b => canon(b.name) === want);
  if (hit) return { code: hit.code, name: hit.name };
  hit = list.find(b => { const c = canon(b.name); return c && (c.includes(want) || want.includes(c)) && Math.min(c.length, want.length) >= 4; });
  return hit ? { code: hit.code, name: hit.name } : null;
}

// ---- Account name check ----------------------------------------------------
async function resolveAccount(accountNumber, bankCode) {
  if (isMock()) {
    if (String(accountNumber).startsWith('000')) { const e = new Error('Could not resolve account'); e.http = 400; throw e; }
    return { account_number: accountNumber, account_name: 'MOCK ACCOUNT HOLDER' };
  }
  const d = await ps('/bank/resolve?account_number=' + encodeURIComponent(String(accountNumber)) + '&bank_code=' + encodeURIComponent(String(bankCode)));
  return d.data ? { account_number: d.data.account_number, account_name: d.data.account_name } : null;
}

// A reusable beneficiary; returns a recipient_code we pass to the transfer.
async function createRecipient({ name: acctName, accountNumber, bankCode }) {
  const d = await ps('/transferrecipient', { method: 'POST', body: {
    type: 'nuban', name: acctName || 'AZAPLUG customer',
    account_number: String(accountNumber), bank_code: String(bankCode), currency: 'NGN'
  } });
  return d.data && d.data.recipient_code;
}

// ---- Create a transfer -----------------------------------------------------
// Same signature as flutterwave.createTransfer. reference MUST be unique per attempt.
// Paystack amounts are in kobo. Returns { id, reference, status }.
async function createTransfer({ accountNumber, bankCode, amount, reference, narration, name: acctName }) {
  if (isMock()) return { id: 'mock_' + reference, reference, status: 'PENDING' };
  const recipient = await createRecipient({ name: acctName, accountNumber, bankCode });
  if (!recipient) { const e = new Error('Could not create the Paystack transfer recipient.'); e.http = 502; throw e; }
  const d = await ps('/transfer', { method: 'POST', body: {
    source: 'balance', amount: Math.round(Number(amount) * 100), currency: 'NGN',
    recipient, reference: String(reference), reason: narration || 'AZAPLUG withdrawal'
  } });
  const t = d.data || {};
  if (String(t.status || '').toLowerCase() === 'otp') {
    const e = new Error('Paystack is asking for an OTP. Disable OTP in your Paystack dashboard (Settings → Preferences) to auto-pay.');
    e.http = 400; throw e;
  }
  return { id: t.transfer_code || (t.id != null ? String(t.id) : null), reference: t.reference || reference, status: mapStatus(t.status) };
}

async function fetchTransfer(id) {
  if (isMock()) return { id, status: 'SUCCESSFUL' };
  const d = await ps('/transfer/' + encodeURIComponent(id));
  const t = d.data || {};
  return { id, status: mapStatus(t.status) };
}

// ---- Webhook verification --------------------------------------------------
// Paystack signs the raw body with HMAC-SHA512 using your secret key and sends
// it in the x-paystack-signature header. We need req.rawBody (captured by the
// express.json verify hook) to match the exact bytes.
function verifyWebhook(req) {
  const secret = key();
  if (!secret) return isMock();   // tests: accept in mock mode
  const sig = String(req.headers['x-paystack-signature'] || '');
  const raw = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
  const expected = crypto.createHmac('sha512', secret).update(raw).digest('hex');
  if (!sig || sig.length !== expected.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected)); } catch (e) { return false; }
}

module.exports = { name, configured, isMock, banks, bankCode, resolveAccount, createTransfer, fetchTransfer, verifyWebhook };
