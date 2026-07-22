# RECIO EXCHANGE — Manual Deposit Verification Platform

Customers send money into an account you provide, upload a receipt, and your team manually
verifies and credits their balance. Three roles: **Customer**, **Staff**, **Admin**.

## How the flow works

1. Customer signs up with their name, bank, and account number (locked forever after signup) — they get instant access, **no approval needed**. (Staff are different — see below.)
2. Customer enters the amount they want to send. Anything over ₦3,000,000 (adjustable) is blocked — they're told to chat with you instead.
3. They're shown an account (title, account number + copy button, tiered rate) provided by one of your staff.
4. They pay into it and upload a receipt.
5. The staff member who owns that account reviews it: **Confirm** (customer sees it), **Approve** (balance updates), or **Failed** (with a required reason).
6. You (admin) can undo a mistaken Approve back to Failed — this reverses the balance credit automatically.
7. Staff then remit the money they collected to your settlement account and upload their own proof — tracked per trade.

## A few judgment calls I made while building this

- **Only staff need your approval** before they can act — customers get instant access after signup, exactly as you clarified.
- Admin can still **Suspend** (block) or **Delete** a customer at any time from the Users tab, even though no upfront approval is required.
- **Images (receipts, settlements, account logos) are stored as compressed text directly in the database** — no separate file-storage bucket to configure. Simpler setup, one less thing that can break.
- **Nav labels on the landing page** ("Rates" / "How It Works") replace the old gift-card-era labels since the business changed — the layout and colors otherwise match your PDF.
- The **rate board table** on the homepage still shows Title / Lowest / Rate / Higher / Rate — now representing your deposit accounts' tiers instead of gift card prices.

---

## 1. Set up Supabase

1. Go to https://supabase.com → create a project (e.g. `recio-exchange`)
2. **SQL Editor → New Query** → paste this and click **Run**:

```sql
create table users (
  id uuid primary key,
  name text not null,
  phone text unique not null,
  account_number text not null,
  bank_name text not null,
  password_hash text not null,
  status text not null default 'pending',   -- pending / approved / rejected
  balance numeric not null default 0,
  created_at timestamptz not null default now()
);

create table staff (
  id uuid primary key,
  name text not null,
  phone text unique not null,
  password_hash text not null,
  status text not null default 'pending',   -- pending / approved / rejected
  created_at timestamptz not null default now()
);

create table accounts (
  id uuid primary key default gen_random_uuid(),
  staff_id uuid references staff(id),        -- null = admin-owned
  title text not null,
  account_number text not null,
  bank_name text not null,
  image_data text,                            -- optional logo/QR, compressed image text
  lowest_amount numeric not null default 0,
  lowest_rate numeric not null default 0,
  higher_amount numeric not null default 0,
  higher_rate numeric not null default 0,
  min_amount numeric not null default 0,
  max_amount numeric not null default 0,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table trades (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id),
  account_id uuid references accounts(id),
  staff_id uuid references staff(id),
  intended_amount numeric not null,
  receipt_image text not null,
  status text not null default 'checking',   -- checking / seen / confirmed / approved / failed
  fail_reason text,
  account_number_used text,
  account_title_used text,
  user_payout_account text,
  user_payout_bank text,
  settlement_screenshot text,
  settlement_status text default 'pending',   -- pending / done
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table settings (
  id int primary key default 1,
  rules_text text default 'No scam money allowed. We do not support scam money.',
  settlement_account text default '',
  settlement_bank text default '',
  max_deposit numeric default 3000000
);
insert into settings (id) values (1);

create table messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id),
  sender text not null,        -- 'user' or 'admin'
  text text,
  image_data text,
  created_at timestamptz not null default now()
);

create table withdrawals (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id),
  amount numeric not null,
  payout_account text not null,
  payout_bank text not null,
  status text not null default 'pending',   -- pending / paid / rejected
  reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
```

3. **Project Settings → API Keys** → copy the **Project URL** and the **secret / service_role key**.

---

## 2. Install and configure

```
npm install
```

Copy `.env.example` to `.env` and fill in `ADMIN_PASSWORD`, `SESSION_SECRET`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`.

## 3. Run it

```
npm start
```

- `http://localhost:3000` — public site
- `http://localhost:3000/login.html` — customer sign up / login
- `http://localhost:3000/staff-login.html` — staff sign up / login
- `http://localhost:3000/admin.html` — your dashboard (log in with `ADMIN_PASSWORD`)

**First thing to do:** log into `/admin.html`, go to **Staff**, register a staff account from
`/staff-login.html`, then approve it from the admin dashboard. Then that staff member can add
their first account under **Check Account** in their dashboard.

---

## 4. Push to GitHub, deploy on Render

```
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/recio-exchange.git
git push -u origin main
```

On Render.com: **New Web Service** → connect the repo → Build Command `npm install` →
Start Command `npm start` → add Environment Variables:
`ADMIN_PASSWORD`, `SESSION_SECRET`, `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`.

Your site goes live at something like `https://recio-exchange.onrender.com`.

---

## Day-to-day use

- **Approve people:** Admin → Users / Staff tabs.
- **Add/manage deposit accounts:** Staff dashboard (own accounts only) or Admin → Accounts (any account, any staff).
- **Process a payment:** open the receipt image, click Confirm, Approve, or Failed (reason required for Failed).
- **Undo a mistake:** Admin → Trades → Failed on an already-Approved trade reverses the balance automatically.
- **Edit rules or the staff settlement account:** Admin → Rules & Settings.
- **Reply to a customer:** Admin → Messages.
- **Pay out a withdrawal:** Admin → Withdrawals → Mark Paid once you've sent the money, or Reject with a reason (this refunds it back to their balance automatically).
