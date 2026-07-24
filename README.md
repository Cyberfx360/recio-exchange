# AZAPLUG — Manual Deposit Verification Platform

> **Already live with data in Supabase?** This update needs a few small database changes —
> run this in your Supabase SQL Editor before deploying the new code:
> ```sql
> alter table trades add column if not exists credited_amount numeric;
> alter table trades add column if not exists staff_credited_amount numeric;
> alter table trades add column if not exists fail_image text;
> alter table withdrawals add column if not exists reason_image text;
> ```
> That's it — no other schema changes, nothing else to touch in Supabase.

Customers send money into an account you provide, upload a receipt, and your team manually
verifies and credits their balance. Three roles: **Customer**, **Staff**, **Admin**.

## How the flow works

1. Customer signs up with their name, bank, and account number (all editable later from their dashboard) — they get instant access, **no approval needed**. (Staff are different — see below.)
2. Customer enters the amount they want to send. Anything over ₦3,000,000 (adjustable) is blocked — they're told to chat with you instead.
3. They're shown an account (title, account number + copy button, tiered rate) provided by one of your staff — but only once an **admin has verified it**.
4. They pay into it and upload a receipt.
5. The staff member who owns that account reviews it: **Confirm** (customer sees it), **Approve** — entering the amount *they* calculate should be credited based on the rate — or **Failed** (reason required, photo optional).
6. **Two-step verification:** staff approving does **not** touch the balance. An admin must separately open **Verify & Credit**, see the staff's proposed amount, confirm or adjust it, and only then does the balance actually update. This is also the exact moment the customer's current payout account is locked into the record permanently — safe even if they later change or delete their bank details.
7. Admin can undo a credited trade back to Failed — this reverses the balance credit automatically.
7. Staff then remit the money they collected to your settlement account and upload their own proof — tracked per trade.

## A few judgment calls I made while building this

- **Only staff need your approval** before they can act — customers get instant access after signup, exactly as you clarified.
- Admin can still **Suspend** (block) or **Delete** a customer at any time from the Users tab, even though no upfront approval is required.
- **Images (receipts, settlements, account logos) are stored as compressed text directly in the database** — no separate file-storage bucket to configure. Simpler setup, one less thing that can break.
- **Nav labels on the landing page** ("Rates" / "How It Works") replace the old gift-card-era labels since the business changed — the layout and colors otherwise match your PDF.
- The **rate board table** on the homepage still shows Title / Lowest / Rate / Higher / Rate — now representing your deposit accounts' tiers instead of gift card prices.
- **New accounts require admin verification** before customers can see them — staff-created accounts start hidden until you click Verify.
- **Two-step trade approval:** staff can propose a credit amount when they Approve, but only an admin's separate "Verify & Credit" action actually updates the customer's balance — and that's the exact moment the customer's current payout account gets locked into the record forever, even if they later edit or the account is deleted.

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
  active boolean not null default true,       -- staff-created accounts start FALSE (unverified) until admin verifies
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table trades (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id),
  account_id uuid references accounts(id),
  staff_id uuid references staff(id),
  intended_amount numeric not null,
  staff_credited_amount numeric,               -- staff's proposed credit amount (does not touch balance)
  credited_amount numeric,                     -- admin-verified final amount — this is what actually credits the balance
  receipt_image text not null,
  status text not null default 'checking',   -- checking / seen / confirmed / approved / failed
  fail_reason text,
  fail_image text,                             -- optional photo attached to a failure reason
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
  reason_image text,                          -- optional photo attached to a rejection reason
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

- **Approve staff:** Admin → Staff tab. (Customers no longer need approval — they get instant access.)
- **Verify a new account before customers can see it:** Admin → Accounts → click **Verify** on any account marked UNVERIFIED. Staff-created accounts always start unverified; admin-created ones are auto-verified.
- **Add/manage deposit accounts:** Staff dashboard (own accounts only, no rates — those are admin-only) or Admin → Accounts (any account, any staff, including rates and images).
- **Process a payment (staff):** open the receipt, click Confirm, Approve (enter the amount you calculate should be credited, based on the rate), or Failed (reason required, photo optional). Approving does **not** touch the balance yet.
- **Verify and actually credit a payment (admin only):** Admin → Trades → once a trade is staff-Approved, a **Verify & Credit Balance** button appears. Review the staff's proposed amount, confirm or adjust it, and the balance updates — this also locks in the customer's current payout account permanently.
- **Undo a mistake:** Admin → Trades → Failed on an already-credited trade reverses the balance automatically.
- **View full trade detail:** Click any trade's title (staff, admin, or customer dashboard) to see the receipt full-size plus any failure photo.
- **Edit rules or the staff settlement account:** Admin → Rules & Settings.
- **Edit a user's name, bank, or account number:** Admin → Users → Edit. Customers can also self-edit from their own dashboard.
- **Reply to a customer:** Admin → Messages.
- **Pay out a withdrawal:** Admin → Withdrawals → Mark Paid once you've sent the money (this locks in their current payout account), or Reject with a reason and optional photo (this refunds it back to their balance automatically).
