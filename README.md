# AZAPLUG — Manual Deposit Verification Platform

> **Already live with data in Supabase?** This update needs a few small database changes —
> run this in your Supabase SQL Editor before deploying the new code:
> ```sql
> alter table trades add column if not exists credited_amount numeric;
> alter table trades add column if not exists staff_credited_amount numeric;
> alter table trades add column if not exists fail_image text;
> alter table withdrawals add column if not exists reason_image text;
> ```
> For 6-digit PIN login, email codes, staying signed in and fingerprint login, run this one line:
> ```sql
> alter table users add column if not exists email text; alter table staff add column if not exists email text; create table if not exists sessions (sid text primary key, data jsonb not null, expires_at timestamptz not null); create table if not exists passkeys (id text primary key, kind text not null, owner_id text not null, public_key text not null, counter bigint not null default 0, created_at timestamptz not null default now()); alter table sessions enable row level security; alter table passkeys enable row level security;
> ```
> and add two Environment Variables on Render so codes can be emailed (from a free Brevo account):
> `BREVO_API_KEY` (Brevo → SMTP & API → API Keys) and `MAIL_FROM` (the sender email you verified in Brevo).
> Until both are set, sign-up works without the email code and "Forgot PIN" tells people to contact support.
>
> **Photos and voice notes** are stored in Supabase Storage (a private bucket called `media`, created automatically),
> not inside the database. Old pictures already in the database move there by themselves in the background.
> Chat photos and voice notes older than 90 days are removed (receipts are kept forever); change this with `MEDIA_DAYS` on Render.
>
> **System Health page (Admin Panel → System Health):** run this once in the Supabase SQL editor so the counts are saved and database/storage sizes show:
> ```sql
> create table if not exists app_metrics (id text primary key, value bigint not null default 0, updated_at timestamptz not null default now()); alter table app_metrics enable row level security; create or replace function app_sizes() returns json language sql security definer set search_path = public as $$ select json_build_object('db', pg_database_size(current_database()), 'storage', coalesce((select sum((metadata->>'size')::bigint) from storage.objects where bucket_id = 'media'), 0)) $$; revoke execute on function app_sizes() from public, anon, authenticated; grant execute on function app_sizes() to service_role;
> ```
> Limits can be raised when you upgrade: `LIMIT_EGRESS_GB`, `LIMIT_DB_GB`, `LIMIT_STORAGE_GB`, `LIMIT_RENDER_HOURS`, `LIMIT_RAM_MB`, `LIMIT_EMAILS_DAY`. Supabase usage resets on day `SUPABASE_CYCLE_DAY` (default 21).
>
> **Admin two-step login (Google Authenticator):** in the admin app open **Two-Step Login**, add AZAPLUG to Google Authenticator,
> check one code, then add `ADMIN_TOTP_SECRET` on Render with the key it shows. Lost the phone? Delete `ADMIN_TOTP_SECRET` on Render.
>
> > For "online", "last seen", and seen ticks in chats to be remembered after a restart, run this one line:
> ```sql
> create table if not exists chat_state (id text primary key, at timestamptz not null default now()); alter table chat_state enable row level security;
> ```
>
> > For giveaways (Admin → Giveaway), run this one line:
> ```sql
> create table if not exists giveaways (id uuid primary key default gen_random_uuid(), title text not null, amount numeric not null, winners int not null, keyword text not null default 'hi', starts_at timestamptz not null, status text not null default 'open', created_at timestamptz not null default now()); create table if not exists giveaway_entries (id uuid primary key default gen_random_uuid(), giveaway_id uuid not null references giveaways(id) on delete cascade, user_id uuid not null references users(id) on delete cascade, installed boolean not null default false, alerts_on boolean not null default false, won boolean not null default false, credited boolean not null default false, created_at timestamptz not null default now(), unique (giveaway_id, user_id)); alter table giveaways enable row level security; alter table giveaway_entries enable row level security;
> ```
>
> For **gift cards** (customers sell Apple, Amazon, Steam… cards; admin gift codes), run this one line:
> ```sql
> create table if not exists gift_cards (id uuid primary key default gen_random_uuid(), name text not null, rows jsonb not null default '[]', image text, note text, active boolean not null default true, sort int not null default 0, created_at timestamptz not null default now()); create table if not exists gift_codes (code text primary key, amount numeric not null, max_uses int not null default 1, used int not null default 0, note text, expires_at timestamptz, active boolean not null default true, created_at timestamptz not null default now()); create table if not exists gift_redemptions (id uuid primary key default gen_random_uuid(), code text not null references gift_codes(code) on delete cascade, user_id uuid not null references users(id) on delete cascade, amount numeric not null, created_at timestamptz not null default now(), unique (code, user_id)); alter table trades add column if not exists card jsonb; alter table settings add column if not exists gift_on boolean not null default true; alter table gift_cards enable row level security; alter table gift_codes enable row level security; alter table gift_redemptions enable row level security;
> ```
> Then open Admin → Gift Cards and set a rate on each card type. A card only shows to customers once it has a rate.
> The switch at the top of Admin → Gift Cards turns the whole feature off or on for customers.
> For **Gift a Friend** (customers turn their balance into a gift code), also run this one line:
> ```sql
> alter table gift_codes add column if not exists created_by uuid references users(id) on delete set null;
> ```
>
> For **card prefixes** on gift cards (Visa/Mastercard/Vanilla BINs the customer picks from), run this one line:
> ```sql
> alter table gift_cards add column if not exists prefixes jsonb not null default '[]';
> ```
> Until it is run, cards still save and sell normally — the prefix picker just does not appear.
>
> For the **December tournament on/off switch** (Admin → December Challenge), run this one line:
> ```sql
> alter table settings add column if not exists challenge_on boolean not null default true;
> ```
> Turning it off hides the tournament banner and board from customers; you can still see the leaders and pay the winners in the admin page.
>
> For the admin to message every staff member, run this one line:
> ```sql
> alter table team_messages alter column from_staff_id drop not null, alter column to_staff_id drop not null;
> ```
> **In-app calls** work with no setup on most networks. For calls on mobile data that will not connect,
> create a TURN key in Cloudflare (Realtime → TURN, 1,000 GB free) and add `CF_TURN_KEY_ID` and `CF_TURN_API_TOKEN` on Render
> (or use Metered: `METERED_DOMAIN` + `METERED_API_KEY`).
>
> For chat managers and vendors to message each other, run this one line (it also saves each staff member's department):
> ```sql
> alter table staff add column if not exists role text; create table if not exists team_messages (id uuid primary key default gen_random_uuid(), from_staff_id uuid not null references staff(id) on delete cascade, to_staff_id uuid not null references staff(id) on delete cascade, message_text text, image_data text, read_at timestamptz, created_at timestamptz not null default now()); alter table team_messages enable row level security;
> ```
>
> For forwarding a single chat message to the admin or another staff member, run this one line:
> ```sql
> create table if not exists forwards (id uuid primary key default gen_random_uuid(), from_staff_id uuid, to_staff_id uuid, user_id uuid, message_text text, image_data text, sender text, status text not null default 'new', created_at timestamptz not null default now()); alter table forwards enable row level security;
> ```
>
> For chat managers to pass a chat receipt on to an account, run this one line:
> ```sql
> alter table trades add column if not exists chat_message_id uuid;
> ```
> For the Bitcoin / USDT naira rates (set under Admin → Edit Rates), also run this one line:
> ```sql
> alter table settings add column if not exists btc_rate numeric not null default 0, add column if not exists usdt_rate numeric not null default 0;
> ```
> For **auto-paying small withdrawals through Flutterwave** (Admin → Withdrawals → Auto-pay), run this one line:
> ```sql
> alter table settings add column if not exists autopay_on boolean not null default false, add column if not exists autopay_max numeric not null default 50000, add column if not exists autopay_daily_cap numeric not null default 500000; alter table withdrawals add column if not exists method text default 'manual', add column if not exists transfer_id text, add column if not exists transfer_ref text, add column if not exists transfer_status text, add column if not exists auto_note text, add column if not exists autopay_at timestamptz; create index if not exists withdrawals_transfer_ref on withdrawals(transfer_ref);
> ```
> Then, in **Render → Environment**, add two secrets (never put these in code or GitHub):
> - `FLW_SECRET_KEY` — your Flutterwave **secret** key (`FLWSECK-...`).
> - `FLW_WEBHOOK_HASH` — any long random string; paste the **same** value into Flutterwave → Settings → Webhooks as the "Secret hash".
>
> In the Flutterwave dashboard, set the **Webhook URL** to `https://recio-exchange.onrender.com/api/flw/webhook`. Keep a funded Flutterwave balance — transfers are debited from it. Auto-pay stays **off** until you switch it on under Admin → Withdrawals, and it only ever covers withdrawals up to your set limit (default ₦50,000) with a daily ceiling (default ₦500,000); anything above waits for you to pay by hand.
> For **confirming the real account name before a withdrawal** (customer picks their bank, types the account number, the real name pops up, they confirm), run this one line:
> ```sql
> alter table users add column if not exists bank_code text, add column if not exists account_name text, add column if not exists payout_verified_at timestamptz;
> ```
> This uses the same `FLW_SECRET_KEY` as above. Once it's on, **new sign-ups confirm their account during registration** (bank + account number → real name → create), and existing customers confirm on their next withdrawal — so a withdrawal always goes to a real, checked name. (If Flutterwave isn't set up, sign-up and withdrawals keep working the old free-text way.)
> For **deleting a message so staff and the customer no longer see it, but the admin still can** (and for **pinning a message to the top of a chat**), run this one line:
> ```sql
> alter table messages add column if not exists deleted_at timestamptz, add column if not exists pinned_at timestamptz; alter table team_messages add column if not exists deleted_at timestamptz, add column if not exists pinned_at timestamptz;
> ```
> (Until you run it, deletes still work — they just remove the message for everyone, the old way — and pinning shows a reminder to run the SQL.)
> For **the admin controls** (System Health → your gains, the withdrawal charge, and maintenance mode), run this one line:
> ```sql
> alter table settings add column if not exists maintenance_on boolean not null default false, add column if not exists withdraw_charge_pct numeric not null default 0, add column if not exists gain_total numeric not null default 0, add column if not exists gain_acct_number text, add column if not exists gain_acct_bank text, add column if not exists gain_acct_code text, add column if not exists gain_acct_name text, add column if not exists charge_total numeric not null default 0, add column if not exists charge_auto_monthly boolean not null default false, add column if not exists charge_last_sweep text; alter table withdrawals add column if not exists payout_amount numeric;
> ```
> This turns on three things in **Admin → System Health**: (1) when you credit a trade the app asks **"what gain did you make?"** and adds it to your **Trade gains**, which you send to your own account with one tap; (2) a **withdrawal charge** — a % the customer pays on each withdrawal that you keep, building up as **Charge earnings** that are paid to your account **automatically every month** (or on demand); and (3) **maintenance mode**, a switch that logs every customer and staff member out until you turn it off. Set **My account** (the bank account your money is sent to) first — changing it later needs your admin password. Gains and charges are sent through the same payout provider as withdrawals (Paystack), and releasing them asks for your payout PIN. Until you run the SQL, everything else keeps working and System Health shows a one-line reminder.
> That's it — no other schema changes, nothing else to touch in Supabase.

> **Escalated chats (Admin Console)** need one more table. Run this once in the Supabase SQL Editor:
> ```sql
> create table if not exists escalations (
>   id uuid primary key default gen_random_uuid(),
>   user_id uuid not null references users(id) on delete cascade,
>   staff_id uuid references staff(id) on delete set null,
>   reason text not null,
>   status text not null default 'open',   -- open / resolved
>   admin_feedback text,
>   created_at timestamptz not null default now(),
>   updated_at timestamptz not null default now()
> );
> ```
> Until it exists, everything else keeps working; only escalating and the Admin Console show an error.

> **Push notifications and the customer Notifications screen** need three tables. Run this once:
> ```sql
> create table if not exists notifications (id uuid primary key default gen_random_uuid(), user_id uuid references users(id) on delete cascade, kind text not null default 'info', title text not null, body text not null, created_at timestamptz not null default now());
> create table if not exists push_subscriptions (endpoint text primary key, user_id uuid not null references users(id) on delete cascade, p256dh text not null, auth text not null, created_at timestamptz not null default now());
> create table if not exists push_keys (id int primary key default 1, public_key text not null, private_key text not null);
> alter table notifications enable row level security; alter table push_subscriptions enable row level security; alter table push_keys enable row level security;
> ```
> The server creates its own push key pair on first use and keeps it in `push_keys`; there are no keys to set on Render.
> On iPhone, customers must add AZAPLUG to their Home Screen before push can be turned on (Apple's rule).

> **Borrow (loans) and staff/admin alerts** need three more tables. Run this once:
> ```sql
> create table if not exists loans (id uuid primary key default gen_random_uuid(), user_id uuid not null references users(id) on delete cascade, amount numeric not null, outstanding numeric not null default 0, status text not null default 'pending', created_at timestamptz not null default now(), updated_at timestamptz not null default now());
> create table if not exists loan_config (id int primary key default 1, loan_limit numeric not null default 5000);
> create table if not exists team_push_subscriptions (endpoint text primary key, staff_id uuid references staff(id) on delete cascade, portal text not null, p256dh text not null, auth text not null, created_at timestamptz not null default now());
> alter table loans enable row level security; alter table loan_config enable row level security; alter table team_push_subscriptions enable row level security;
> ```
> Loan rules: one limit for everyone (set in the admin app), one loan at a time, approval adds the money to the customer's balance, and each credited receipt repays what is owed before anything reaches the balance.

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
