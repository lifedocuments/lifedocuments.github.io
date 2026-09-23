# Life Documents — backend

A small Express + Postgres API: accounts, documents, file uploads, and a
daily cron job that emails real expiry reminders. All data — including
uploaded file bytes — lives in a persistent Postgres database, so it
survives restarts and redeploys (unlike a local file on Render's free disk).

## What it does automatically

- **Password reset:** `/api/forgot` emails a real reset link (needs SMTP set up below).
- **Expiry reminders:** every day at 09:00 server time, it checks every document
  and emails the owner once per document per day if it's inside its alarm
  window — this runs whether or not anyone has the app open.
- **Welcome email:** sent right after signup.

Anyone can sign up and use the app — unlimited documents and file
attachments, no free/premium split.

**Admin access:** whichever account's email matches `ADMIN_EMAIL` in `.env`
gets an "Admin" view in the app showing every user and every document on the
server — the rest of the endpoints stay scoped to each person's own data.
Sign up with that exact email to become the admin. If you're offering this
to other people, be upfront with them (a line in your sign-up flow or a
privacy note) that the operator can see stored documents — it's the honest
thing to do given what's in this vault (IDs, passport numbers, etc).

## 1. Create a free persistent database (Supabase)

1. Go to supabase.com → sign up (free, no card) → New Project.
2. Set a database password (save it — you'll need it in the connection string).
3. Once created: Project Settings → Database → Connection string → "URI" tab.
   Use the **Transaction pooler** version (port 6543) if given the choice —
   it works better with serverless/free hosts than the direct connection.
4. Copy that whole string into `DATABASE_URL` in your `.env` (replace the
   `[YOUR-PASSWORD]` placeholder with the real password from step 2).

The app creates its own tables automatically the first time it starts —
nothing to set up manually in Supabase beyond creating the project.

## 2. Local run

```bash
cd backend
cp .env.example .env        # then edit .env with real values
npm install
npm start                   # API on http://localhost:4000
```

Required to get anything working: `DATABASE_URL` (above), `JWT_SECRET` (any
long random string), and the `SMTP_*` block (an email account the server can
send from — a Gmail "app password" is the fastest way to test).

## 3. Deploy somewhere that stays running

This needs a host that keeps a Node process alive (for the cron job) — not a
serverless/edge function that only runs on request.

- **Render.com** (free tier) → "New Web Service" → point at this folder →
  Build Command `npm install`, Start Command `npm start` → add every value
  from `.env.example` under Environment. Because data now lives in Supabase,
  Render's free tier is fine to use — no persistent disk needed there anymore.
- **Railway.app** → same idea, same env vars.
- Any VPS with `pm2 start server.js` also works.

Once deployed you'll have a URL like `https://your-app.onrender.com`.

## 4. Point the frontend at it

The frontend has your backend URL baked in already (see `DEFAULT_API_BASE`
near the top of the app's `<script>`). If you ever change backend URLs,
update that constant, or use `?backend=1` on the app link to reveal the
manual override field.

## Data model

Postgres tables: `users`, `documents`, `files` (file bytes stored directly
in the `data` column, not on local disk), and `notified` (so the same
reminder email isn't sent twice in one day).

No encryption at rest is applied to file contents in this version — anyone
with database access can read them, same as most small apps. If that
matters for your use case, say so and I can add encryption for stored files.

**History:** this started as SQLite (`better-sqlite3`), which failed to
compile on Render's free build image, so it became a local JSON file
instead — which worked, but was wiped on every restart/redeploy since
Render's free disk isn't persistent. Postgres via Supabase fixes both
problems at once: no native compiling, and real persistence.
