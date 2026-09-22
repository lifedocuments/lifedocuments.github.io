# Life Documents — backend

A small Express + SQLite API: accounts, documents, file uploads, a free/premium
plan, and a daily cron job that emails real expiry reminders.

## What it does automatically

- **Password reset:** `/api/forgot` emails a real reset link (needs SMTP set up below).
- **Expiry reminders:** every day at 09:00 server time, it checks every document
  and emails the owner once per document per day if it's inside its alarm
  window — this runs whether or not anyone has the app open.

Anyone can sign up and use the app — unlimited documents and file
attachments, no free/premium split. The `plan` column is still in the
database (harmless, unused) in case you want that split back later.

**Admin access:** whichever account's email matches `ADMIN_EMAIL` in `.env`
gets an "Admin" view in the app showing every user and every document on the
server — the rest of the endpoints stay scoped to each person's own data.
Sign up with that exact email to become the admin. If you're offering this
to other people, be upfront with them (a line in your sign-up flow or a
privacy note) that the operator can see stored documents — it's the honest
thing to do given what's in this vault (IDs, passport numbers, etc).

## 1. Local run

```bash
cd backend
cp .env.example .env        # then edit .env with real values
npm install
npm start                   # API on http://localhost:4000
```

`.env` walks through every value, but the two you must set to get anything
working: `JWT_SECRET` (any long random string) and the `SMTP_*` block (an
email account the server can send from — a Gmail "app password" is the
fastest way to test).

## 2. Deploy somewhere that stays running

This needs a host that keeps a Node process alive (for the cron job) — not a
serverless/edge function that only runs on request. Easiest free-tier options:

- **Render.com** → "New Web Service" → point at this folder → set Build
  Command `npm install`, Start Command `npm start` → add the `.env` values
  under Environment. Render's free disk is ephemeral, so for real use attach
  a persistent disk (Render → Disks) mounted where `DB_PATH` and
  `UPLOAD_DIR` point, or you'll lose data on redeploy.
- **Railway.app** → similar: new project from this folder, same env vars,
  attach a volume for the SQLite file and uploads.
- Any VPS (a $5 droplet, etc.) with `pm2 start server.js` also works fine and
  keeps disk storage naturally.

Once deployed you'll have a URL like `https://your-app.onrender.com`.

## 3. Point the frontend at it

Open the published Life Documents page → the small "Backend" link on the
sign-in screen → paste that URL in. It's saved in the browser so it only
needs doing once per device.

## Data model

SQLite file (`data.sqlite` by default) with `users`, `documents`, `files`
(uploaded file metadata; the actual bytes sit in `uploads/`), and `notified`
(so the same reminder email isn't sent twice in one day). No encryption at
rest is applied to file contents in this version — anyone with server/disk
access can read them, same as most small apps. If that matters for your use
case, say so and I can add server-side encryption for stored files.
