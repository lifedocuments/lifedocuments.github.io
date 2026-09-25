// Postgres-backed store (e.g. a free Supabase project). Replaces the old
// local JSON file, which Render's free tier wipes on every restart/redeploy.
// Uploaded file BYTES also live in this database now (not on local disk),
// for the same reason — local disk isn't persistent on the free tier either.
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('supabase') ? { rejectUnauthorized: false } : undefined
});

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      password_hash TEXT NOT NULL,
      plan TEXT NOT NULL DEFAULT 'free',
      reset_token TEXT,
      reset_expires BIGINT,
      created_at BIGINT NOT NULL
    );
    -- Added after the table already existed in production, so a plain
    -- CREATE TABLE IF NOT EXISTS above won't add it to existing databases.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at BIGINT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_device TEXT;
    -- When the weekly "use your vault" follow-up email was last sent, so a
    -- server restart (or a manually-triggered sweep) can't double-send it
    -- to someone who already got this week's email.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_weekly_email_at BIGINT;
    -- App Lock: a PIN re-entry lock on top of the normal sign-in, for
    -- someone who's already signed in on a shared/unlocked device.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_enabled BOOLEAN NOT NULL DEFAULT false;
    -- First-login guided tour: the highest tour version this account has
    -- seen. 0 means never seen. Bumping CURRENT_TOUR_VERSION in server.js
    -- (e.g. when a major new feature ships) makes it resurface once for
    -- everyone, without resetting anything else about the account.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS intro_seen_version INTEGER NOT NULL DEFAULT 0;
    -- Family Vault: named profiles (Me, Wife, Children, Parents, ...) that
    -- documents and subscriptions can optionally be tagged with. Everything
    -- still lives under one account/login — this is just a grouping tag.
    CREATE TABLE IF NOT EXISTS profiles(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      relation TEXT NOT NULL DEFAULT 'other',
      created_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_profiles_user ON profiles(user_id);
    CREATE TABLE IF NOT EXISTS documents(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      holder TEXT,
      number TEXT,
      issue TEXT,
      expiry TEXT,
      lead INTEGER NOT NULL DEFAULT 30,
      notes TEXT,
      created_at BIGINT NOT NULL
    );
    -- Snapshot of prior expiry/number/issue kept whenever a document is
    -- renewed (its expiry date is changed to a new one), so old versions
    -- stay available for insurance claims, visa applications, etc.
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS history JSONB NOT NULL DEFAULT '[]';
    -- Automatic Categories: Vehicle / Education / Property / Other, or
    -- anything the user types themselves — free text, not a fixed list.
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS category TEXT;
    -- Family Vault tag (optional — the free-text "holder" field still works
    -- on its own for a one-off "Shop" or similar that isn't a real profile).
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS profile_id TEXT;
    -- Smart Reminder System: how many days before expiry to email about it.
    -- Replaces the old single "lead" cutoff with a customizable milestone
    -- list (default 180/90/30/7/1 days before) — "lead" is kept as-is for
    -- the countdown color, this is only for which emails go out and when.
    ALTER TABLE documents ADD COLUMN IF NOT EXISTS reminder_days INTEGER[] NOT NULL DEFAULT '{180,90,30,7,1}';
    -- Document Bundles: named groups (e.g. "Travel Documents", "Car
    -- Documents") a document can belong to, purely for viewing/filtering
    -- together in-app. A document can be in more than one bundle.
    CREATE TABLE IF NOT EXISTS bundles(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      name TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_bundles_user ON bundles(user_id);
    CREATE TABLE IF NOT EXISTS bundle_items(
      id TEXT PRIMARY KEY,
      bundle_id TEXT NOT NULL REFERENCES bundles(id),
      document_id TEXT NOT NULL REFERENCES documents(id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS uniq_bundle_item ON bundle_items(bundle_id, document_id);
    CREATE INDEX IF NOT EXISTS idx_bundle_items_bundle ON bundle_items(bundle_id);
    CREATE INDEX IF NOT EXISTS idx_bundle_items_doc ON bundle_items(document_id);
    CREATE TABLE IF NOT EXISTS files(
      id TEXT PRIMARY KEY,
      document_id TEXT NOT NULL REFERENCES documents(id),
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      mime TEXT,
      size INTEGER,
      data BYTEA NOT NULL,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notified(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      document_id TEXT NOT NULL,
      sent_date TEXT NOT NULL
    );
    -- Which reminder milestone (e.g. "30 days before") has already been
    -- emailed for a document, so each one only ever fires once per expiry.
    ALTER TABLE notified ADD COLUMN IF NOT EXISTS milestone INTEGER;
    CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id);
    CREATE INDEX IF NOT EXISTS idx_files_document ON files(document_id);
    CREATE INDEX IF NOT EXISTS idx_notified_lookup ON notified(document_id, sent_date);
    CREATE INDEX IF NOT EXISTS idx_notified_milestone ON notified(document_id, milestone);

    -- Subscription & Payment Reminder: recurring bills, separate from the
    -- one-time-expiry documents above (own tab, own reminder sweep).
    CREATE TABLE IF NOT EXISTS subscriptions(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      profile_id TEXT,
      category TEXT NOT NULL DEFAULT 'other',
      name TEXT NOT NULL,
      amount TEXT,
      recurrence TEXT NOT NULL DEFAULT 'monthly',
      next_due TEXT,
      reminder_days INTEGER[] NOT NULL DEFAULT '{7,3,1,0}',
      notes TEXT,
      last_paid_at BIGINT,
      created_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
    CREATE TABLE IF NOT EXISTS sub_notified(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      subscription_id TEXT NOT NULL,
      milestone INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_sub_notified_lookup ON sub_notified(subscription_id, milestone);

    -- Admin Broadcast/Announcement tool: the admin writes one message and
    -- chooses, per broadcast, whether it goes by email, shows in-app (bell
    -- icon + inbox), or both — and whether it goes to every account or one
    -- specific account. broadcast_reads only gets a row once a recipient
    -- actually opens their inbox, rather than fanning out a row per user at
    -- send time, so "unread" is just "no row here yet" for that user.
    CREATE TABLE IF NOT EXISTS broadcasts(
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'both',
      audience TEXT NOT NULL DEFAULT 'all',
      target_user_id TEXT REFERENCES users(id),
      send_push BOOLEAN NOT NULL DEFAULT false,
      created_at BIGINT NOT NULL
    );
    -- send_push is a separate on/off toggle from channel (email/inapp/both),
    -- added after the table already existed in production, so it needs an
    -- explicit migration for databases created before this column existed.
    ALTER TABLE broadcasts ADD COLUMN IF NOT EXISTS send_push BOOLEAN NOT NULL DEFAULT false;
    CREATE INDEX IF NOT EXISTS idx_broadcasts_created ON broadcasts(created_at);
    CREATE TABLE IF NOT EXISTS broadcast_reads(
      broadcast_id TEXT NOT NULL REFERENCES broadcasts(id),
      user_id TEXT NOT NULL REFERENCES users(id),
      read_at BIGINT NOT NULL,
      PRIMARY KEY (broadcast_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_broadcast_reads_user ON broadcast_reads(user_id);

    -- Web Push subscriptions, so the admin can get a real phone notification
    -- (even with the app closed) when something happens, e.g. a new signup.
    -- Keyed by user_id (not hardcoded to one row) so it keeps working if
    -- more than one admin account is ever added later.
    CREATE TABLE IF NOT EXISTS push_subscriptions(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      endpoint TEXT UNIQUE NOT NULL,
      p256dh TEXT NOT NULL,
      auth TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);

    -- User-submitted suggestions/feedback, with an optional single photo or
    -- PDF attachment (stored the same way document files are — as bytes in
    -- the database, not on local disk, since Render's free tier disk isn't
    -- persistent).
    CREATE TABLE IF NOT EXISTS suggestions(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      message TEXT NOT NULL,
      file_name TEXT,
      file_mime TEXT,
      file_size INTEGER,
      file_data BYTEA,
      created_at BIGINT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_suggestions_created ON suggestions(created_at);
  `);
}

module.exports = {
  init,

  // ---- users ----
  async insertUser(u) {
    await pool.query(
      `INSERT INTO users(id,name,email,phone,password_hash,plan,reset_token,reset_expires,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [u.id, u.name, u.email, u.phone, u.password_hash, u.plan, u.reset_token, u.reset_expires, u.created_at]
    );
  },
  async findUserByEmail(email) {
    const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
    return r.rows[0] || null;
  },
  async findUserById(id) {
    const r = await pool.query('SELECT * FROM users WHERE id=$1', [id]);
    return r.rows[0] || null;
  },
  async findUserByResetToken(token) {
    const r = await pool.query('SELECT * FROM users WHERE reset_token=$1', [token]);
    return r.rows[0] || null;
  },
  async updateUser(id, patch) {
    const keys = Object.keys(patch);
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE users SET ${sets} WHERE id=$1`, [id, ...keys.map(k => patch[k])]);
  },
  // `q` filters by name/email/phone (case-insensitive substring); the
  // actual sort (including "most documents", which needs the join in
  // server.js) is applied by the caller after merging in document counts.
  async listUsers({ q } = {}) {
    if (q) {
      const like = `%${String(q).toLowerCase()}%`;
      const r = await pool.query(
        `SELECT id,name,email,phone,created_at,last_login_at FROM users
         WHERE LOWER(name) LIKE $1 OR LOWER(email) LIKE $1 OR LOWER(COALESCE(phone,'')) LIKE $1
         ORDER BY created_at DESC`,
        [like]
      );
      return r.rows;
    }
    const r = await pool.query('SELECT id,name,email,phone,created_at,last_login_at FROM users ORDER BY created_at DESC');
    return r.rows;
  },
  async touchLastLogin(id, device) {
    await pool.query('UPDATE users SET last_login_at=$2, last_login_device=$3 WHERE id=$1', [id, Date.now(), device || null]);
  },
  // Everyone, with how many documents they have and how many of those are
  // missing an expiry date — enough to pick which weekly follow-up email
  // (empty vault / add expiry dates / general check-in) each person gets.
  async weeklyEmailCandidates() {
    const r = await pool.query(`
      SELECT u.id, u.name, u.email, u.last_weekly_email_at,
        COUNT(d.id)::int AS doc_count,
        COUNT(*) FILTER (WHERE d.id IS NOT NULL AND (d.expiry IS NULL OR d.expiry = ''))::int AS missing_expiry_count
      FROM users u
      LEFT JOIN documents d ON d.user_id = u.id
      GROUP BY u.id
    `);
    return r.rows;
  },
  async markWeeklyEmailSent(id, ts) {
    await pool.query('UPDATE users SET last_weekly_email_at=$2 WHERE id=$1', [id, ts]);
  },
  async docCountsByUser() {
    const r = await pool.query('SELECT user_id, COUNT(*)::int c FROM documents GROUP BY user_id');
    const m = {};
    r.rows.forEach(row => { m[row.user_id] = row.c; });
    return m;
  },
  // Top-line counts for the admin stats bar. "Expiring this week" and
  // "overdue" only look at documents with a well-formed YYYY-MM-DD expiry.
  async adminStats() {
    const users = await pool.query('SELECT COUNT(*)::int c FROM users');
    const docs = await pool.query('SELECT COUNT(*)::int c FROM documents');
    const expiry = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE expiry::date < CURRENT_DATE)::int AS overdue,
        COUNT(*) FILTER (WHERE expiry::date >= CURRENT_DATE AND expiry::date < CURRENT_DATE + INTERVAL '7 days')::int AS expiring_this_week
      FROM documents
      WHERE expiry ~ '^\\d{4}-\\d{2}-\\d{2}$'
    `);
    return {
      totalUsers: users.rows[0].c,
      totalDocuments: docs.rows[0].c,
      expiringThisWeek: expiry.rows[0].expiring_this_week,
      overdue: expiry.rows[0].overdue,
    };
  },

  // ---- documents ----
  async insertDocument(d) {
    await pool.query(
      `INSERT INTO documents(id,user_id,type,title,holder,number,issue,expiry,lead,notes,category,profile_id,reminder_days,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [d.id, d.user_id, d.type, d.title, d.holder, d.number, d.issue, d.expiry, d.lead, d.notes,
        d.category || null, d.profile_id || null, d.reminder_days || [180, 90, 30, 7, 1], d.created_at]
    );
  },
  async findDocument(id, userId) {
    const r = await pool.query('SELECT * FROM documents WHERE id=$1 AND user_id=$2', [id, userId]);
    return r.rows[0] || null;
  },
  async listDocumentsByUser(userId) {
    const r = await pool.query('SELECT * FROM documents WHERE user_id=$1 ORDER BY created_at', [userId]);
    return r.rows;
  },
  async updateDocument(id, patch) {
    const keys = Object.keys(patch);
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE documents SET ${sets} WHERE id=$1`, [id, ...keys.map(k => patch[k])]);
  },
  async deleteDocument(id) {
    await pool.query('DELETE FROM documents WHERE id=$1', [id]);
  },
  async allDocumentsWithExpiry() {
    const r = await pool.query(`
      SELECT documents.*, users.email AS user_email
      FROM documents JOIN users ON users.id = documents.user_id
      WHERE documents.expiry IS NOT NULL AND documents.expiry <> ''
    `);
    return r.rows;
  },

  // ---- bundles (Document Bundles) ----
  async insertBundle(b) {
    await pool.query(
      'INSERT INTO bundles(id,user_id,name,created_at) VALUES($1,$2,$3,$4)',
      [b.id, b.user_id, b.name, b.created_at]
    );
  },
  async listBundlesByUser(userId) {
    const r = await pool.query('SELECT * FROM bundles WHERE user_id=$1 ORDER BY created_at', [userId]);
    return r.rows;
  },
  async findBundle(id, userId) {
    const r = await pool.query('SELECT * FROM bundles WHERE id=$1 AND user_id=$2', [id, userId]);
    return r.rows[0] || null;
  },
  async updateBundle(id, patch) {
    const keys = Object.keys(patch);
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE bundles SET ${sets} WHERE id=$1`, [id, ...keys.map(k => patch[k])]);
  },
  async deleteBundle(id) {
    await pool.query('DELETE FROM bundle_items WHERE bundle_id=$1', [id]);
    await pool.query('DELETE FROM bundles WHERE id=$1', [id]);
  },
  // All (bundle_id, document_id) pairs across every bundle this user owns,
  // so the client can build a full membership map in one round trip.
  async listBundleItemsByUser(userId) {
    const r = await pool.query(
      `SELECT bi.bundle_id, bi.document_id FROM bundle_items bi
       JOIN bundles b ON b.id = bi.bundle_id WHERE b.user_id=$1`,
      [userId]
    );
    return r.rows;
  },
  async insertBundleItem(it) {
    await pool.query(
      'INSERT INTO bundle_items(id,bundle_id,document_id) VALUES($1,$2,$3) ON CONFLICT (bundle_id,document_id) DO NOTHING',
      [it.id, it.bundle_id, it.document_id]
    );
  },
  async deleteBundleItem(bundleId, documentId) {
    await pool.query('DELETE FROM bundle_items WHERE bundle_id=$1 AND document_id=$2', [bundleId, documentId]);
  },
  async deleteBundleItemsByDocument(documentId) {
    await pool.query('DELETE FROM bundle_items WHERE document_id=$1', [documentId]);
  },

  // ---- profiles (Family Vault) ----
  async insertProfile(p) {
    await pool.query(
      'INSERT INTO profiles(id,user_id,name,relation,created_at) VALUES($1,$2,$3,$4,$5)',
      [p.id, p.user_id, p.name, p.relation || 'other', p.created_at]
    );
  },
  async listProfilesByUser(userId) {
    const r = await pool.query('SELECT * FROM profiles WHERE user_id=$1 ORDER BY created_at', [userId]);
    return r.rows;
  },
  async findProfile(id, userId) {
    const r = await pool.query('SELECT * FROM profiles WHERE id=$1 AND user_id=$2', [id, userId]);
    return r.rows[0] || null;
  },
  async updateProfile(id, patch) {
    const keys = Object.keys(patch);
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE profiles SET ${sets} WHERE id=$1`, [id, ...keys.map(k => patch[k])]);
  },
  async deleteProfile(id) {
    // Untag anything that pointed at this profile rather than leaving a
    // dangling reference or blocking the delete.
    await pool.query('UPDATE documents SET profile_id=NULL WHERE profile_id=$1', [id]);
    await pool.query('UPDATE subscriptions SET profile_id=NULL WHERE profile_id=$1', [id]);
    await pool.query('DELETE FROM profiles WHERE id=$1', [id]);
  },

  // ---- reminder milestones (documents) ----
  async findNotifiedMilestone(documentId, milestone) {
    const r = await pool.query('SELECT id FROM notified WHERE document_id=$1 AND milestone=$2', [documentId, milestone]);
    return r.rows[0] || null;
  },
  async insertNotifiedMilestone(n) {
    await pool.query(
      'INSERT INTO notified(id,user_id,document_id,sent_date,milestone) VALUES($1,$2,$3,$4,$5)',
      [n.id, n.user_id, n.document_id, n.sent_date, n.milestone]
    );
  },

  // ---- subscriptions (Subscription & Payment Reminder) ----
  async insertSubscription(s) {
    await pool.query(
      `INSERT INTO subscriptions(id,user_id,profile_id,category,name,amount,recurrence,next_due,reminder_days,notes,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [s.id, s.user_id, s.profile_id || null, s.category || 'other', s.name, s.amount || '',
        s.recurrence || 'monthly', s.next_due || '', s.reminder_days || [7, 3, 1, 0], s.notes || '', s.created_at]
    );
  },
  async findSubscription(id, userId) {
    const r = await pool.query('SELECT * FROM subscriptions WHERE id=$1 AND user_id=$2', [id, userId]);
    return r.rows[0] || null;
  },
  async listSubscriptionsByUser(userId) {
    const r = await pool.query('SELECT * FROM subscriptions WHERE user_id=$1 ORDER BY created_at', [userId]);
    return r.rows;
  },
  async updateSubscription(id, patch) {
    const keys = Object.keys(patch);
    if (!keys.length) return;
    const sets = keys.map((k, i) => `${k}=$${i + 2}`).join(', ');
    await pool.query(`UPDATE subscriptions SET ${sets} WHERE id=$1`, [id, ...keys.map(k => patch[k])]);
  },
  async deleteSubscription(id) {
    await pool.query('DELETE FROM sub_notified WHERE subscription_id=$1', [id]);
    await pool.query('DELETE FROM subscriptions WHERE id=$1', [id]);
  },
  async allSubscriptionsWithDue() {
    const r = await pool.query(`
      SELECT subscriptions.*, users.email AS user_email
      FROM subscriptions JOIN users ON users.id = subscriptions.user_id
      WHERE subscriptions.next_due IS NOT NULL AND subscriptions.next_due <> ''
    `);
    return r.rows;
  },
  async findSubNotifiedMilestone(subscriptionId, milestone) {
    const r = await pool.query('SELECT id FROM sub_notified WHERE subscription_id=$1 AND milestone=$2', [subscriptionId, milestone]);
    return r.rows[0] || null;
  },
  async insertSubNotifiedMilestone(n) {
    await pool.query(
      'INSERT INTO sub_notified(id,user_id,subscription_id,milestone) VALUES($1,$2,$3,$4)',
      [n.id, n.user_id, n.subscription_id, n.milestone]
    );
  },
  async deleteSubNotifiedBySubscription(subscriptionId) {
    await pool.query('DELETE FROM sub_notified WHERE subscription_id=$1', [subscriptionId]);
  },

  // ---- files ----
  async insertFile(f) {
    await pool.query(
      `INSERT INTO files(id,document_id,user_id,name,mime,size,data,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [f.id, f.document_id, f.user_id, f.name, f.mime, f.size, f.data, f.created_at]
    );
  },
  async findFile(id, userId) {
    const r = await pool.query('SELECT * FROM files WHERE id=$1 AND user_id=$2', [id, userId]);
    return r.rows[0] || null;
  },
  async findFileById(id) {
    const r = await pool.query('SELECT * FROM files WHERE id=$1', [id]);
    return r.rows[0] || null;
  },
  async listFilesByUser(userId) {
    const r = await pool.query('SELECT id,document_id,name,mime,size FROM files WHERE user_id=$1', [userId]);
    return r.rows;
  },
  async listFilesByDocument(docId) {
    const r = await pool.query('SELECT id,document_id,name,mime,size FROM files WHERE document_id=$1', [docId]);
    return r.rows;
  },
  async deleteFile(id) {
    await pool.query('DELETE FROM files WHERE id=$1', [id]);
  },
  async deleteFilesByDocument(docId) {
    await pool.query('DELETE FROM files WHERE document_id=$1', [docId]);
  },

  // ---- notified ----
  async findNotified(docId, date) {
    const r = await pool.query('SELECT id FROM notified WHERE document_id=$1 AND sent_date=$2', [docId, date]);
    return r.rows[0] || null;
  },
  async insertNotified(n) {
    await pool.query('INSERT INTO notified(id,user_id,document_id,sent_date) VALUES($1,$2,$3,$4)', [n.id, n.user_id, n.document_id, n.sent_date]);
  },
  async deleteNotifiedByDocument(docId) {
    await pool.query('DELETE FROM notified WHERE document_id=$1', [docId]);
  },

  // ---- admin broadcasts / announcements ----
  async insertBroadcast(b) {
    await pool.query(
      `INSERT INTO broadcasts(id,title,body,channel,audience,target_user_id,send_push,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [b.id, b.title, b.body, b.channel, b.audience, b.target_user_id || null, !!b.send_push, b.created_at]
    );
  },
  async listBroadcasts(limit) {
    const r = await pool.query(
      `SELECT b.*, u.name AS target_name, u.email AS target_email
       FROM broadcasts b LEFT JOIN users u ON u.id = b.target_user_id
       ORDER BY b.created_at DESC LIMIT $1`,
      [limit || 50]
    );
    return r.rows;
  },
  async listAllUsersBasic() {
    const r = await pool.query('SELECT id, name, email FROM users');
    return r.rows;
  },
  // Every broadcast this account can see in its in-app inbox (channel
  // 'inapp' or 'both', and either sent to everyone or targeted at them),
  // newest first, each flagged with whether they've opened their inbox
  // since it went out.
  async listAnnouncementsForUser(userId) {
    const r = await pool.query(
      `SELECT b.id, b.title, b.body, b.created_at, (br.user_id IS NOT NULL) AS read
       FROM broadcasts b
       LEFT JOIN broadcast_reads br ON br.broadcast_id = b.id AND br.user_id = $1
       WHERE (b.channel = 'inapp' OR b.channel = 'both')
         AND (b.audience = 'all' OR b.target_user_id = $1)
       ORDER BY b.created_at DESC LIMIT 50`,
      [userId]
    );
    return r.rows;
  },
  async markBroadcastRead(broadcastId, userId, ts) {
    await pool.query(
      `INSERT INTO broadcast_reads(broadcast_id,user_id,read_at) VALUES($1,$2,$3)
       ON CONFLICT (broadcast_id,user_id) DO NOTHING`,
      [broadcastId, userId, ts || Date.now()]
    );
  },
  async markAllBroadcastsRead(userId, ts) {
    await pool.query(
      `INSERT INTO broadcast_reads(broadcast_id,user_id,read_at)
       SELECT b.id, $1, $2 FROM broadcasts b
       WHERE (b.channel = 'inapp' OR b.channel = 'both')
         AND (b.audience = 'all' OR b.target_user_id = $1)
       ON CONFLICT (broadcast_id,user_id) DO NOTHING`,
      [userId, ts || Date.now()]
    );
  },

  // ---- push subscriptions (phone notifications, any signed-in user) ----
  async insertPushSubscription(s) {
    await pool.query(
      `INSERT INTO push_subscriptions(id,user_id,endpoint,p256dh,auth,created_at)
       VALUES($1,$2,$3,$4,$5,$6)
       ON CONFLICT (endpoint) DO UPDATE SET user_id=$2, p256dh=$4, auth=$5`,
      [s.id, s.user_id, s.endpoint, s.p256dh, s.auth, s.created_at]
    );
  },
  async listPushSubscriptionsByUser(userId) {
    const r = await pool.query('SELECT * FROM push_subscriptions WHERE user_id=$1', [userId]);
    return r.rows;
  },
  // Every device, across every user — used to push a broadcast sent to
  // "everyone" with the push channel turned on.
  async listAllPushSubscriptions() {
    const r = await pool.query('SELECT * FROM push_subscriptions');
    return r.rows;
  },
  async deletePushSubscriptionByEndpoint(endpoint) {
    await pool.query('DELETE FROM push_subscriptions WHERE endpoint=$1', [endpoint]);
  },

  // ---- suggestions ----
  async insertSuggestion(s) {
    await pool.query(
      `INSERT INTO suggestions(id,user_id,message,file_name,file_mime,file_size,file_data,created_at)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [s.id, s.user_id, s.message, s.file_name || null, s.file_mime || null, s.file_size || null, s.file_data || null, s.created_at]
    );
  },
  // Newest first, joined with the sender's name/email — never selects the
  // file bytes here, so listing stays cheap even with large attachments.
  async listSuggestionsForAdmin(limit) {
    const r = await pool.query(
      `SELECT s.id, s.message, s.file_name, s.created_at, u.name, u.email
       FROM suggestions s JOIN users u ON u.id = s.user_id
       ORDER BY s.created_at DESC LIMIT $1`,
      [limit || 100]
    );
    return r.rows;
  },
  async findSuggestionFile(id) {
    const r = await pool.query('SELECT file_name, file_mime, file_data FROM suggestions WHERE id=$1', [id]);
    return r.rows[0] || null;
  }
};
