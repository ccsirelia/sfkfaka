import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, chmodSync } from 'node:fs';
import path from 'node:path';
export function openStore(config, crypto) {
  mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
  const file = path.join(config.dataDir, 'limen.sqlite');
  const db = new DatabaseSync(file);
  try { chmodSync(file, 0o600); } catch { /* Windows uses directory ACLs. */ }
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), payload TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, owner TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL, password_tag TEXT);
    CREATE TABLE IF NOT EXISTS submissions (id TEXT PRIMARY KEY, owner TEXT NOT NULL, digest TEXT NOT NULL, card_hash TEXT, account_hash TEXT NOT NULL, state TEXT NOT NULL, order_no TEXT, created INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS submissions_account ON submissions(account_hash, state);
    CREATE INDEX IF NOT EXISTS submissions_card ON submissions(card_hash, state);
    CREATE TABLE IF NOT EXISTS orders (order_no TEXT PRIMARY KEY, owner TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, created INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS orders_owner ON orders(owner, created);
    CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, action TEXT NOT NULL, created INTEGER NOT NULL);
  `);
  if (!db.prepare('PRAGMA table_info(sessions)').all().some(column => column.name === 'password_tag')) db.exec('ALTER TABLE sessions ADD COLUMN password_tag TEXT');
  const defaults = { siteName: 'LIMEN 礼门', announcement: '请确认账号信息后再兑换。提交成功后，可在订单查询中查看处理进度。', maintenance: false, allowBatch: true, supportText: '如需帮助，请联系向您提供卡密的商家。', apiKey: '', verificationSite: '' };
  if (!db.prepare('SELECT id FROM settings WHERE id=1').get()) db.prepare('INSERT INTO settings VALUES(1, ?)').run(crypto.encrypt(defaults));
  return { db,
    settings: () => ({ ...defaults, ...crypto.decrypt(db.prepare('SELECT payload FROM settings WHERE id=1').get().payload) }),
    saveSettings: settings => db.prepare('UPDATE settings SET payload=? WHERE id=1').run(crypto.encrypt(settings)),
    audit(action) { db.prepare('INSERT INTO audit(action,created) VALUES(?,?)').run(action, Date.now()); db.prepare('DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 2000)').run(); },
    saveOrder(order, owner) {
      db.prepare(`INSERT INTO orders VALUES(?,?,?,?,?) ON CONFLICT(order_no) DO UPDATE SET payload=excluded.payload,status=excluded.status`).run(order.order_no, owner, crypto.encrypt(order), order.status, Date.now());
      db.prepare('UPDATE submissions SET state=?, order_no=? WHERE order_no=?').run(order.status, order.order_no, order.order_no);
    },
    close: () => db.close(),
  };
}
