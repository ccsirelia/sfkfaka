import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { randomBytes, scryptSync } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
if (!existsSync('.env')) { console.error('请先运行 npm run setup'); process.exit(1); }
const env = readFileSync('.env', 'utf8');
if (!/^ADMIN_PASSWORD_HASH=.+$/m.test(env)) { console.error('未找到有效的 ADMIN_PASSWORD_HASH，请检查 .env'); process.exit(1); }
const password = randomBytes(18).toString('base64url'); const salt = randomBytes(16).toString('hex');
const hash = `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
const dir = env.match(/^DATA_DIR=(.+)$/m)?.[1].trim().replace(/^['"]|['"]$/g, '') || './data';
const database = path.resolve(dir, 'limen.sqlite');
if (existsSync(database)) {
  const db = new DatabaseSync(database); db.exec('PRAGMA busy_timeout=5000');
  db.prepare('UPDATE sessions SET admin=0').run(); db.close();
}
const temp = `.env.reset-${randomBytes(6).toString('hex')}`;
writeFileSync(temp, env.replace(/^ADMIN_PASSWORD_HASH=.+$/m, `ADMIN_PASSWORD_HASH=${hash}`), { mode: 0o600, flag: 'wx' });
renameSync(temp, '.env');
console.log(`管理员新密码（请保存）：\n\n${password}\n\n请重启服务使新密码生效。现有管理员会话已降为普通访客。`);
