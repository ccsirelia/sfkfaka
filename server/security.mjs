import { createCipheriv, createDecipheriv, randomBytes, createHmac, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCallback);
export function security(config) {
  const key = Buffer.from(config.encryptionKey, 'hex');
  return {
    hash: value => createHmac('sha256', config.sessionSecret).update(value).digest('hex'),
    encrypt(value) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
    },
    decrypt(value) {
      const raw = Buffer.from(value, 'base64');
      const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
      decipher.setAuthTag(raw.subarray(12, 28));
      return JSON.parse(Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8'));
    },
  };
}
export async function verifyPassword(value, stored) {
  if (typeof value !== 'string' || value.length > 256) return false;
  const [salt, hash] = stored.split(':');
  const actual = await scrypt(value, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
export function loadConfig(env = process.env) {
  for (const name of ['ENCRYPTION_KEY', 'SESSION_SECRET']) {
    if (!/^[a-f\d]{64}$/i.test(env[name] || '')) throw new Error(`${name} 未配置，请先运行 npm run setup`);
  }
  if (!/^[a-f\d]{32}:[a-f\d]{128}$/i.test(env.ADMIN_PASSWORD_HASH || '')) throw new Error('管理员密码未初始化，请先运行 npm run setup');
  const production = env.NODE_ENV === 'production' || process.argv.includes('--production');
  const origin = new URL(env.APP_ORIGIN || 'http://localhost:3200');
  if (origin.username || origin.password || origin.pathname !== '/' || origin.search || origin.hash) throw new Error('APP_ORIGIN 必须是纯站点源地址');
  if (production && origin.protocol !== 'https:') throw new Error('生产环境 APP_ORIGIN 必须使用 HTTPS');
  return { encryptionKey: env.ENCRYPTION_KEY, sessionSecret: env.SESSION_SECRET, passwordHash: env.ADMIN_PASSWORD_HASH,
    origin: origin.origin, production, secure: origin.protocol === 'https:', trustProxy: env.TRUST_PROXY === '1', dataDir: env.DATA_DIR || './data' };
}
