import { randomBytes, scryptSync } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
if (existsSync('.env')) {
  console.error('.env 已存在，初始化已停止，现有密钥不会被覆盖。重置管理员密码请参考 README。');
  process.exit(1);
}
const password = randomBytes(18).toString('base64url');
const salt = randomBytes(16).toString('hex');
const hash = `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
writeFileSync('.env', `PORT=3200\nHOST=127.0.0.1\nAPP_ORIGIN=http://localhost:3200\nENCRYPTION_KEY=${randomBytes(32).toString('hex')}\nSESSION_SECRET=${randomBytes(32).toString('hex')}\nADMIN_PASSWORD_HASH=${hash}\nDATA_DIR=./data\nTRUST_PROXY=0\n`, { mode: 0o600, flag: 'wx' });
console.log(`初始化完成。请妥善保存以下随机管理员密码（仅显示本次）：\n\n${password}\n\n后台入口：http://localhost:3200/kmdh/limdh-admin\n生产部署前必须修改 APP_ORIGIN 并配置 HTTPS。`);
