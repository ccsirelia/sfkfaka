import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import { APP_BASE, appPath } from '../app-path.mjs';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { security, verifyPassword } from './security.mjs';
import { openStore } from './store.mjs';
import { subscriptionSchema, subscriptionInput, cleanSubscription, SUBSCRIPTION_URL } from './subscription.mjs';
import { createSchema, querySchema, lookupSchema, verifyCardSchema, recoverCardSchema, settingsSchema, parse } from './validation.mjs';

export const UPSTREAM = 'https://admin-lm.zdhxylc.shop/api/v1';
const active = ['submitting', 'unknown', 'pending', 'processing', 'pending_verification'];
const statuses = [...active, 'success', 'failed'];
const canonical = v => JSON.stringify(v && typeof v === 'object' ? (Array.isArray(v) ? v.map(x => JSON.parse(canonical(x))) : Object.fromEntries(Object.keys(v).sort().map(k => [k, JSON.parse(canonical(v[k]))]))) : v);
const safeText = value => typeof value === 'string' ? value.replace(/eyJ[A-Za-z0-9_.-]{20,}/g, '[已隐藏凭据]').replace(/\b\d{12,19}\b/g, '[已隐藏卡号]').slice(0, 500) : null;
function cleanOrder(data) {
  if (!data || typeof data.order_no !== 'string' || !/^[a-f\d-]{36}$/i.test(data.order_no) || !statuses.includes(data.status)) throw fault(502, '上游订单响应格式异常，请使用原提交标识重试', 'UPSTREAM_INVALID');
  const order = { order_no: data.order_no, status: data.status };
  for (const k of ['order_type', 'country', 'plan_type', 'email', 'payment_amount', 'payment_currency', 'failure_reason', 'subscription_verification_state', 'subscription_verification_reason', 'retry_batch_no', 'finished_at', 'created_at', 'updated_at']) {
    order[k] = safeText(data[k]);
  }
  order.payment_confirmed = data.payment_confirmed === true;
  order.is_subscription_cancelled = data.is_subscription_cancelled === 1 ? 1 : 0;
  order.retry_attempt = Number.isInteger(data.retry_attempt) ? data.retry_attempt : null;
  return order;
}
export function fault(status, message, code = 'REQUEST_ERROR') { return Object.assign(new Error(message), { status, code }); }
export function createApp({ config, fetcher = fetch }) {
  const crypto = security(config);
  const store = openStore(config, crypto);
  const { db } = store;
  const app = express();
  const routes = express.Router();
  app.disable('x-powered-by');
  if (config.trustProxy) app.set('trust proxy', 1);
  app.use(helmet({ xFrameOptions: { action: 'deny' }, contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"],
    fontSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], baseUri: ["'self'"], formAction: ["'self'"], upgradeInsecureRequests: config.secure ? [] : null,
  } }, strictTransportSecurity: config.secure ? { maxAge: 31536000, includeSubDomains: true } : false, referrerPolicy: { policy: 'no-referrer' } }));
  app.use((req, res, next) => {
    if (['GET', 'HEAD'].includes(req.method) && ['/', APP_BASE].includes(req.path)) {
      const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
      return res.redirect(308, `${appPath('/')}${query}`);
    }
    next();
  });
  app.use(appPath('/api'), (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
  const limiter = (limit, windowMs = 60000) => rateLimit({ windowMs, limit, standardHeaders: 'draft-8', legacyHeaders: false,
    message: { error: { code: 'RATE_LIMIT', message: '操作过于频繁，请稍后再试。' } } });
  app.use(appPath('/api'), limiter(100));
  app.use(express.json({ limit: '512kb', strict: true }));
  app.use(cookieParser());
  const cookieName = config.secure ? '__Host-limen_session' : 'limen_session';
  const cookieOptions = { httpOnly: true, secure: config.secure, sameSite: 'strict', path: '/', maxAge: 30 * 86400000 };
  function issueSession(res, owner, admin = 0) {
    const raw = randomBytes(32).toString('base64url');
    const id = crypto.hash(raw);
    const session = { id, owner: owner || randomBytes(24).toString('hex'), admin, expires: Date.now() + cookieOptions.maxAge, password_tag: crypto.hash(config.passwordHash) };
    db.prepare('INSERT INTO sessions(id,owner,admin,expires,password_tag) VALUES(?,?,?,?,?)').run(id, session.owner, admin, session.expires, session.password_tag);
    res.cookie(cookieName, raw, cookieOptions);
    return { session, csrf: crypto.hash(`csrf:${raw}`) };
  }
  routes.use('/api', (req, res, next) => {
    const raw = req.cookies[cookieName];
    const session = typeof raw === 'string' && raw.length < 200 ? db.prepare('SELECT * FROM sessions WHERE id=? AND expires>?').get(crypto.hash(raw), Date.now()) : null;
    if (session) { req.session = session; req.csrf = crypto.hash(`csrf:${raw}`); }
    else { const issued = issueSession(res); req.session = issued.session; req.csrf = issued.csrf; }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      if (req.get('origin') && req.get('origin') !== config.origin) return next(fault(403, '请求来源不被允许', 'ORIGIN_REJECTED'));
      if (req.get('x-csrf-token') !== req.csrf) return next(fault(403, '会话校验失败，请刷新页面后重试', 'CSRF_REJECTED'));
      if (!req.is('application/json')) return next(fault(415, '请使用 JSON 格式提交'));
    }
    next();
  });
  const isAdmin = req => req.session.admin > Date.now() && req.session.password_tag === crypto.hash(config.passwordHash);
  const adminOnly = (req, res, next) => isAdmin(req) ? next() : next(fault(401, '请先登录管理后台', 'ADMIN_REQUIRED'));
  const publicSettings = () => { const { apiKey, verificationSite, ...settings } = store.settings(); return { ...settings, configured: !!apiKey, verificationConfigured: !!verificationSite }; };
  routes.get('/api/session', (req, res) => res.json({ csrfToken: req.csrf, admin: isAdmin(req), settings: publicSettings() }));
  routes.get('/api/health', (_req, res) => res.json({ ok: true }));
  routes.post('/api/admin/login', limiter(8, 15 * 60000), async (req, res) => {
    if (!(await verifyPassword(req.body?.password, config.passwordHash))) { store.audit('login_failed'); throw fault(401, '管理员密码不正确', 'INVALID_LOGIN'); }
    const issued = issueSession(res, req.session.owner, Date.now() + 8 * 3600000);
    db.prepare('DELETE FROM sessions WHERE id=?').run(req.session.id);
    store.audit('login_success');
    res.json({ csrfToken: issued.csrf, admin: true });
  });
  routes.post('/api/admin/logout', adminOnly, (req, res) => {
    const issued = issueSession(res, req.session.owner);
    db.prepare('DELETE FROM sessions WHERE id=?').run(req.session.id);
    store.audit('logout'); res.json({ csrfToken: issued.csrf, admin: false });
  });
  routes.get('/api/admin/settings', adminOnly, (_req, res) => res.json({ ...publicSettings(), verificationSite: store.settings().verificationSite, apiBase: UPSTREAM }));
  routes.put('/api/admin/settings', adminOnly, (req, res) => {
    const value = parse(settingsSchema, req.body);
    const { clearApiKey, apiKey, ...other } = value;
    const existing = store.settings();
    store.saveSettings({ ...existing, ...other, apiKey: clearApiKey ? '' : apiKey || existing.apiKey });
    store.audit(apiKey || clearApiKey ? 'settings_and_key_updated' : 'settings_updated');
    res.json(publicSettings());
  });
  // A shared budget keeps all visitors together below the provider's 120/IP/min limit.
  let requests = [];
  function reserveUpstreamRequest() {
    const now = Date.now(); requests = requests.filter(t => t > now - 60000);
    if (requests.length >= 100) throw fault(429, '当前服务繁忙，请稍后重试', 'UPSTREAM_BUDGET');
    requests.push(now);
  }
  async function upstream(endpoint, body, idempotencyKey) {
    const apiKey = store.settings().apiKey;
    if (!apiKey) throw fault(503, '服务尚未配置，请联系商家完成 API 配置', 'NOT_CONFIGURED');
    reserveUpstreamRequest();
    let response;
    try {
      response = await fetcher(`${UPSTREAM}${endpoint}`, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(25000),
        headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey, ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}) }, body: JSON.stringify(body) });
    } catch { throw fault(504, '连接超时或中断，结果尚未确定。请保留原内容并使用相同提交标识重试，切勿重复创建订单。', 'RESULT_UNKNOWN'); }
    let payload;
    try { payload = await response.json(); } catch { throw fault(502, '上游响应异常，请保留原提交标识后重试', 'RESULT_UNKNOWN'); }
    if (!response.ok || payload.code !== 0) {
      const messages = {
        40106: '商户 API Key 缺失，请联系商家', 40107: '商户 API Key 无效，请联系商家更新', 40301: '商户已停用，请联系商家',
        40022: '商户积分不足，请联系商家', 40012: '暂无可用卡片，请联系商家', 40020: '账号预检失败，请检查 Session、套餐及账号状态',
        40009: '卡密或账号校验未通过，请检查信息或联系商家', 40402: '卡密不存在或不属于当前商户', 40403: '未找到匹配订单',
        40902: '卡密已使用，请查询原订单', 40903: '卡密不可用或已停用', 40904: '提交标识与原始内容不一致，请恢复原始内容',
        42902: '上游请求过于频繁，请稍后重试', 42200: '请求字段格式无效，请检查后重试',
      };
      const invalidToken = [40005,40006,40007,40008,40024,40025,40026,40027].includes(payload.code);
      const uncertain = response.status >= 500 || typeof payload.code !== 'number' || payload.code === 0;
      const error = fault(response.status >= 500 ? 503 : response.status >= 400 ? response.status : 502,
        messages[payload.code] || (invalidToken ? 'Session 无效或已过期，请重新获取完整 Session' : '上游暂时无法完成请求，请保留原提交标识并联系商家'), uncertain ? 'RESULT_UNKNOWN' : `UPSTREAM_${payload.code}`);
      throw error;
    }
    return payload.data;
  }
  function proofSignature(owner, site, cardKey, expires) {
    return crypto.hash(`card-verification:${owner}:${site}:${crypto.hash(cardKey)}:${expires}`);
  }
  routes.post('/api/subscription/query', limiter(10, 60000), async (req, res) => {
    const input = parse(subscriptionSchema, req.body);
    const session = subscriptionInput(input.session);
    reserveUpstreamRequest();
    let response, data;
    try {
      response = await fetcher(SUBSCRIPTION_URL, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(25000),
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chatgpt_token: session }) });
      data = await response.json();
    } catch { throw fault(503, '暂时无法连接订阅查询服务，请稍后重试。', 'SUBSCRIPTION_UNAVAILABLE'); }
    if (!response.ok) {
      if (response.status === 429) throw fault(429, '查询过于频繁，请稍后重试。', 'RATE_LIMIT');
      if ([400, 401, 422].includes(response.status)) throw fault(400, '无法确认账号或 Session 已过期，请重新获取完整 Session 后再试。', 'INVALID_SESSION');
      throw fault(503, '订阅查询服务暂时不可用，请稍后重试。', 'SUBSCRIPTION_UNAVAILABLE');
    }
    const subscription = cleanSubscription(data);
    if (!subscription) throw fault(502, '订阅查询响应异常，暂时无法确认订阅状态。', 'SUBSCRIPTION_INVALID');
    res.json({ subscription });
  });
  function validProof(proof, owner, site, cardKey) {
    if (!site || typeof proof !== 'string' || !/^\d{13}\.[a-f0-9]{64}$/.test(proof)) return false;
    const [expires, signature] = proof.split('.');
    const time = Number(expires);
    if (time <= Date.now() || time > Date.now() + 30 * 60000) return false;
    return timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(proofSignature(owner, site, cardKey, expires), 'hex'));
  }
  routes.post('/api/card-keys/verify', limiter(60, 60000), async (req, res) => {
    const { cardKey } = parse(verifyCardSchema, req.body);
    const settings = store.settings();
    if (settings.maintenance) throw fault(503, '兑换服务暂时维护中，请稍后再试', 'MAINTENANCE');
    if (!settings.apiKey || !settings.verificationSite) throw fault(503, '卡密验证尚未配置，请联系商家', 'VERIFICATION_NOT_CONFIGURED');
    if (req.get('x-batch-mode') === '1' && !settings.allowBatch) throw fault(403, '批量提交暂未开放');
    const cardHash = crypto.hash(cardKey);
    if (db.prepare("SELECT id FROM submissions WHERE card_hash=? AND state!='failed'").get(cardHash)) throw fault(409, '此卡密已有订单或未确定的提交，请先查询原订单，不要重复充值。', 'ORDER_LOCKED');
    reserveUpstreamRequest();
    let response, data;
    try {
      response = await fetcher(`https://admin-lm.zdhxylc.shop/api/v2/sites/${encodeURIComponent(settings.verificationSite)}/preview`, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(15000), headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ redeem_code: cardKey }),
      });
      data = await response.json();
    } catch { throw fault(503, '暂时无法验证卡密，请稍后重试', 'VERIFICATION_UNAVAILABLE'); }
    if (!response.ok) {
      if (response.status === 400 || response.status === 409) throw fault(400, '卡密无效、不可用或不属于本站，请检查后联系商家', 'CARD_INVALID');
      if (response.status === 429) throw fault(429, '卡密验证过于频繁，请稍后重试', 'RATE_LIMIT');
      throw fault(503, '暂时无法验证卡密，请稍后重试', 'VERIFICATION_UNAVAILABLE');
    }
    if (!data || typeof data !== 'object' || typeof (data.plan_label || data.plan) !== 'string' || !(data.plan_label || data.plan).trim()) throw fault(502, '上游验证响应异常，请稍后重试', 'VERIFICATION_UNAVAILABLE');
    const expires = String(Date.now() + 30 * 60000);
    res.json({ verificationToken: `${expires}.${proofSignature(req.session.owner, settings.verificationSite, cardKey, expires)}`, expiresAt: Number(expires), planLabel: safeText(data.plan_label || data.plan) });
  });
  routes.post('/api/card-keys/recover', limiter(20, 60000), (req, res) => {
    const { cardKey, submissionKey } = parse(recoverCardSchema, req.body);
    const id = crypto.hash(`${req.session.owner}:${submissionKey}`);
    const row = db.prepare("SELECT card_hash FROM submissions WHERE id=? AND owner=? AND state='unknown'").get(id, req.session.owner);
    if (!row || row.card_hash !== crypto.hash(cardKey)) throw fault(404, '未找到匹配的待确认提交，请核对卡密和原提交标识，或联系商家。', 'RECOVERY_NOT_FOUND');
    res.json({ recoverable: true, message: '已找到原提交。请填写原来的 Session，系统只会尝试恢复相同内容。' });
  });
  function rememberOrder(data, owner) { const order = cleanOrder(data); store.saveOrder(order, owner); return order; }
  routes.post('/api/orders', limiter(60, 3600000), async (req, res) => {
    const input = parse(createSchema, req.body);
    if (input.orderType === 'direct' && !isAdmin(req)) throw fault(403, '银行卡直充仅限管理员使用', 'ADMIN_REQUIRED');
    const settings = store.settings();
    if (settings.maintenance) throw fault(503, '兑换服务暂时维护中，请稍后再试', 'MAINTENANCE');
    if (!settings.apiKey) throw fault(503, '服务尚未配置，请联系商家完成 API 配置', 'NOT_CONFIGURED');
    if (req.get('x-batch-mode') === '1' && !settings.allowBatch) throw fault(403, '批量提交暂未开放');
    const clientKey = req.get('idempotency-key') || '';
    if (!/^[A-Za-z\d_-]{1,128}$/.test(clientKey)) throw fault(422, '必须提供有效的 Idempotency-Key 提交标识');
    const id = crypto.hash(`${req.session.owner}:${clientKey}`);
    const digest = crypto.hash(canonical(input));
    const existing = db.prepare('SELECT * FROM submissions WHERE id=?').get(id);
    if (existing && existing.digest !== digest) throw fault(409, '同一提交标识的内容不能改变', 'IDEMPOTENCY_CONFLICT');
    if (existing?.order_no) {
      const row = db.prepare('SELECT payload FROM orders WHERE order_no=?').get(existing.order_no);
      return res.json({ order: crypto.decrypt(row.payload), reused: true });
    }
    if (existing?.state === 'submitting') throw fault(409, '原请求正在提交，请等待后查询', 'IN_FLIGHT');
    // An uncertain earlier submission must be retried with its original key even if its card is now consumed.
    if (input.orderType === 'card_key' && !existing && !validProof(req.get('x-card-verification'), req.session.owner, settings.verificationSite, input.cardKey)) {
      throw fault(403, '请先验证当前卡密；验证过期或修改卡密后需要重新验证', 'CARD_VERIFICATION_REQUIRED');
    }
    const cardHash = input.orderType === 'card_key' ? crypto.hash(input.cardKey) : null;
    const accountHash = crypto.hash(input.token.account.id);
    if (!existing) {
      const accountLock = db.prepare(`SELECT id FROM submissions WHERE account_hash=? AND state IN ('submitting','unknown','pending','processing','pending_verification')`).get(accountHash);
      const cardLock = cardHash && db.prepare("SELECT id FROM submissions WHERE card_hash=? AND state!='failed'").get(cardHash);
      if (accountLock || cardLock) throw fault(409, '此卡密或账号已有订单或未确定的提交，请先查询原订单；待核验时不要重复充值。', 'ORDER_LOCKED');
      db.prepare('INSERT INTO submissions VALUES(?,?,?,?,?,?,?,?)').run(id, req.session.owner, digest, cardHash, accountHash, 'submitting', null, Date.now());
    } else db.prepare('UPDATE submissions SET state=? WHERE id=?').run('submitting', id);
    try {
      const data = await upstream('/third-party/orders/direct', input, id);
      const order = rememberOrder(data, req.session.owner);
      db.prepare('UPDATE submissions SET order_no=?,state=? WHERE id=?').run(order.order_no, order.status, id);
      store.audit('order_created'); res.status(201).json({ order });
    } catch (error) {
      if (existing?.state === 'unknown' || ['RESULT_UNKNOWN', 'UPSTREAM_INVALID'].includes(error.code) || !error.status) db.prepare('UPDATE submissions SET state=? WHERE id=?').run('unknown', id);
      else db.prepare('DELETE FROM submissions WHERE id=?').run(id);
      throw error;
    }
  });
  routes.post('/api/orders/query', async (req, res) => {
    const input = parse(querySchema, req.body);
    const ids = Array.isArray(input.order_no) ? input.order_no : [input.order_no];
    if (!isAdmin(req)) {
      for (const id of ids) if (!db.prepare('SELECT order_no FROM orders WHERE order_no=? AND owner=?').get(id, req.session.owner)) throw fault(404, '未找到当前浏览器的订单，请核对订单号，跨设备查询请联系商家', 'ORDER_NOT_FOUND');
    }
    const result = await upstream('/third-party/orders/query', input);
    const rows = Array.isArray(result) ? result : result ? [result] : [];
    const orders = rows.filter(row => ids.includes(row.order_no)).map(data => {
      const current = db.prepare('SELECT owner FROM orders WHERE order_no=?').get(data.order_no);
      return rememberOrder(data, current?.owner || req.session.owner);
    });
    res.json({ orders });
  });
  routes.get('/api/orders', (req, res) => {
    const rows = db.prepare('SELECT payload FROM orders WHERE owner=? ORDER BY created DESC LIMIT 100').all(req.session.owner);
    res.json({ orders: rows.map(row => crypto.decrypt(row.payload)) });
  });
  routes.post('/api/admin/lookup', adminOnly, async (req, res) => {
    const input = parse(lookupSchema, req.body);
    const result = await upstream('/third-party/orders/lookup', input);
    if (!Array.isArray(result)) throw fault(502, '补查响应格式异常');
    const orders = result.map(data => {
      const current = db.prepare('SELECT owner FROM orders WHERE order_no=?').get(data.order_no);
      return rememberOrder(data, current?.owner || req.session.owner);
    });
    store.audit('order_lookup'); res.json({ orders });
  });
  routes.get('/api/admin/overview', adminOnly, (_req, res) => {
    const counts = db.prepare('SELECT status,COUNT(*) AS total FROM orders GROUP BY status').all();
    res.json({ counts, recentOrders: db.prepare('SELECT payload FROM orders ORDER BY created DESC LIMIT 100').all().map(row => crypto.decrypt(row.payload)),
      audit: db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 20').all(),
      unresolved: db.prepare("SELECT COUNT(*) AS total FROM submissions WHERE state='unknown'").get().total });
  });
  routes.use('/api', (_req, _res, next) => next(fault(404, '接口不存在')));
  // Recover interrupted process requests with their original upstream idempotency keys.
  db.prepare("UPDATE submissions SET state='unknown' WHERE state='submitting'").run();
  const cleanup = setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<?').run(Date.now()), 3600000);
  cleanup.unref();
  const errorHandler = (error, _req, res, _next) => {
    const status = error.type === 'entity.too.large' ? 413 : error.type === 'entity.parse.failed' ? 400 : error.status || 500;
    const message = status === 413 ? '提交内容过大，请减少批量数量' : error.type === 'entity.parse.failed' ? 'JSON 格式错误' : status >= 500 && !error.status ? '服务器暂时无法处理请求' : error.message;
    res.status(status).json({ error: { code: error.code || 'REQUEST_ERROR', message } });
  };
  app.use(APP_BASE, routes);
  return { app, store, errorHandler, close() { clearInterval(cleanup); store.close(); } };
}
