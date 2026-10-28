import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes, randomUUID, scryptSync } from 'node:crypto';
import request from 'supertest';
import { createApp, UPSTREAM } from '../server/app.mjs';
import { loadConfig } from '../server/security.mjs';
import { parseBatch } from '../src/api.js';
import { mountProduction } from '../server/static.mjs';
import express from 'express';

const password = 'Integration-only-password-123!';
const salt = randomBytes(16).toString('hex');
const passwordHash = `${salt}:${scryptSync(password, salt, 64).toString('hex')}`;
function token(account = randomUUID()) {
  return { user: { email: 'tester@example.com' }, account: { id: account }, accessToken: `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ iat: Math.floor(Date.now()/1000)-10, exp: Math.floor(Date.now()/1000)+3600 })).toString('base64url')}.integration_signature`, sessionToken: 'DO-NOT-PERSIST-SESSION-SECRET' };
}
const payload = () => ({ orderType: 'card_key', cardKey: `CARD-${randomUUID()}`, token: token() });
const directPayload = () => ({ orderType: 'direct', token: token(), cardNumber: '4242424242424242', cvv: '987', expMonth: 12, expYear: 2035, planType: 'plus', country: 'PH' });
async function fixture(t, fetchOverride) {
  const dataDir = mkdtempSync(path.join(tmpdir(), 'limen-test-'));
  const calls = []; const orders = new Map(); const idempotency = new Map();
  const config = { dataDir, encryptionKey: randomBytes(32).toString('hex'), sessionSecret: randomBytes(32).toString('hex'), passwordHash, origin: 'http://localhost:3200', secure: false, production: false, trustProxy: false };
  const fetcher = async (url, options) => {
    const body = JSON.parse(options.body); calls.push({ url, options, body });
    if (fetchOverride) return fetchOverride(url, options, { calls, orders, idempotency });
    if (url.endsWith('/direct')) {
      const key = options.headers['Idempotency-Key'];
      let order = idempotency.get(key);
      if (!order) { order = { order_no: randomUUID(), order_type: body.orderType, status: 'pending', email: body.token.user.email, card_key: body.cardKey, accessToken: body.token.accessToken, cvv: body.cvv, cardNumber: body.cardNumber }; orders.set(order.order_no, order); idempotency.set(key, order); }
      return Response.json({ code: 0, data: order }, { status: 201 });
    }
    if (url.endsWith('/query')) {
      const ids = Array.isArray(body.order_no) ? body.order_no : [body.order_no];
      const found = ids.map(id=>orders.get(id)).filter(Boolean);
      return Response.json({ code: 0, data: Array.isArray(body.order_no) ? found : found[0] || null });
    }
    if (url.endsWith('/lookup')) return Response.json({ code: 0, data: [...orders.values()] });
    throw new Error('Unexpected test URL');
  };
  const runtime = createApp({ config, fetcher }); runtime.app.use(runtime.errorHandler);
  t.after(() => { runtime.close(); const resolved = path.resolve(dataDir); assert.ok(resolved.startsWith(path.join(tmpdir(), 'limen-test-'))); rmSync(resolved, { recursive: true, force: true }); });
  async function client(admin = false) {
    const agent = request.agent(runtime.app);
    let session = (await agent.get('/api/session').expect(200)).body;
    const client = { agent, get csrf() { return session.csrfToken; },
      send(method, endpoint, body, headers = {}) { return agent[method](endpoint).set('Origin',config.origin).set('X-CSRF-Token',session.csrfToken).set(headers).send(body); },
      async login() { session = (await client.send('post','/api/admin/login',{password}).expect(200)).body; },
    };
    if (admin) await client.login();
    return client;
  }
  const settings = { siteName: 'Test site', announcement: '公告', maintenance: false, allowBatch: true, supportText: '联系商家' };
  const admin = await client(true);
  await admin.send('put','/api/admin/settings',{...settings,apiKey:'test-api-key-private-123'}).expect(200);
  return { ...runtime, admin, client, calls, orders, config, settings };
}
test('管理员认证、CSRF 和来源检查保护配置及补查接口', async t => {
  const f=await fixture(t); const visitor=await f.client();
  await visitor.agent.get('/api/admin/settings').expect(401);
  await visitor.send('post','/api/admin/lookup',{cardNumber:'4242424242424242',email:'tester@example.com'}).expect(401);
  await f.admin.agent.put('/api/admin/settings').send({...f.settings}).expect(403);
  await f.admin.send('put','/api/admin/settings',f.settings,{Origin:'https://evil.example'}).expect(403);
  const result=await f.admin.agent.get('/api/admin/settings').expect(200);
  assert.equal(result.body.configured,true); assert.equal(result.body.apiKey,undefined);
  assert.equal(JSON.stringify(result.body).includes('test-api-key-private'),false);
});
test('创建请求遵循 X-API-Key、card_key 和幂等约定，响应不泄露凭据',async t=>{
  const f=await fixture(t);const c=await f.client();const p=payload();
  const result=await c.send('post','/api/orders',p,{'Idempotency-Key':randomUUID()}).expect(201);
  assert.equal(f.calls[0].url,`${UPSTREAM}/third-party/orders/direct`);
  assert.equal(f.calls[0].options.headers['X-API-Key'],'test-api-key-private-123');
  assert.equal(f.calls[0].body.orderType,'card_key');
  assert.equal(result.body.order.status,'pending');
  for(const secret of [p.cardKey,p.token.accessToken,p.token.sessionToken]) assert.ok(!JSON.stringify(result.body).includes(secret));
});
test('相同内容安全重试只创建一笔，修改同一标识内容返回冲突',async t=>{
  const f=await fixture(t);const c=await f.client();const p=payload();const key=randomUUID();
  const first=await c.send('post','/api/orders',p,{'Idempotency-Key':key}).expect(201);
  const second=await c.send('post','/api/orders',p,{'Idempotency-Key':key}).expect(200);
  assert.equal(first.body.order.order_no,second.body.order.order_no);assert.equal(f.calls.length,1);
  await c.send('post','/api/orders',{...p,cardKey:'CHANGED'}, {'Idempotency-Key':key}).expect(409);
});
test('更换标识或浏览器无法重复提交同一卡密或处理中的账号',async t=>{
  const f=await fixture(t);const c=await f.client();const p=payload();
  await c.send('post','/api/orders',p,{'Idempotency-Key':randomUUID()}).expect(201);
  const other=await f.client();
  await other.send('post','/api/orders',p,{'Idempotency-Key':randomUUID()}).expect(409);
  await c.send('post','/api/orders',{...p,cardKey:'OTHER-CARD'}, {'Idempotency-Key':randomUUID()}).expect(409);
  assert.equal(f.calls.length,1);
});
test('并发重复点击只有一个请求进入上游',async t=>{
  let release;const barrier=new Promise(resolve=>{release=resolve;});
  const f=await fixture(t,async(_u,_o)=>{await barrier;return Response.json({code:0,data:{order_no:randomUUID(),status:'pending'}});});
  const c=await f.client();const p=payload();const key=randomUUID();
  const first=c.send('post','/api/orders',p,{'Idempotency-Key':key}).then(r=>r);
  while(!f.calls.length)await new Promise(r=>setTimeout(r,5));
  await c.send('post','/api/orders',p,{'Idempotency-Key':key}).expect(409);release();
  assert.equal((await first).status,201);assert.equal(f.calls.length,1);
});
test('前台订单按浏览器隔离，管理员可查询商户订单',async t=>{
  const f=await fixture(t);const c=await f.client();const other=await f.client();
  const created=await c.send('post','/api/orders',payload(),{'Idempotency-Key':randomUUID()}).expect(201);
  const order_no=created.body.order.order_no;
  await other.send('post','/api/orders/query',{order_no}).expect(404);
  assert.equal((await other.agent.get('/api/orders').expect(200)).body.orders.length,0);
  await c.send('post','/api/orders/query',{order_no}).expect(200);
  await f.admin.send('post','/api/orders/query',{order_no}).expect(200);
});
test('批量查询最多 100 条，保留重复顺序并使用 order_no',async t=>{
  const f=await fixture(t);const c=await f.client();const created=await c.send('post','/api/orders',payload(),{'Idempotency-Key':randomUUID()}).expect(201);
  const id=created.body.order.order_no;
  const result=await c.send('post','/api/orders/query',{order_no:[id,id]}).expect(200);
  assert.equal(result.body.orders.length,2);assert.deepEqual(f.calls.at(-1).body,{order_no:[id,id]});
  await c.send('post','/api/orders/query',{order_no:Array(101).fill(id)}).expect(422);
  await c.send('post','/api/orders/query',{cardKey:'WRONG-FIELD'}).expect(422);
});
test('待核验与支付确认单独保存，并拦截重复充值',async t=>{
  const f=await fixture(t);const c=await f.client();const p=payload();
  const created=await c.send('post','/api/orders',p,{'Idempotency-Key':randomUUID()}).expect(201);const id=created.body.order.order_no;
  f.orders.set(id,{...f.orders.get(id),status:'pending_verification',payment_confirmed:false,subscription_verification_state:'needs_attention',subscription_verification_reason:'等待人工核实'});
  const result=await c.send('post','/api/orders/query',{order_no:id}).expect(200);
  assert.equal(result.body.orders[0].status,'pending_verification');assert.equal(result.body.orders[0].payment_confirmed,false);
  assert.equal(result.body.orders[0].subscription_verification_state,'needs_attention');
  await c.send('post','/api/orders',{...p,cardKey:'ANOTHER'}, {'Idempotency-Key':randomUUID()}).expect(409);
});
test('Session 有效期、字段与银行卡日期均在服务端验证',async t=>{
  const f=await fixture(t);const c=await f.client();const headers={'Idempotency-Key':randomUUID()};
  await c.send('post','/api/orders',{...payload(),token:{accessToken:'bad'}},headers).expect(422);
  const p=payload();p.token.accessToken=`eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({iat:1,exp:2})).toString('base64url')}.signature`;
  await c.send('post','/api/orders',p,headers).expect(422);
  await f.admin.send('post','/api/orders',{...directPayload(),expYear:2020},headers).expect(422);
  assert.equal(f.calls.length,0);
});
test('银行卡直充仅管理员可执行，全部套餐代码可以通过校验',async t=>{
  const f=await fixture(t);const c=await f.client();
  await c.send('post','/api/orders',directPayload(),{'Idempotency-Key':randomUUID()}).expect(403);
  for(const planType of ['go','plus','pro5','pro20','pro50'])await f.admin.send('post','/api/orders',{...directPayload(),planType},{'Idempotency-Key':randomUUID()}).expect(201);
  assert.equal(f.calls.length,5);
});
test('按卡号邮箱补查使用文档路径并持久化安全订单摘要',async t=>{
  const f=await fixture(t);
  await f.admin.send('post','/api/orders',directPayload(),{'Idempotency-Key':randomUUID()}).expect(201);
  const r=await f.admin.send('post','/api/admin/lookup',{cardNumber:'4242424242424242',email:'tester@example.com'}).expect(200);
  assert.ok(f.calls.at(-1).url.endsWith('/third-party/orders/lookup'));assert.equal(r.body.orders.length,1);
  assert.ok(!JSON.stringify(r.body).includes('4242424242424242'));
});
test('超时保留原幂等键与锁，后续原内容重试可恢复订单',async t=>{
  let attempts=0;
  const f=await fixture(t,async()=>{attempts++;if(attempts===1)throw new Error('timeout');return Response.json({code:0,data:{order_no:randomUUID(),status:'pending'}});});
  const c=await f.client();const p=payload();const key=randomUUID();
  const error=await c.send('post','/api/orders',p,{'Idempotency-Key':key}).expect(504);assert.equal(error.body.error.code,'RESULT_UNKNOWN');
  await c.send('post','/api/orders',p,{'Idempotency-Key':randomUUID()}).expect(409);
  await c.send('post','/api/orders',p,{'Idempotency-Key':key}).expect(201);
  assert.equal(f.calls[0].options.headers['Idempotency-Key'],f.calls[1].options.headers['Idempotency-Key']);
});
test('未知提交重试遭遇上游错误时仍保留锁',async t=>{
  let attempts=0;
  const f=await fixture(t,async()=>{attempts++;if(attempts===1)throw new Error('timeout');return Response.json({code:42902,data:null},{status:429});});
  const c=await f.client();const p=payload();const key=randomUUID();
  await c.send('post','/api/orders',p,{'Idempotency-Key':key}).expect(504);
  await c.send('post','/api/orders',p,{'Idempotency-Key':key}).expect(429);
  await c.send('post','/api/orders',p,{'Idempotency-Key':randomUUID()}).expect(409);
  assert.equal(f.store.db.prepare('SELECT state FROM submissions').get().state,'unknown');
});
test('只有 code=0 且 HTTP 成功才按成功处理，上游错误不回显秘密',async t=>{
  const f=await fixture(t,async()=>Response.json({code:40020,message:'secret token SHOULD-NOT-ECHO',data:null},{status:400}));
  const c=await f.client();const r=await c.send('post','/api/orders',payload(),{'Idempotency-Key':randomUUID()}).expect(400);
  assert.equal(r.body.error.code,'UPSTREAM_40020');assert.ok(!JSON.stringify(r.body).includes('SHOULD-NOT-ECHO'));
});
test('维护及删除密钥阻止创建，现有订单查询不受维护影响',async t=>{
  const f=await fixture(t);const c=await f.client();const created=await c.send('post','/api/orders',payload(),{'Idempotency-Key':randomUUID()}).expect(201);
  await f.admin.send('put','/api/admin/settings',{...f.settings,maintenance:true}).expect(200);
  await c.send('post','/api/orders',payload(),{'Idempotency-Key':randomUUID()}).expect(503);
  await c.send('post','/api/orders/query',{order_no:created.body.order.order_no}).expect(200);
  await f.admin.send('put','/api/admin/settings',{...f.settings,clearApiKey:true}).expect(200);
  assert.equal((await c.agent.get('/api/session')).body.settings.configured,false);
});
test('数据库及 WAL 不包含明文密钥、Session、卡密、邮箱或银行卡字段',async t=>{
  const f=await fixture(t);const p=directPayload();
  await f.admin.send('post','/api/orders',p,{'Idempotency-Key':randomUUID()}).expect(201);
  const c=await f.client();const card=payload();await c.send('post','/api/orders',card,{'Idempotency-Key':randomUUID()}).expect(201);
  const files=readdirSync(f.config.dataDir).filter(n=>n.startsWith('limen.sqlite'));
  for(const name of files){const bytes=readFileSync(path.join(f.config.dataDir,name));for(const value of ['test-api-key-private-123',p.token.accessToken,p.token.sessionToken,p.cardNumber,card.cardKey,'tester@example.com'])assert.equal(bytes.includes(Buffer.from(value)),false,`${name} leaked a private value`);}
});
test('登录会旋转会话，退出后原后台会话失效',async t=>{
  const f=await fixture(t);const r=await f.admin.send('post','/api/admin/logout',{}).expect(200);
  assert.equal(r.body.admin,false);await f.admin.agent.get('/api/admin/settings').expect(401);
  const c=await f.client();await c.send('post','/api/admin/login',{password:'incorrect'}).expect(401);
});
test('安全响应头、防缓存与请求体限制生效',async t=>{
  const f=await fixture(t);const c=await f.client();const r=await request(f.app).get('/api/session').expect(200);
  assert.equal(r.headers['cache-control'],'no-store');assert.equal(r.headers['x-frame-options'],'DENY');assert.ok(r.headers['content-security-policy'].includes("frame-ancestors 'none'"));
  assert.match(r.headers['set-cookie']?.join('')||'',/HttpOnly/);assert.match(r.headers['set-cookie']?.join('')||'',/SameSite=Strict/);
  await c.send('post','/api/orders',{huge:'x'.repeat(530000)}).expect(413);
});
test('生产配置拒绝默认密钥和非 HTTPS 地址',()=>{
  assert.throws(()=>loadConfig({}),/ENCRYPTION_KEY/);
  assert.throws(()=>loadConfig({ENCRYPTION_KEY:'a'.repeat(64),SESSION_SECRET:'b'.repeat(64),ADMIN_PASSWORD_HASH:passwordHash,NODE_ENV:'production',APP_ORIGIN:'http://example.com'}),/HTTPS/);
});
test('生产静态入口全部可访问，HTML 禁止长期缓存',async t=>{
  const directory=mkdtempSync(path.join(tmpdir(),'limen-test-'));
  writeFileSync(path.join(directory,'index.html'),'<!doctype html><html lang="zh-CN"><title>Production smoke</title></html>');
  t.after(()=>{assert.ok(path.resolve(directory).startsWith(path.join(tmpdir(),'limen-test-')));rmSync(directory,{recursive:true,force:true});});
  const app=express();mountProduction(app,directory);
  for(const route of ['/','/recharge','/orders','/help','/limdh-admin','/limdh-admin/settings']){
    const r=await request(app).get(route).expect(200);assert.match(r.text,/Production smoke/);assert.equal(r.headers['cache-control'],'no-cache');
  }
  await request(app).get('/admin').expect(404);await request(app).get('/.env').expect(404);await request(app).get('/data/limen.sqlite').expect(404);
});
test('管理员会话绑定密码版本，密码更改后旧权限失效',async t=>{
  const f=await fixture(t);await f.admin.agent.get('/api/admin/settings').expect(200);
  const otherSalt=randomBytes(16).toString('hex');
  f.config.passwordHash=`${otherSalt}:${scryptSync('New-password',otherSalt,64).toString('hex')}`;
  await f.admin.agent.get('/api/admin/settings').expect(401);
});
test('批量解析支持两行和 JSON 数组，拒绝重复卡密、重复账号与超额',()=>{
  const p=payload();assert.equal(parseBatch(`${p.cardKey}\n${JSON.stringify(p.token)}`).length,1);
  assert.equal(parseBatch(JSON.stringify([p])).length,1);
  assert.throws(()=>parseBatch(JSON.stringify([p,p])),/重复/);
  assert.throws(()=>parseBatch(JSON.stringify([p,{...p,cardKey:'different'}])),/账号/);
  assert.throws(()=>parseBatch(JSON.stringify(Array(51).fill(p))),/50/);
  assert.throws(()=>parseBatch('CARD\n{}\nORPHAN'),/两行/);
});
