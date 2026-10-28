let csrfToken = '';
export async function api(path, { method = 'GET', body, headers = {}, ...options } = {}) {
  let response;
  try {
    response = await fetch(`/api${path}`, { method, credentials: 'same-origin', headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(method !== 'GET' ? { 'X-CSRF-Token': csrfToken } : {}), ...headers }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}), ...options });
  } catch { throw Object.assign(new Error('网络连接中断。如正在提交，请保留原内容并使用相同提交标识重试。'), { code: 'RESULT_UNKNOWN' }); }
  let result;
  try { result = await response.json(); } catch { throw Object.assign(new Error('服务器响应异常，请保留原提交内容后重试。'), { code: 'RESULT_UNKNOWN' }); }
  if (!response.ok) throw Object.assign(new Error(result.error?.message || '请求失败，请稍后重试'), { code: result.error?.code, status: response.status });
  if (result.csrfToken) csrfToken = result.csrfToken;
  return result;
}
export async function submissionKey(payload) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(payload)));
  const digest = Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2, '0')).join('');
  const name = `limen-attempt:${digest}`;
  try {
    const existing = sessionStorage.getItem(name);
    if (existing) return existing;
    const key = crypto.randomUUID(); sessionStorage.setItem(name, key); return key;
  } catch { throw new Error('浏览器暂时无法保存提交标识，请允许本网站使用会话存储后再试。'); }
}
export function downloadJson(name, data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a'); a.href = url; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function parseSession(raw) {
  let token;
  try { token = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { throw new Error('Session 不是有效的 JSON，请复制完整内容。'); }
  if (!token || typeof token !== 'object' || !token.user?.email || !token.account?.id || typeof token.accessToken !== 'string') throw new Error('Session 需要包含 user.email、account.id 和 accessToken。');
  if (token.sessionToken !== undefined && typeof token.sessionToken !== 'string') throw new Error('sessionToken 必须是字符串。');
  try {
    const parts = token.accessToken.split('.');
    const claim = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (parts.length !== 3 || !Number.isFinite(claim.exp) || !Number.isFinite(claim.iat) || claim.exp <= Date.now() / 1000 || claim.iat > Date.now()/1000+120 || claim.iat >= claim.exp) throw new Error();
  } catch { throw new Error('accessToken 无效或已过期，请重新获取 Session。'); }
  return token;
}
export function parseCardList(raw) {
  const cards = raw.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!cards.length || cards.length > 50) throw new Error('请输入 1–50 张卡密，每行一张。');
  if (cards.some(card => card.length > 128 || /[\r\n]/.test(card))) throw new Error('每张卡密最多 128 个字符。');
  if (new Set(cards).size !== cards.length) throw new Error('卡密列表存在重复项，请检查后重试。');
  return cards;
}
export function parseBatchSessions(raw, cards) {
  const input = raw.trim();
  if (!input) throw new Error('请按卡密顺序输入 Session。');
  let sessions;
  if (input.startsWith('[')) {
    try { sessions = JSON.parse(input); } catch { throw new Error('Session JSON 数组格式不正确。'); }
  } else sessions = input.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
  if (!Array.isArray(sessions) || sessions.length !== cards.length) throw new Error(`请按顺序提供 ${cards.length} 条 Session。`);
  const accounts = new Set();
  return sessions.map((session, i) => {
    try {
      const token = parseSession(session);
      if (accounts.has(token.account.id)) throw new Error('同一账号不能在本批次重复兑换。');
      accounts.add(token.account.id);
      return { orderType: 'card_key', cardKey: cards[i].cardKey, token };
    } catch (error) { throw new Error(`第 ${i + 1} 条 Session：${error.message}`); }
  });
}
