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
export function parseBatch(raw) {
  const input = raw.trim();
  if (!input) throw new Error('请粘贴或导入批量兑换内容。');
  let rows;
  if (input.startsWith('[')) {
    try { rows = JSON.parse(input); } catch { throw new Error('批量 JSON 数组格式不正确。'); }
    if (!Array.isArray(rows)) throw new Error('请使用 JSON 数组格式。');
  } else {
    const lines = input.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    if (lines.length % 2) throw new Error('每组需要两行：第一行卡密，第二行完整 Session JSON。');
    rows = [];
    for (let i = 0; i < lines.length; i += 2) rows.push({ cardKey: lines[i], token: lines[i+1] });
  }
  if (!rows.length || rows.length > 50) throw new Error('每批支持 1–50 组兑换。');
  const cards = new Set(); const accounts = new Set();
  return rows.map((row, index) => {
    try {
      if (typeof row.cardKey !== 'string' || !row.cardKey.trim() || row.cardKey.trim().length > 128) throw new Error('卡密长度应为 1–128 个字符。');
      const token = parseSession(row.token);
      const cardKey = row.cardKey.trim();
      if (cards.has(cardKey)) throw new Error('卡密在本批次重复。');
      if (accounts.has(token.account.id)) throw new Error('同一账号不能在本批次重复兑换。');
      cards.add(cardKey); accounts.add(token.account.id);
      return { orderType: 'card_key', cardKey, token };
    } catch (error) { throw new Error(`第 ${index + 1} 组：${error.message}`); }
  });
}
