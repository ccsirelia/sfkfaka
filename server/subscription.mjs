import { z } from 'zod';

export const subscriptionSchema = z.object({ session: z.string().trim().min(10).max(100000) }).strict();
export const SUBSCRIPTION_URL = 'https://admin-lm.zdhxylc.shop/api/v2/recharge/subscription-query';

export function subscriptionInput(raw) {
  try {
    const input = raw.startsWith('{') ? JSON.parse(raw) : { accessToken: raw };
    const token = input.accessToken;
    if (typeof token !== 'string' || token.length > 40000 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token)) throw new Error();
    const claim = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
    const now = Date.now() / 1000;
    if (!Number.isFinite(claim.exp) || !Number.isFinite(claim.iat) || claim.exp <= now || claim.iat > now + 120 || claim.iat >= claim.exp) throw new Error();
    // Only the fields needed to identify the account are forwarded. Refresh credentials stay out of this request.
    const session = { accessToken: token };
    if (typeof input.user?.email === 'string' && input.user.email.length <= 255) session.user = { email: input.user.email };
    if (typeof input.account?.id === 'string' && input.account.id.length <= 256) session.account = { id: input.account.id };
    return JSON.stringify(session);
  } catch {
    throw Object.assign(new Error('Session 无效或已过期，请重新获取完整 Session JSON 或 accessToken。'), { status: 422, code: 'INVALID_SESSION' });
  }
}

export function cleanSubscription(data) {
  if (!data || typeof data.has_active_subscription !== 'boolean' || typeof data.plan !== 'string' || !data.plan.trim() || data.plan.length > 100) return null;
  const text = value => typeof value === 'string' && value.length <= 255 ? value.replace(/[\x00-\x1f\x7f]/g, '') : null;
  const date = value => typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value)) ? value : null;
  return {
    active: data.has_active_subscription, plan: text(data.plan), email: text(data.email),
    startedAt: date(data.subscription_started_at), expiresAt: date(data.expires_at),
    willRenew: typeof data.will_renew === 'boolean' ? data.will_renew : null,
    billingPeriod: text(data.billing_period), currency: text(data.billing_currency),
    accountStatus: text(data.account_status), paymentChannel: text(data.payment_channel), checkedAt: new Date().toISOString(),
  };
}
