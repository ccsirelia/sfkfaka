import { z } from 'zod';
const token = z.object({
  user: z.object({ email: z.email().max(255) }).passthrough(),
  account: z.object({ id: z.string().min(1).max(256) }).passthrough(),
  accessToken: z.string().min(10).max(40000), sessionToken: z.string().max(40000).optional(),
}).passthrough().superRefine((value, ctx) => {
  try {
    const pieces = value.accessToken.split('.');
    if (pieces.length !== 3) throw new Error();
    const jwt = JSON.parse(Buffer.from(pieces[1], 'base64url').toString());
    const now = Date.now() / 1000;
    if (!Number.isFinite(jwt.iat) || !Number.isFinite(jwt.exp) || jwt.exp <= now || jwt.iat > now + 120 || jwt.iat >= jwt.exp) throw new Error();
  } catch { ctx.addIssue({ code: 'custom', message: 'accessToken 格式无效或已过期，请重新获取完整 Session' }); }
});
const cdk = z.object({ orderType: z.literal('card_key'), cardKey: z.string().trim().min(1).max(128), token }).strict();
const direct = z.object({ orderType: z.literal('direct'), token, country: z.string().regex(/^[A-Z]{2}$/).default('PH'),
  cardNumber: z.string().regex(/^\d{12,19}$/), cvv: z.string().regex(/^\d{3,4}$/),
  expMonth: z.number().int().min(1).max(12), expYear: z.number().int().min(2000).max(2099),
  planType: z.enum(['go', 'plus', 'pro5', 'pro20', 'pro50']) }).strict().refine(value => {
    const now = new Date();
    return value.expYear > now.getUTCFullYear() || (value.expYear === now.getUTCFullYear() && value.expMonth >= now.getUTCMonth() + 1);
  }, '银行卡已过期');
export const createSchema = z.discriminatedUnion('orderType', [cdk, direct]);
export const uuid = z.uuid();
export const querySchema = z.object({ order_no: z.union([uuid, z.array(uuid).min(1).max(100)]) }).strict();
export const lookupSchema = z.object({ cardNumber: z.string().regex(/^\d{12,19}$/), email: z.email().max(255) }).strict();
export const settingsSchema = z.object({
  apiKey: z.string().trim().min(8).max(512).regex(/^[\x21-\x7e]+$/).optional(),
  clearApiKey: z.boolean().optional(), siteName: z.string().trim().min(1).max(30),
  announcement: z.string().trim().max(300), maintenance: z.boolean(), allowBatch: z.boolean(),
  supportText: z.string().trim().max(150),
}).strict().refine(v => !(v.apiKey && v.clearApiKey), '不能同时设置和删除密钥');
export function parse(schema, input) {
  const result = schema.safeParse(input);
  if (!result.success) {
    const issue = result.error.issues[0];
    const error = new Error(`${issue.path.join('.') || '请求'}：${issue.message}`);
    error.status = 422; error.code = 'VALIDATION_ERROR'; throw error;
  }
  return result.data;
}
