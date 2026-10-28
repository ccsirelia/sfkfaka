# 商户 API 对接文档

通过商户专属 API Key 接入充值。API 订单与商户工作台共用充值策略、积分规则和订单记录。

API Base URL：`https://admin-lm.zdhxylc.shop/api/v1`

## 接入约定

1. 在个人中心获取 API Key，在请求头传入 `X-API-Key`。
2. 准备完整 Session 和银行卡或商户 CDK，创建订单。
3. 保存响应的 `data.order_no`，使用该订单号轮询最终结果。

使用 JSON / UTF-8；生产环境使用 HTTPS。成功需同时满足 HTTP 2xx 和 `code=0`。创建成功表示已受理，最终是否成功以订单查询为准。

### 统一响应

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

推荐创建请求携带 `Idempotency-Key`（1–128 字符，每笔业务单一个值）。同一 Key、相同内容重试返回原订单及原始 order\_no；不同内容返回 40904。不携带时，直充重复提交可能产生多笔订单。

密钥重新生成后旧 Key 立即失效，新 Key 仍可查询本商户历史 API 订单。接口不会返回 Session、CVV 或完整银行卡号。仅商户主账户支持 API Key。

积分按平台实际配置结算。创建订单预留成功、失败扣分的较大值，结算后释放多余预留；创建失败不扣分。

## 创建订单

`POST /third-party/orders/direct`

首次创建返回 HTTP 201；幂等重试返回 HTTP 200。通过 orderType 选择 direct 或 card\_key。

| 字段 | 要求 |
| --- | --- |
| orderType | 必填：direct（提交银行卡）或 card\_key（使用本商户 CDK） |
| token | 必填对象：user.email、account.id、accessToken。可选 sessionToken 必须是字符串，其他 Session 字段原样保存。accessToken 须包含有效 iat / exp。 |
| country | 可选，默认 PH；支持地区以平台当前配置为准。CDK 使用自身配置地区。 |
| cardNumber / expMonth / expYear / cvv | 直充必填：12–19 位卡号字符串；1–12 的整数月份；2000–2099 的整数年份且未过期；3–4 位安全码字符串。 |
| planType | 直充必填：go、plus、pro5、pro20、pro50。pro50 对应 Pro x50（系统套餐代码 pro\_x50）；套餐及所选地区须在平台启用并配置价格。 |
| cardKey | CDK 模式必填，1–128 字符；仅接受当前商户所属、未使用且有效的 CDK。无需银行卡和 planType。 |

### 直充请求（测试卡号仅用于说明）

```bash
curl -X POST "https://admin-lm.zdhxylc.shop/api/v1/third-party/orders/direct" \
  -H "X-API-Key: <你的 API Key>" \
  -H "Content-Type: application/json" \
  -d '{
  "orderType": "direct",
  "cardNumber": "4242424242424242",
  "expMonth": 12,
  "expYear": 2032,
  "cvv": "123",
  "planType": "plus",
  "country": "PH",
  "token": {
    "user": {
      "email": "user@example.com"
    },
    "account": {
      "id": "account-example"
    },
    "accessToken": "<有效的 ChatGPT accessToken>",
    "sessionToken": ""
  }
}'
```

### CDK 请求

```bash
curl -X POST "https://admin-lm.zdhxylc.shop/api/v1/third-party/orders/direct" \
  -H "X-API-Key: <你的 API Key>" \
  -H "Content-Type: application/json" \
  -d '{
  "orderType": "card_key",
  "cardKey": "PLUS-EXAMPLE",
  "token": {
    "user": {
      "email": "user@example.com"
    },
    "account": {
      "id": "account-example"
    },
    "accessToken": "<有效的 ChatGPT accessToken>",
    "sessionToken": ""
  }
}'
```

### 创建响应核心字段

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "order_no": "8d24b518-a2be-4f14-bd86-3f9a5c18df01",
    "card_key": "DIRECT-兼容标识",
    "order_type": "direct",
    "plan_type": "plus",
    "email": "user@example.com",
    "status": "pending",
    "message": "下单成功，订单已进入队列，请轮询查询最终结果"
  }
}
```

**两种模式统一使用 data.order\_no 查询订单。**该值与商户「订单记录」中的订单号一致，请保存完整 UUID。

`data.card_key` 保留为兼容响应字段，不用于订单查询。direct 模式返回系统生成的 `DIRECT-...` 标识，下单时无需提供 cardKey；card\_key 模式返回本次使用的 CDK，创建请求仍使用 `cardKey` 传入 CDK。

创建前会检查 Session 字段、accessToken 格式与有效期，并执行账号预检。检查未通过时直接返回 HTTP 400、非零 code、具体失败原因 message 和 data: null，不创建订单，也不预留或扣除积分。请根据 message 修正信息后重新提交。

### 账号预检失败示例（HTTP 400）

```json
{
  "code": 40020,
  "message": "ChatGPT Token 无效或已过期。",
  "data": null
}
```

## 订单查询

`POST /third-party/orders/query`

**请求字段名是 order\_no，值取自创建响应的 data.order\_no。**direct 和 card\_key 模式使用相同格式；查询结果精确对应这个订单号，与商户「订单记录」一致。

| 入参 | 类型 / 必填 | 取值说明 |
| --- | --- | --- |
| `order_no` | 字符串 / 必填 | 单笔：填写创建成功返回的 data.order\_no，即完整订单 UUID。 |
| `order_no` | 字符串数组 / 必填 | 批量：填写多个完整订单 UUID，最多 100 个。与单笔格式二选一。 |

### 字段对应关系（JavaScript）

```javascript
// createResponse 为创建订单成功后的响应 JSON
const queryRequest = {
  order_no: createResponse.data.order_no
};
// 将 queryRequest 作为 JSON 请求体提交至 /third-party/orders/query
```

### 单笔查询

```bash
curl -X POST "https://admin-lm.zdhxylc.shop/api/v1/third-party/orders/query" \
  -H "X-API-Key: <你的 API Key>" \
  -H "Content-Type: application/json" \
  -d '{
  "order_no": "8d24b518-a2be-4f14-bd86-3f9a5c18df01"
}'
```

### 批量请求体

```json
{
  "order_no": [
    "8d24b518-a2be-4f14-bd86-3f9a5c18df01",
    "8d24b518-a2be-4f14-bd86-3f9a5c18df02"
  ]
}
```

单笔返回对象；批量每次 1–100 个，返回数组，保持请求顺序（含重复项），跳过不存在或不属于本商户的订单。全部未匹配时返回空数组。

旧路径 `POST /third-party/orders/status` 保留为兼容入口，但入参同样改为 `order_no`，不再接受 cardKey。新增接入请使用 /orders/query。

### 成功订单响应示例

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "order_no": "8d24b518-a2be-4f14-bd86-3f9a5c18df01",
    "order_type": "direct",
    "country": "PH",
    "plan_type": "plus",
    "card_key": "DIRECT-兼容标识",
    "email": "user@example.com",
    "pay_link": null,
    "payment_amount": "15.75",
    "payment_currency": "USD",
    "is_subscription_cancelled": 1,
    "retry_batch_no": "8d24b518-a2be-4f14-bd86-3f9a5c18df01",
    "retry_attempt": 1,
    "status": "success",
    "failure_reason": null,
    "payment_result": {
      "success": true,
      "failure_detail": null
    },
    "finished_at": "2026-09-27 12:01:00",
    "created_at": "2026-09-27 12:00:00",
    "updated_at": "2026-09-27 12:01:00"
  }
}
```

- `pending / processing`：排队 / 处理中，继续查询。
- `pending_verification`：订阅结果待核验，不能按成功或失败处理，禁止重复创建充值订单。根据 subscription\_verification\_state 判断是否等待自动核验或联系商家处理。
- `success`：订阅成功，停止轮询。
- `failed`：该笔订单失败或取消，查看 failure\_reason，停止轮询该订单。

| 订阅核验字段 | 说明 |
| --- | --- |
| `payment_confirmed` | 布尔值：true 表示支付已确认成功；false 表示尚未确认支付成功，不能据此判定未扣款或支付失败。pending\_verification 本身不代表已扣款。 |
| `subscription_verification_state` | 可选字符串：needs\_attention（首次核验未能确认，待人工核验）、succeeded（核验成功）、failed（人工确认失败）；未进入此流程时为 null。 |
| `subscription_verification_reason` | 可选字符串：当前核验说明。待核验订单请展示此字段，不能当作充值失败原因。 |

### 支付成功、订阅待核验的响应核心字段

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "order_no": "8d24b518-a2be-4f14-bd86-3f9a5c18df01",
    "status": "pending_verification",
    "payment_confirmed": true,
    "subscription_verification_state": "needs_attention",
    "subscription_verification_reason": "支付已成功，首次核验未确认目标订阅，请人工核实。",
    "failure_reason": null
  }
}
```

### 支付已提交、支付结果尚未确认的响应核心字段

```json
{
  "code": 0,
  "message": "success",
  "data": {
    "order_no": "8d24b518-a2be-4f14-bd86-3f9a5c18df01",
    "status": "pending_verification",
    "payment_confirmed": false,
    "subscription_verification_state": "needs_attention",
    "subscription_verification_reason": "支付已提交，首次核验未确认最终结果，请人工核实。",
    "failure_reason": null
  }
}
```

pending / checking 时后台持续核验订阅，请延迟查询同一个 order\_no；不会再次支付。needs\_attention 时停止自动轮询并联系商家核实，仍为 pending\_verification，不能按失败退款或重新充值。商户可在订单详情安排重新核验。核验成功后 status 变为 success；取消自动续费的结果独立记录，不会把订阅成功改成充值失败。

建议每 3 秒查询一次，30 秒后每 5–10 秒查询。设置总超时并保留 order\_no 供后续查询。每个来源 IP 每分钟最多 120 次 API 请求（含失败请求）。

时间为北京时间 YYYY-MM-DD HH:mm:ss。pay\_link 固定 null；payment\_amount 为实际扣款金额字符串，未确定时为 null；金额币种见 payment\_currency。is\_subscription\_cancelled 为 0 / 1，退订处理可能晚于充值完成，请稍后补查。

原订单的 order\_no 保持不变，重试会另建订单并生成新的 order\_no。查询原订单号始终返回原订单，不会自动切换到最新重试订单。API 订单产生的重试订单可使用其新订单号查询，可从订单记录或卡号邮箱补查结果中获取。失败原因与商户订单记录一致，payment\_result 仅返回结果摘要。

## 按卡号和邮箱补查

`POST /third-party/orders/lookup`

### cURL

```bash
curl -X POST "https://admin-lm.zdhxylc.shop/api/v1/third-party/orders/lookup" \
  -H "X-API-Key: <你的 API Key>" \
  -H "Content-Type: application/json" \
  -d '{
  "cardNumber": "4242424242424242",
  "email": "user@example.com"
}'
```

cardNumber 为完整的 12–19 位数字字符串，email 为订单邮箱（1–255 字符）。仅查询当前商户通过 API 创建的订单；返回数组，每条业务链取最新重试记录，按创建时间倒序排列。可保存补查结果中的 order\_no，再通过订单查询接口查询该笔订单。无匹配返回 40403。

## 错误码与处理

| code | HTTP | 含义与处理 |
| --- | --- | --- |
| 40106 / 40107 | 401 | 缺少或无效的 API Key；重新生成后请更新调用方配置 |
| 40301 | 403 | 商户已停用，请联系平台管理员 |
| 40005–40008 | 400 | Session 缺少有效字段，请提交完整 Session JSON |
| 40024–40027 | 400 | accessToken 格式或有效期无效，请重新获取 Session |
| 40022 | 400 | 积分不足，请补充积分或等待在途订单释放预留 |
| 40012 | 400 | 没有可用卡片，请检查商户卡池 |
| 40020 / 40009 | 400 | 直充 / CDK 业务校验失败，具体原因见 message |
| 40402 / 40403 | 404 | 卡密 / API 订单不存在，或不属于当前商户 |
| 40902 / 40903 | 409 | 卡密已使用、不可用或已停用 |
| 40904 | 409 | 同一幂等键用于不同请求；重试时应保持原内容 |
| 42200 | 422 | 请求字段类型、必填项或格式无效 |
| 42902 | 429 | 请求过于频繁，请降低频率并延迟重试 |
| 50300 / 50001 | 503 / 500 | 维护中或服务异常，先查询已有订单，再决定是否重试 |

错误响应为 `{"code": 40403, "message": "订单不存在", "data": null}`。网络中断或超时不代表订单未创建：已拿到 order\_no 时先查询；未拿到时使用相同 Idempotency-Key 重试，或按卡号和邮箱补查。
