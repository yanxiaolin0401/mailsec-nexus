# 嵌套 JSON 接入与字段映射

> 本文补充[研发任务与推进计划](基于大模型的邮件数据分析与智能检索系统_研发任务与推进计划.md)及[输入输出与数据规范](邮件离线分析系统_输入输出与数据规范.md)，不改写其历史原文。接口以 `POST /api/v2/mails` 为准；原始 EML 仍走 `/v1/mail/raw` 或 `/v1/mail/upload`。

## 实际输入与封装层

[测试样例工作簿](邮件离线分析_测试样例_demo.xlsx)的第一个工作表是一行一封的**平铺表格**，A—P 共 16 列：`from`、`senderhost`、`senderaccount`、`accountnick`、`replyTo`、`allReceiverAccount`、`toaccount`、`tonick`、`subject`、`ip`、`clientip`、`attachInfos_md5`、`attachInfos_filename`、`urls`、`textContent`、`mailHeaderList`。其中 `urls` 与 `mailHeaderList` 的单元格可保存 JSON 数组**字符串**；不能因此称 XLSX 本身是嵌套 JSON。上游推送时把这些业务字段装入 `mail` 对象，并在顶层补来源/时间元数据。

主格式：

```json
{
  "sourceSystemId": "demo-gateway",
  "sourceEventId": "delivery-001",
  "eventTime": "2026-10-21T10:00:00+08:00",
  "mail": {
    "from": "通知 <notice@example.test>",
    "senderaccount": "notice@example.test",
    "toaccount": "analyst@example.test",
    "allReceiverAccount": "analyst@example.test,reviewer@example.test",
    "subject": "合成测试邮件",
    "ip": "unknown",
    "textContent": "这是一封不含真实个人数据的测试邮件。",
    "mailHeaderList": ["From: 通知 <notice@example.test>", "To: analyst@example.test"],
    "urls": [],
    "attachInfos_filename": "-",
    "attachInfos_md5": "-"
  }
}
```

兼容两种旧封装：把业务字段直接放顶层的平铺对象；或将 `mail` 换为 `data`。顶层的 `mail`、`data` 同时出现，或嵌套对象与顶层业务字段混用，均视为歧义输入；不会递归搜索任意未知层级。字段名在所选层中大小写不敏感，但不会凭相似名称猜测映射。

## 字段去向

| 输入字段 | `mail_events` 去向 / 规则 |
| --- | --- |
| 顶层 `sourceSystemId`、`sourceEventId` | `source_system_id`、`source_event_id`；两者均有效时组成幂等键。无完整来源键则每次接收生成独立 `event_id`。来源系统标识目前**不等于**已实现租户授权隔离。 |
| 顶层 `eventTime` | `event_time`；要求带时区，缺失/无效时取接收时间并加质量标签。 |
| `senderaccount`、`from`、`mailHeaderList` 中的 `From` | 按优先级提取 `sender_account`/`src_email_address`；不把展示昵称当邮箱。 |
| `allReceiverAccount`、`toaccount`、头中的 `To/Cc/Bcc` | 合并、去重为 `receiver_accounts`；首个地址为 `to_email_address`，单封多收件人仍只有一个事件。 |
| `subject`、头中的 `Subject` | `subject`，优先业务字段。 |
| `ip`、头中的 `Received` | `sender_ip`；只接受有效公网地址；从 `Received` 回退时加不可信来源标签，绝不声称已验证真实发信 IP。`clientip` 是上游声称的内部客户端地址，不能冒充网关可信 `ingress_ip`。 |
| `textContent` | 清洗有限 HTML 后存 `text_content`，供主题/正文关键词检索；缺失用 `-`。 |
| `mailHeaderList` | `mail_headers`；可用头文本、头字符串数组、`{name,value}` 数组；重复头保留顺序。工作簿中的 JSON 数组字符串也按数组解析。 |
| `urls`、正文 HTML 链接 | 合并为 `external_urls`；接受单个文本、数组及 JSON 数组字符串，不主动访问链接。 |
| `attachInfos_filename`、`attachInfos_md5` | 按位置组成 `external_attachments`；可为逗号/分号分隔字符串。也支持 `attachInfos` 对象数组中的 `filename`、`md5`、`size`。 |
| `senderhost`、`replyTo` | `sender_host`、`reply_to`；`accountnick`、`tonick` 暂不映射到独立分析列。 |

其余规范字段按约定兜底为 `-`、`unknown`、`0` 或 `[]`。未研判时 `risk_verdict` 与 `risk_level` 为 `unknown`，**不是** `pass`/`low`。规范原始 DDL 的 33 个分析列加 `text_content` 共 34 列；原规范所列 `pass`/`low` 数据库默认值不能作为未研判事件的安全结论。实际 DDL 位于 `src/mailsec_smart_search/event_schema.sql`，物理分区、排序与时间区类型不同于规范中的示例 DDL；字段基线与物理调优必须分别验收。未知扩展字段不参与业务映射；原 JSON 在受控审计存储保留，不通过列表或详情公开。字段/数组/头/正文仍受大小和数量上限限制，截断或无效输入带数据质量标签。

## 投递与可见性

`202 Accepted` 仅表示请求已写入本机 SQLite WAL FULL 持久队列，**不表示 ClickHouse 已完成写入**；worker 异步消费后才能在检索接口查到。相同 `(sourceSystemId, sourceEventId)` 加相同载荷是幂等重试；同键不同载荷返回 `409 Conflict`。没有完整来源键时每次投递都是新事件，即使内容相同。`mail_hash` 只是内容指纹，不能代替事件 ID/幂等键。

以下命令要求服务已按[部署与使用](../部署与使用.md)启动、`.env` 中已有 `MAILSEC_API_TOKEN`。写入的是合成数据；执行后用返回的 `eventId` 查询详情（异步消费可能需要稍候）。

```bash
set -a; . ./.env; set +a
curl -i -H "X-Mailsec-Token: $MAILSEC_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary '{"sourceSystemId":"demo-gateway","sourceEventId":"delivery-001","eventTime":"2026-10-21T10:00:00+08:00","mail":{"from":"通知 <notice@example.test>","senderaccount":"notice@example.test","toaccount":"analyst@example.test","subject":"合成测试邮件","textContent":"这是一封合成测试邮件。"}}' \
  http://127.0.0.1:8080/api/v2/mails
```

API 以 `X-Mailsec-Token` 鉴权。不要向外部模型发送未获授权的真实邮件；`/api/v1/nl/query` 只允许模型给出白名单过滤条件，服务端编译参数化固定 SQL，默认 `execute:false`。查询具体邮箱/IP/URL/MD5/11—19 位长数字时先做本地占位并仅将脱敏问题发送模型，再把占位绑定回受限过滤器；不支持的组织部门映射应拒绝，不能虚构。相对时间以 `Asia/Shanghai` 为锚点并按自然周解释。占位是尽力脱敏，姓名等自由文本仍可能未被识别；外发必须配置授权开关。模型不可用时基础结构化检索应继续工作。按需 `POST /api/v1/mails/{event_id}/analysis` 仅记录模型意见与限制，不伪称完成杀毒，历史结果用 `GET /api/v1/mails/{event_id}/analyses` 查看；`mail_events` 的未研判风险基线保持不变。
