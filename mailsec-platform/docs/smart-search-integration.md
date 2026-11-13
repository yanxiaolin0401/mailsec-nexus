# Smart-search 接入勘察

2026-10-22，已实现首期平台 BFF；隔离 ClickHouse 合成数据联调通过，结果见 `reports/integration-smoke.json`。HTTP 采用进程内 ASGI 桥接，不等于完整 Compose 网络链路验收。

## 2026-10-30 Cloud 对接更新

平台现已适配两条独立链路，不再只查询 JSON 事件：

| 平台请求 | source=event（API 默认） | source=legacy（页面默认） |
| --- | --- | --- |
| `POST /api/platform/v1/mail/search` | `GET /api/v1/mails` | `POST /v1/search` |
| `POST /api/platform/v1/mail/stats` | `GET /api/v1/stats` | `POST /v1/stats` |
| `GET /api/platform/v1/mail/{id}?source=…` | `/api/v1/mails/{event_id}` | `/v1/mail/{mail_id}` |

`subject` 映射为 `subject_contains`；legacy 的 `q` 仅映射为 `body_contains`，不能声称是跨字段关键词；sender/recipient 保持上游语义。legacy 风险过滤返回 422。每条路径复用服务端会话、专用实例租户绑定及操作审计。

历史列表 `total=null`，使用上游 `may_have_more`；当前页条数不是总数，总数通过统计接口单独读取。事件列表按已知 total 翻页；历史空尾页仍可返回上一页；offset 上限 10000，需缩小筛选范围继续调查。发送时间为 null 时明确缺失，不拿入库时间填充。

数据查询默认超时 30 秒，可用 `SMART_SEARCH_TIMEOUT_SECONDS` 调整；健康检查仍为 3 秒。上游错误通用化，不回传内部主机或凭据。Cloud 启动与只读验收见 [平台说明](../README.md#clickhouse-cloud-联调复用已运行的-smart-search)。

## 已有能力

后端：`mailsec-smart-search/src/mailsec_smart_search/{api,event_api,event_storage}.py`。
JSON 搜索使用 `GET /api/v1/mails`，统计为 `GET /api/v1/stats`（仅 total），详情为 `GET /api/v1/mails/{event_id}`。
自然语言计划使用 `POST /api/v1/nl/query`，请求 `{text, execute:false}`；依赖模型配置，不可用应明确呈现。
接入为 `POST /api/v2/mails`，202 表示持久接收；`GET /api/v2/jobs/{job_id}` 查询完成状态。
健康接口为 `/health/live`、`/health/ready`。
旧 EML 使用独立 `/v1/*` 链路，不能将 EML 样本量当作 JSON 事件数量。

## 平台适配边界

浏览器 → `/api/platform/v1` → 服务端鉴权/范围校验 → smart-search。
内部请求使用 `X-Mailsec-Token`，不把共享令牌暴露给前端。
平台搜索用 POST，避免敏感检索条件进入浏览器 URL；适配已有 GET 语义，不能无提示替换原接口。
现有列表为 limit/offset 分页，limit 上限 200、offset 上限 10000；不能假称已提供稳定游标。
真实依赖不可用时显示错误，不能自动用演示数据替代。

## 必须解决的授权缺口

当前模块没有平台账号、会话或强制租户/项目隔离。`source_system_id` 是业务过滤，不是授权凭据；详情按 event_id 查询。
不得将加登录页或前端过滤视为完成数据隔离。正式用户检索开放前，需要确定并测试可信范围映射、列表/详情/统计/分析的统一授权路径。
既有 ClickHouse schema 位于 `event_schema.sql` 和 `schema.sql`；不得将现有表宣称为多租户 schema，或为接入而直接破坏既有数据。

## 后续实施与验收顺序

1. 选择视觉方向和登录方式；冻结本期范围。
2. PostgreSQL 身份/租户/项目/会话/审计物理设计及迁移，兼容现有设计约束。
3. 身份校验与授权适配；先写越权、模式错配、会话撤销和依赖失败测试。
4. React 页面与平台 API 接入；其他模块仅导航说明和未实现接口契约。
5. 使用明确授权的测试数据完成真实 ClickHouse 联调；记录成功、空结果、失败和隔离测试证据。

管理员切换选项不能授予权限；真实账号类型由服务端确定。用户已确认首期本地账号密码；管理员可修改账号显示名、重置密码、停用/启用。当前采用专用实例单租户绑定，不声称完成共享索引多租户。
