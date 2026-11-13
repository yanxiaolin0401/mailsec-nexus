# Platform API v1 (implemented scope)

Base `/api/platform/v1`. JSON errors use `{ "detail": "..." }`. All non-GET requests authenticated by cookie require `X-CSRF-Token` from `GET /session`. Session cookie is HttpOnly, SameSite=Lax (Secure when HTTPS configured). Public login and registration are exempt from CSRF; both enforce same-origin browser requests.

Demo password policy: every password field accepts any string, including `""`, with no length or complexity check. Fields remain required where shown. In `PATCH /admin/users/{id}`, omitted or `null` password leaves it unchanged; `""` explicitly sets an empty password. Passwords are stored as salted scrypt hashes.

- `POST /auth/login` `{username,password,mode:"user"|"admin",tenant_slug?}` → `{user,csrf_token}` and cookie. Mode must match stored role. Tenant slug is required for a user and forbidden for an admin.
- `POST /auth/register` `{username,display_name,password,tenant_slug}` → 201 `{message:"Registration pending administrator approval"}`. Registers **only** a regular user for an existing tenant in inactive state, without a session. Clients cannot choose role, tenant ID, or active status. An administrator must enable the account through `PATCH /admin/users/{id}` before login succeeds. Duplicate username returns 409, unknown tenant identifier 404, cross-origin request 403, and peer registration rate limit 429 (five attempts per 15 minutes). A tenant slug is a routing identifier, not proof of authorization; registration does not grant mail access.
- `GET /session` → `{user:{id,username,display_name,role,tenant_id},csrf_token}`.
- `POST /session/logout` → `{ok:true}` and cookie removal.
- `POST /session/password` `{current_password,new_password}` → `{ok:true}`; **all** sessions, including the current one, are revoked. Client must clear local session state and log in again.
- Admin only: `GET /admin/users` → `{items:[user]}`; `POST /admin/users` `{username,display_name,password,role,tenant_id?}` → user; `PATCH /admin/users/{id}` `{display_name?,password?,is_active?}` → user. User requires a tenant; admin has no tenant. Password change or deactivation revokes target sessions; cannot deactivate self.
- Admin only: `GET /admin/tenants` → `{items:[tenant]}`; `POST /admin/tenants` `{name,slug}` → tenant.
- Admin only: `GET /admin/audit` → `{items:[audit]}`.
- `GET /modules` → `{items:[{name,status}]}`; `POST /modules/{name}/invoke` → 501 for known unimplemented module, 404 otherwise.
- `POST /mail/search` `{source?:"event"|"legacy",q?,sender?,recipient?,subject?,risk_level?,limit?,offset?,tenant_id?}` → `{items,total,limit,offset,may_have_more}`. Default `source=event` preserves the JSON event search. `source=legacy` searches historical EML records: `q` searches **body text only** (`body_contains` upstream), `subject` maps to `subject_contains`; `risk_level` is unsupported and rejected with 422 rather than ignored. Legacy `total` is `null` because paginated search does not count all matches; `may_have_more` comes from upstream. Admin must provide `tenant_id`; user cannot provide another tenant.
- `POST /mail/stats` accepts the same filters and source, with the same tenant authorization. Event stats contain `total`; legacy stats contain `total`, `with_attachment`, `parse_failed`. Stats is a separate potentially expensive count query; no automatic count is run for legacy pagination.
- `GET /mail/{id}?source=event|legacy&tenant_id=` → selected upstream detail. Default event; admin must provide tenant, user may omit own tenant. Legacy detail uses `mail_id`, `body_text`, `sent_at`; event uses `event_id`, `text_content`, `event_time`. No raw file paths are returned.
- `GET /integration/status` → `{smart_search:{status,tenant_id}}`; status is `ready` (dedicated binding and upstream `/health/ready` passes), `disabled` (not configured or user tenant not bound), or `unavailable` (health failed). `tenant_id` is null unless ready. No token exposed.

**Isolation gate:** Search and stats work only when `SMART_SEARCH_DEDICATED=true` and `SMART_SEARCH_TENANT_ID` equals requested tenant. Deployment operator must verify that upstream instance/ClickHouse contains only this tenant's data. No `source_system_id`-based tenancy. Otherwise 503/403 fail closed. Upstream uses server-only `X-Mailsec-Token`; timeout (`SMART_SEARCH_TIMEOUT_SECONDS`, default 30), network/non-2xx returns generic 503 except detail 404. No raw upstream errors forwarded.

## 智能检索 / 模型配置

- `POST /mail/nl/plan` `{source:"event"|"legacy",text,tenant_id?}` → `{plan,executed:false,plan_token}`。平台先校验用户和专用租户，调用对应 smart-search `/api/v1/nl/query` 或 `/v1/nl/query`，强制 `execute:false`。计划令牌用 HMAC 绑定用户、租户、数据源、过滤条件和 10 分钟有效期。
- `POST /mail/plan/execute` `{plan_token,source,tenant_id?,limit?,offset?}` → `{plan,executed:true,result}`。执行已签名的结构化过滤条件；翻页只覆盖 `limit/offset`，不再次调用模型。`stats` 不接受分页。legacy 搜索的 `result.total=null`，事件搜索使用上游 total。
- `GET /llm/providers` 返回预设服务商目录。`GET /llm/config` 返回 smart-search 当前配置状态，始终不返回 API Key；`PUT /admin/llm/config` 仅管理员可提交 `{provider,base_url,model,api_key?,external_authorized}`。`api_key` 省略保留旧值、空字符串清除；服务端密钥不发送到浏览器。模型调用由 smart-search 在显式授权后执行。
- 结构化搜索还接受 `from_time/to_time`（必须带时区）、`sender_domain`、`has_attachment`、`attachment_suffix`；事件专属 `sender_ip`、`attachment_md5`、`risk_verdict`、`subject_or_attachment_contains`、`attachment_name_contains`、`source_system_id`。legacy 使用事件专属条件返回 422；事件业务字段 `tenant_id` 不开放为筛选条件，平台 `tenant_id` 仅用于授权。
