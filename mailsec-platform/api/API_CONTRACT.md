# Platform API v1 (implemented scope)

Base `/api/platform/v1`. JSON errors use `{ "detail": "..." }`. All non-GET requests authenticated by cookie require `X-CSRF-Token` from `GET /session`. Session cookie is HttpOnly, SameSite=Lax (Secure when HTTPS configured). Login is exempt from CSRF.

- `POST /auth/login` `{username,password,mode:"user"|"admin",tenant_slug?}` → `{user,csrf_token}` and cookie. Mode must match stored role. Tenant slug is required for a user and forbidden for an admin.
- `GET /session` → `{user:{id,username,display_name,role,tenant_id},csrf_token}`.
- `POST /session/logout` → `{ok:true}` and cookie removal.
- `POST /session/password` `{current_password,new_password}` → `{ok:true}`; **all** sessions, including the current one, are revoked. Client must clear local session state and log in again.
- Admin only: `GET /admin/users` → `{items:[user]}`; `POST /admin/users` `{username,display_name,password,role,tenant_id?}` → user; `PATCH /admin/users/{id}` `{display_name?,password?,is_active?}` → user. User requires a tenant; admin has no tenant. Password change or deactivation revokes target sessions; cannot deactivate self.
- Admin only: `GET /admin/tenants` → `{items:[tenant]}`; `POST /admin/tenants` `{name,slug}` → tenant.
- Admin only: `GET /admin/audit` → `{items:[audit]}`.
- `GET /modules` → `{items:[{name,status}]}`; `POST /modules/{name}/invoke` → 501 for known unimplemented module, 404 otherwise.
- `POST /mail/search` `{q?,sender?,risk_level?,limit?,offset?,tenant_id?}` → smart-search `{items,total,limit,offset}`. Admin must provide `tenant_id`; user cannot provide another tenant. `GET /mail/{id}?tenant_id=` → smart-search detail; admin must provide tenant, user may omit own tenant.
- `GET /integration/status` → `{smart_search:{status,tenant_id}}`; status is `ready` (dedicated binding and upstream `/health/ready` passes), `disabled` (not configured or user tenant not bound), or `unavailable` (health failed). `tenant_id` is null unless ready. No token exposed.

**Isolation gate:** Search works only when `SMART_SEARCH_DEDICATED=true` and `SMART_SEARCH_TENANT_ID` equals requested tenant. Deployment operator must verify that upstream instance/ClickHouse contains only this tenant's data. No `source_system_id`-based tenancy. Otherwise 503/403 fail closed. Upstream uses server-only `X-Mailsec-Token`; timeout/network/non-2xx returns generic 503 except detail 404. No raw upstream errors forwarded.
