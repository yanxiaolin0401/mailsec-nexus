# MailSec Nexus Platform · 首期底座

React/TypeScript 控制台 + FastAPI 平台 API + PostgreSQL 账号控制面，适配现有 smart-search/ClickHouse。
视觉使用用户选定的 **A：深色导航、浅色内容**；本期使用本地账号密码，覆盖旧架构文档的首期 OIDC 设想。

## 实现范围

- 用户/管理员双模式登录，服务端真实角色校验；HttpOnly 会话、CSRF、退出与会话撤销。
- 管理员创建租户/账号、修改显示名、重置密码、停用/启用账号和查看操作审计。
- 邮件结构化检索、分页、详情和依赖状态；浏览器不接触 smart-search 共享令牌。
- header-parser/threat-trace 导航说明、接口占位；调用返回 501，不伪造分析结果。
- PostgreSQL v1 表结构、初始化命令；独立 ClickHouse 检索服务及 worker 编排。

**本期边界：** 一个专用 smart-search 实例只绑定一个平台租户。未绑定租户不能搜索；不能把含多个租户数据的旧实例直接绑定。项目/资源共享、多实例路由、完整案件流程、自然语言/模型分析前端、OIDC/MFA、生产 HA 尚未实现。此版是开发底座，不是完整生产验收。

## 本地开发

见 [API 启动及初始化](api/README.md) 和 [前端开发](web/README.md)。开发服务器 API 8090、Web 5173；浏览器来源应配置为实际 Web 地址，例如 `PLATFORM_ORIGIN=http://localhost:5173`。HTTP 本地开发设 `COOKIE_SECURE=false`；HTTPS 部署设为 true。

## 独立 Compose 部署

不复用旧搜索库，默认创建本项目专用 volumes；数据库和内部搜索服务不发布主机端口。

```bash
cd mailsec-platform
cp .env.example .env
# 配置独立随机凭据；不要保留 CHANGE_ME 值。
docker compose up --build -d
# 凭据由 .env 注入一次性初始化容器，不在命令参数中传明文。
docker compose run --rm bootstrap
```

首次初始化运行后，访问 `http://localhost:8091`，选择管理员登录。创建租户后，将其 ID 填入 `.env` 的 `SMART_SEARCH_TENANT_ID`；**确认本栈搜索数据只属于该租户**后设置 `SMART_SEARCH_DEDICATED=true`，再执行 `docker compose up -d api`。修改口令/显示名在账号管理完成。

浏览器 URL 必须匹配 `PLATFORM_ORIGIN`；localhost 与 127.0.0.1 是不同来源。PostgreSQL URL 内的密码需 URL 安全（推荐随机 hex）；不要把特殊字符密码直接拼接 URL。

## 验证

- API：`cd api && .venv/bin/python -m pytest -q`
- Web：`cd web && npm run typecheck && npm run lint && npm test && npm run build`
- 隔离真实 ClickHouse：根目录执行 `mailsec-smart-search/.venv/bin/python mailsec-platform/scripts/smoke_integration.py`。
  该脚本用测试环境已有凭据，但不打印凭据；只创建/删除唯一临时库和合成邮件，不改业务库。HTTP 为进程内 ASGI，ClickHouse 为真实连接。

[数据库 v1 与验证边界](docs/database-v1.md) · [API 契约](api/API_CONTRACT.md) · [接入与隔离说明](docs/smart-search-integration.md) · [设计源](../DESIGN.md)

浏览器验收脚本：`scripts/smoke_browser.py`（需要 Playwright/Chromium）；截图与报告在 `docs/reports/`。本机执行使用已有临时 Playwright 工具和浏览器依赖，没有把 QA 工具加入运行时镜像。
