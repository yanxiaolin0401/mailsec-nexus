# MailSec Nexus Platform · 首期底座

React/TypeScript 控制台 + FastAPI 平台 API + PostgreSQL 账号控制面，适配现有 smart-search/ClickHouse。
视觉使用用户选定的 **A：深色导航、浅色内容**；本期使用本地账号密码，覆盖旧架构文档的首期 OIDC 设想。

## 实现范围

- 用户注册（管理员审核启用后可登录）、用户/管理员双模式登录，服务端真实角色校验；HttpOnly 会话、CSRF、退出与会话撤销。
- 管理员创建租户/账号、修改显示名、重置密码、停用/启用账号和查看操作审计。
- 历史 EML / JSON 事件双数据源结构化检索、统计、分页、详情和依赖状态；浏览器不接触 smart-search 共享令牌。
- header-parser/threat-trace 导航说明、接口占位；调用返回 501，不伪造分析结果。
- PostgreSQL v1 表结构、初始化命令；独立 ClickHouse 检索服务及 worker 编排。

**本期边界：** 一个专用 smart-search 实例只绑定一个平台租户。未绑定租户不能搜索；不能把含多个租户数据的旧实例直接绑定。项目/资源共享、多实例路由、完整案件流程、OIDC/MFA、生产 HA 尚未实现。此版是开发底座，不是完整生产验收。

## 登录、注册和数据位置

当前为测试 demo：登录、注册、创建账号和改密均支持任意密码及空密码；编辑账号时，勾选“将密码设为空”可清空该账号密码。

- 登录页提供「用户登录」「管理员登录」「用户注册」。注册只创建普通用户，需填写已有租户标识（当前测试空间 `cloud-test`）；注册后由管理员在「账号管理」核实并点击「启用」。不知道组织代号应联系管理员，不会自动创建或加入任意组织。
- 管理员登录不填租户标识；账号管理可分配普通用户、重置密码、停用。租户标识是组织空间的唯一代号，不是密码、邀请码或租赁编号。
- 本机预览的账号、租户、会话、限流、操作审计存储在 SQLite 文件 `.local/cloud-preview.db`；Compose 部署使用 PostgreSQL。数据库里的密码为随机盐 scrypt 哈希，不保存原始密码；仅开发预览的初始随机密码备忘保存在 owner-only `.local/cloud-preview-credentials.json`，不要提交或公开此文件。
- 邮件结构化字段、正文及检索数据由 smart-search 存入 ClickHouse Cloud；原始 EML 保存在本机受控文件目录，索引保留原文引用/摘要。接收后先持久排队，worker 处理完成才可检索。JSON 超限原件的保留/省略边界以 smart-search 输入契约为准，不宣称每封 JSON 原件都完整保存。
- 浏览器只访问平台 API；平台先校验会话、角色、租户，再携带服务端令牌调用 smart-search，以参数化条件查询 ClickHouse 并返回列表、统计、详情。浏览器不持有 ClickHouse 凭据。

## 本地开发

见 [API 启动及初始化](api/README.md) 和 [前端开发](web/README.md)。统一启动脚本使用私有 Unix socket 连接平台 API 和 smart-search，仅 Web 监听 5173；浏览器来源应配置为实际 Web 地址，例如 `PLATFORM_ORIGIN=http://localhost:5173`。HTTP 本地开发设 `COOKIE_SECURE=false`；HTTPS 部署设为 true。

## ClickHouse Cloud 联调（复用已运行的 smart-search）

平台不直连 ClickHouse，也不把 Cloud 密码或模块令牌发送给浏览器。已迁移的数据通过 `../mailsec-smart-search/var/platform-ipc/search/search.sock` 私有接口读取，模块自带网页及 8080 发布已移除；**不要用下面的本地 Compose 栈替代当前 Cloud 服务**。

安装 API/Web 的既有依赖后，从仓库根目录运行：

```bash
mailsec-platform/api/.venv/bin/python mailsec-platform/scripts/run_cloud_preview.py \
  --confirm-test-dataset
```

当前公网映射测试入口 `http://43.133.251.134:5173` 的完整启动/停止命令（仓库根目录执行）：

```bash
# 启动：前台运行，保持终端打开；本轮已由独立 tmux 会话保持运行。
mailsec-platform/api/.venv/bin/python mailsec-platform/scripts/run_cloud_preview.py --confirm-test-dataset --host 10.8.0.3 --origin http://43.133.251.134:5173
# 停止：只停止经过进程身份校验的平台 Web/API，不停 Cloud 搜索服务，不删数据。
mailsec-platform/api/.venv/bin/python mailsec-platform/scripts/run_cloud_preview.py --stop
```

注意：`--host` 是服务器绑定的内网地址，`--origin` 必须是浏览器实际访问地址（当前为上述公网 IP），二者不必相同。使用其他地址登录会被来源保护拒绝；不要关闭来源校验来绕过。该映射只用于临时测试，应配置 HTTPS 并限制访问范围。

停止再启动不会清空账号、注册申请或邮件。脚本拒绝占用中的端口，不会杀掉无关进程；Cloud 暂时不可用时仍启动登录/注册页面，检索状态如实显示不可用，不自动切假数据。开发代理下注册限流按服务端看到的连接地址合并计数（5 次/15 分钟），不能把它当作生产边缘限流。

默认不传 host/origin 时访问 `http://127.0.0.1:5173`。要从可信内网访问本机，可加 `--host 0.0.0.0 --origin http://<本机内网IP>:5173`；登录时必须使用同一个 origin。此 HTTP/Vite 环境仅供本地或可信内网测试，不要暴露到公网；正式部署需 HTTPS 与生产 Web 镜像。

- 复用 `mailsec-smart-search/.env.cloud` 的 `MAILSEC_API_TOKEN`，不执行环境文件、不读取 Cloud 数据库凭据。
- 仅创建隔离的本地 SQLite 控制面 `.local/cloud-preview.db`，不影响此前 `preview.db`，不启动搜索 worker、不迁移/写入邮件。
- 首次随机生成管理员 `admin` 与普通用户 `analyst`；普通用户租户标识 `cloud-test`。初始密码保存在 `.local/cloud-preview-credentials.json`（0600），不会输出到日志。修改密码后以新密码为准，重启不重置账号。
- `--confirm-test-dataset` 表示确认上游语料只属于该授权测试空间；禁止把混合企业租户的真实库直接绑定。其他平台租户仍拒绝访问。
- 默认选“历史 EML 邮件”，可留空条件浏览；“统计匹配数”单独读取全量总数。历史邮件没有风险评级，未知发送时间不会替换为入库时间。
- 前台 `Ctrl-C` 或下方 `--stop` 同时停止本次启动的 Web/API，不影响已有 smart-search。日志在 `.local/cloud-api.log`、`.local/cloud-web.log`。端口占用时拒绝启动，不杀占用进程。
- 本次常驻测试使用独立 tmux 会话 `mailsec-cloud-preview`；可用 `tmux attach -t mailsec-cloud-preview` 查看运行状态，按 `Ctrl-C` 停止，`Ctrl-B D` 仅脱离不停止。

只读验收（URL 与启动 origin 相同）：

```bash
mailsec-platform/api/.venv/bin/python mailsec-platform/scripts/smoke_cloud_preview.py \
  --url http://127.0.0.1:5173
# 可加 --browser-path /path/to/chrome；Python 环境需有 Playwright，仅作 QA。
```

结果见 `docs/reports/cloud-preview-acceptance.json`；报告仅含数量/检查项，不记录邮件内容或凭据。该脚本会产生平台登录和查询审计，不修改云端邮件。邮件头解析和威胁溯源沿用现有模块入口。自然语言检索接入见下文“大模型接入与智能检索”。

## 独立 Compose 部署（本地 ClickHouse，不是 Cloud 预览）

不复用旧搜索库，默认创建本项目专用 volumes；数据库和内部搜索服务不发布主机端口。

```bash
cd mailsec-platform
cp .env.example .env
# 配置独立随机凭据；不要保留 CHANGE_ME 值。
docker compose up --build -d
# 凭据由 .env 注入一次性初始化容器，不在命令参数中传明文。
docker compose run --rm bootstrap
```

首次初始化运行后，访问 `http://localhost:5173`，选择管理员登录。创建租户后，将其 ID 填入 `.env` 的 `SMART_SEARCH_TENANT_ID`；**确认本栈搜索数据只属于该租户**后设置 `SMART_SEARCH_DEDICATED=true`，再执行 `docker compose up -d api`。修改口令/显示名在账号管理完成。

浏览器 URL 必须匹配 `PLATFORM_ORIGIN`；localhost 与 127.0.0.1 是不同来源。PostgreSQL URL 内的密码需 URL 安全（推荐随机 hex）；不要把特殊字符密码直接拼接 URL。

## 验证

- API：`cd api && .venv/bin/python -m pytest -q`
- Web：`cd web && npm run typecheck && npm run lint && npm test && npm run build`
- 隔离真实 ClickHouse：根目录执行 `mailsec-smart-search/.venv/bin/python mailsec-platform/scripts/smoke_integration.py`。
  该脚本用测试环境已有凭据，但不打印凭据；只创建/删除唯一临时库和合成邮件，不改业务库。HTTP 为进程内 ASGI，ClickHouse 为真实连接。

[数据库 v1 与验证边界](docs/database-v1.md) · [API 契约](api/API_CONTRACT.md) · [接入与隔离说明](docs/smart-search-integration.md) · [设计源](../DESIGN.md)

浏览器验收脚本：`scripts/smoke_browser.py`（需要 Playwright/Chromium）；截图与报告在 `docs/reports/`。本机执行使用已有临时 Playwright 工具和浏览器依赖，没有把 QA 工具加入运行时镜像。

## 登录注册本轮验收（2026-11-05）

API/启动脚本 22 项测试、Web 7 项测试、typecheck/lint/build，以及浏览器“注册→待审核不能登录→管理员启用→登录/刷新/退出”通过；注册页面已验证 375px 无溢出且品牌/页脚不遮挡长表单。可复跑 `scripts/smoke_registration.py --url <启动origin> --browser-path <Chrome路径>`，使用 API Python 与可选 Playwright QA 环境；该脚本创建唯一的本地测试账号，结束后停用，保留审计，不写云端邮件。验收报告和无敏感信息截图保存在 `.local/`。

## 大模型接入与智能检索

管理员进入「大模型接入」，选择服务商、模型并填写 API Key，确认授权后保存。配置持久保存在 smart-search 数据卷 `llm-config.json`，保存后即时生效；网页只显示密钥是否已配置。切换服务商时填写该服务商自己的密钥。

| 服务商 / 官网 | Base URL | 预置模型 ID | 官方说明 |
| --- | --- | --- | --- |
| [DeepSeek](https://www.deepseek.com) | `https://api.deepseek.com` | `deepseek-flash`, `deepseek-v4-pro` | [接入文档](https://api-docs.deepseek.com/) |
| [阿里云百炼](https://bailian.console.aliyun.com) | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-plus`, `qwen-flash` | [接入文档](https://help.aliyun.com/zh/model-studio/first-api-call-to-qwen) |
| [OpenAI](https://platform.openai.com) | `https://api.openai.com/v1` | `gpt-4.1-mini` | [模型文档](https://developers.openai.com/api/docs/models/gpt-4.1-mini) |
| [Anthropic](https://platform.claude.com) | `https://api.anthropic.com/v1` | `claude-sonnet-4-6`, `claude-haiku-4-5-20251001` | [模型状态](https://platform.claude.com/docs/en/about-claude/model-deprecations) |

该目录于 2026-11-12 核对官方文档；可手动填写账号支持的模型 ID。OpenAI 兼容协议在 Base URL 后追加 `/chat/completions`，Anthropic 协议追加 `/messages`，Base URL 不填写完整方法路径。百炼预置杭州 DashScope 兼容接入点。

智能检索支持历史 EML / JSON 事件：输入自然语言→生成只读查询计划→检查条件→确认执行。计划由平台签名并绑定用户、租户、数据源，有效期十分钟；翻页执行已确认条件，不再次调用模型。模型只产生条件，ClickHouse 负责查询和统计。切换租户或数据源会清空旧计划。

结构化高级筛选包含时间、发件域、附件及事件专属线索；沿用 smart-search 参数化查询。未配置模型时仍可使用结构化检索。

本轮验收：平台 API/启动测试 29 项、Web 10 项测试、类型检查和构建通过；浏览器验证真实配置状态/服务商目录及模拟模型计划的预览、确认执行、分页和切换清理。报告在 `.local/llm-ui-acceptance.json`。现有服务端密钥状态已读取，不执行真实外部模型调用。

## 统一入口与模块同步（2026-11-12）

用户页面全部由本平台承载。自然语言检索、JSON/历史 EML 查询、详情、按需单封研判与历史、管理员只读存储和队列任务，以及模型配置均通过平台会话和服务端适配层访问。浏览器不持有模块令牌或模型密钥。当前 Cloud 启动脚本默认以 Unix socket 连接两个后端，仅监听 5173；Compose 的容器内部仍可使用服务端口，但宿主机仅发布 5173。

先按 smart-search README 准备私有 IPC 目录并启动现有 Cloud API/worker，再运行本文件的 `run_cloud_preview.py` 命令；保留已有 `.local` 账号数据库和凭据。显式 `--search-url` 仅供兼容旧后端，默认无需该参数。
