# Cloud 平台对接验收 · 2026-10-30

## 实施范围

- 平台 API、React 前端适配历史 EML / JSON 事件两套已有 HTTP 接口；没有改动 smart-search 算法、迁移脚本或云端业务表。
- 复用专用实例租户门禁、CSRF、审计和服务端共享令牌；未新增运行依赖。
- 新增可复跑的启动脚本、启动状态回归测试及真实 Cloud 只读验收脚本；使用独立 SQLite 测试控制面，不覆盖旧预览账号。
- 保留用户进入本轮时的 smart-search 未提交修改。

## 验证证据

- `cd mailsec-platform/api && .venv/bin/python -m pytest tests ../scripts/tests -q`：16 passed；1 项 Starlette/httpx 弃用警告。
- 平台 Python 源码、测试与新脚本 Ruff 检查通过；compileall 通过。
- 前端 typecheck、ESLint、7 项 Node 测试、生产 build 通过。
- `scripts/smoke_cloud_preview.py` 对真实运行平台和 Cloud 上游完成 HTTP 与 Chromium 验收，见 `cloud-preview-acceptance.json`：历史 EML 109516、JSON 事件 13，双源统计/分页/详情、租户越权拒绝、CSRF、管理员及用户登录、退出和 375px 布局通过，JavaScript 错误 0。
- 分页回归覆盖事件响应没有 may_have_more、历史空尾页和 offset=10000；未知历史发送时间不回退为入库时间。
- 无云端邮件写入、无模型调用；验收只产生本地登录/检索审计。截图保存在 ignored `.local/`，截图前清除邮件结果。

## 启动与边界

测试 Web 5173、平台 API 仅 loopback 8090；复用现有 smart-search 8080。测试服务在专用 tmux 会话 `mailsec-cloud-preview` 常驻。凭据在 ignored `.local/cloud-preview-credentials.json`，未写入本报告或前端。

该环境是可信内网 HTTP/Vite + SQLite 测试环境，不是生产部署验收。没有新增共享索引多租户隔离、项目级权限、自然语言模型前端、邮件头解析或威胁溯源实现。现有 Compose 保留本地 ClickHouse 行为并在 README 明确区分，不用于本次 Cloud 预览。未重新执行会写库的旧 ClickHouse 集成脚本。
