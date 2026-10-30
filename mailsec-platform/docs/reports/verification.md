# 首期验证记录 · 2026-10-22

## 已通过

- API pytest：10 passed；账号/角色/租户、CSRF、撤销、管理动作、模块占位、上游失败、输入限制和 CLI 审计。
- Web：TypeScript 检查、ESLint、3 项 API/helper 测试、Vite 生产构建通过。
- Ruff 与 Python compileall 通过；Bandit 扫描 0 项发现（不等于安全认证）。
- 真实 ClickHouse：11 项隔离合成数据检查通过，HTTP 为进程内 ASGI 桥接；唯一临时库在 finally 清理。检查含检索、详情、越权拒绝、重置密码和会话撤销。
- Chromium：真实本地 HTTP + FastAPI + 临时 SQLite，7 项流程检查通过，pageerror 为 0；1440px 桌面与 375px 手机截图已保存。浏览器测试故意关闭搜索依赖，验证错误展示；不将其称为浏览器到 ClickHouse 的完整 E2E。
- Compose（含 bootstrap profile）配置语法校验通过。

## 验证限制

- Docker socket 权限不足，未启动完整 Compose，也未实测 PostgreSQL 容器；数据库行为测试使用 SQLite，不能代替 PostgreSQL 运行验收。
- ClickHouse smoke 曾有一次未定位瞬时 DatabaseError，后续连续三次及最终复跑成功；不将其归因为已证实的具体原因。
- Starlette TestClient 有 httpx 弃用警告，不影响当前测试通过。
- 未验收共享索引多租户、项目/资源权限、OIDC/MFA、HA/恢复/容量或生产安全基线。
- 浏览器可视证据只包含合成账号，不含真实邮件或凭据。测试进程及临时账号库已清理。

## 本机浏览器复跑

```bash
LD_LIBRARY_PATH=/tmp/mailsec-browser-deps/root/usr/lib/x86_64-linux-gnu \
PYTHONPATH=/tmp/mailsec-quality \
mailsec-platform/api/.venv/bin/python mailsec-platform/scripts/smoke_browser.py
```

其他机器须安装 Playwright 及 Chromium 系统依赖；脚本要求 loopback 8090/5173 端口空闲，不会停止无关进程。
