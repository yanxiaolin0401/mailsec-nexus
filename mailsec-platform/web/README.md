# MailSec Nexus Web

正式前端采用 React + TypeScript + Vite，方案 A（深色侧栏、浅色工作区）。`design-preview.html` 仍保留为视觉方案对照，不连接业务。

## 开发

```sh
npm ci
npm run dev
npm run typecheck && npm run lint && npm test && npm run build
```

开发服务器将 `/api` 转发至 `http://127.0.0.1:8090`。生产镜像由 `Dockerfile` 构建、nginx 分发静态资源，并将 `/api/` 反代到 Compose 服务 `api:8090`。后端契约见 `../api/API_CONTRACT.md`。

登录仅使用服务端 HttpOnly 会话 Cookie，不在浏览器持久化令牌或密码。CSRF token 来自 `/session`。用户登录需要租户标识；管理员跨租户检索必须显式选择租户，未配置专用检索实例时显示真实后端错误。邮件头解析与威胁溯源为说明页，不展示模拟结果。
