# Design

## Source of truth
Status: Active · 2026-10-22。范围：MailSec Nexus platform 控制台与登录入口。
依据：`docs/product/页面与交互设计.md`、`docs/product/数据与接口设计.md`、`mailsec-platform/docs/architecture.md`、本轮用户要求。
平台正在实现首期可运行底座；`mailsec-platform/web/design-preview.html` 仅为视觉候选，不代表业务实现。未发现现有正式组件、主题或浏览器截图基线。

## Brand
专业、克制、可信；中文界面，MailSec Nexus 标识。避免霓虹堆叠、装饰性大屏和无依据的安全评分。

## Product goals
本期：平台前端、用户/管理员登录、数据库设计、smart-search/ClickHouse 接入。
非目标：header-parser 和 threat-trace 算法实现；只提供导航说明页与预留接口。该最新要求覆盖旧页面文档“不展示未上线模块页面”的约定。
成功信号：真实登录鉴权、授权范围内检索与详情、依赖故障明确可见；视觉预览不作为上述验收证据。

## Personas and jobs
用户：在授权租户/项目范围内检索和调查邮件。管理员：管理平台用户、租户、配置和授权业务数据，明确标识当前管理范围。

## Information architecture
登录 → 总览 → 智能检索 → 邮件详情；模块说明：邮件头解析、威胁溯源。管理员有独立管理入口，普通用户不展示管理菜单。
导入、任务、案件等扩展流程的本期实施深度待确认，不因导航存在即视为实现。

## Design principles
检索与证据优先；状态真实；权限由服务端决定；未知不等于安全。演示数据与真实数据严格区分。

## Visual language
用户已选择 A 浅色企业控制台：深色导航、浅色内容、蓝色操作强调。B/C 仅保留为历史候选。
使用系统中文字体；8px 间距基准；紧凑表格与清晰层级；风险状态同时使用文字与颜色。不依赖外部字体或装饰图片。

## Components
统一侧栏、顶栏、范围指示、搜索过滤器、结果表、分页、状态提示、模块未接入卡片、用户/管理员登录切换。
正式 React 组件及 tokens 位于 `mailsec-platform/web/src/`；候选页 CSS 不是新增运行时设计系统。

## Accessibility
以 WCAG 2.2 AA 为目标；原生语义控件、可见焦点、键盘操作、输入标签、非纯颜色提示；尊重减少动画设置。未完成正式无障碍验收。

## Responsive behavior
覆盖 1440/1024/768/375px；窄屏折叠导航和筛选，表格仅在自身容器内横向滚动，登录可单列展示。

## Interaction states
正式页面需 loading/empty/forbidden/error/partial/stale；依赖不可用不得自动切演示数据。预览始终标记静态演示，不连接后端。

## Content voice
简洁中文，技术标识保持原名；未接入、未知、失败各有明确语义，不声称未实现能力可用。

## Implementation constraints
遵循现有 React + TypeScript + Vite、FastAPI 基线。PG 管身份及事务，ClickHouse 管检索投影；浏览器只调用平台 API，不持有模块共享凭据。
不直接互写模块业务表，不改变 smart-search 既有接口含义。正式实施需契约测试、权限测试、前端构建和浏览器验收；静态预览仅进行独立基础检查。

## Open questions
- [x] 用户：已选择 A。
- [x] 用户：首期本地账号密码，管理员可修改账号；此决定覆盖原 OIDC 首期基线。后续 OIDC 留作扩展。
- [x] 首期采用专用 smart-search 实例绑定单一租户；其他租户 fail closed。不声称实现共享索引多租户或项目级隔离。
- [ ] 用户/实施负责人：明确首期导入、任务、案件和管理操作的验收边界。
