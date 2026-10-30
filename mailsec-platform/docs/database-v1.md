# 数据库 v1：已实现与后续边界

物理 DDL：[`api/schema_v1.postgresql.sql`](../api/schema_v1.postgresql.sql)，ORM 位于 `api/platform_api/models.py`，通过 CLI `init-db` 创建。`schema_version=1` 标记基线，不自动修改未知/残缺版本；后续变更须增加显式迁移。

| 表 | 作用及约束 |
|---|---|
| tenants | 租户名称、唯一 slug、创建时间 |
| users | 唯一登录名、显示名、scrypt 密码哈希、启停状态；CHECK 保证 user 有租户而 admin 无租户；租户外键 RESTRICT |
| sessions | 用户外键、随机会话 token 的 SHA-256 摘要、CSRF 摘要、过期/撤销时间；浏览器 cookie 为 HttpOnly |
| audit_events | 操作人、动作、目标、字段名摘要、时间；不记录密码、内部 token 或邮件正文 |
| login_attempts | 用户名+直接连接地址的哈希键、15 分钟窗口、失败次数和锁定时间 |
| schema_version | 当前物理基线版本 |

ID 为整数；用户名全平台唯一，小写归一化。管理员可修改显示名、重置密码、停用/启用，不通过通用 PATCH 修改角色或租户。密码重置/停用撤销已有会话；禁止停用自身。初始管理员通过本地 CLI 创建且有审计，无默认口令。

## ClickHouse

不复制或覆盖 smart-search 的表定义。现有 `event_schema.sql` 管 JSON `mail_events`，旧 `schema.sql` 管 EML `mail_records` 与分析历史。平台通过 API 访问，不直接写模块私有表。

Compose 默认使用独立 volumes，避免误接既有混合数据。`SMART_SEARCH_DEDICATED=true` + `SMART_SEARCH_TENANT_ID` 是运维绑定：上游整个实例只能包含该租户数据。此条件不是从邮件的 `sourceSystemId` 自动推断。

**不是共享索引多租户实现。** 未绑定租户拒绝访问；管理员也必须明确目标租户。当前同租户用户共享该专用实例的数据可见范围，尚无项目级或逐邮件用户 ACL。需要这些能力时须先扩展受信作用域和数据库设计，不得只增加前端过滤。

## 验证范围与后续

账号/会话测试及浏览器验收使用一次性 SQLite 控制面；真实搜索测试使用隔离 ClickHouse 临时库。PostgreSQL DDL已生成，但当前执行环境无可用 PostgreSQL、Docker socket 无权限，尚未实测 PostgreSQL 容器或完整 Compose 启动。

尚未创建项目/资源分享/案件/任务/对象证据/审批表；对应顶层概念模型是后续规划，不应描述为本期迁移已完成。当前审计未实现数据库层防篡改，限流仍需生产入口补强；本地账号并不等于完成企业身份安全验收。
