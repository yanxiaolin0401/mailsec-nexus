# ClickHouse Cloud 迁移与智能检索（2026-10-30）

## 范围与安全边界

- 本轮按用户授权将**已入库的全部逻辑数据**迁入配置于 `.env.cloud` 的 ClickHouse Cloud，不是把 `data/raw/` 下所有未入库语料追加导入。
- 数据包含正文、邮件头、地址等已存储字段；原始 EML 文件保留本机，不调用第三方模型、不投递邮件、不执行附件。
- 本地数据库、原始数据与队列保留；云端既有 3 条 JSON 测试事件保留。`mail_records` / `mail_events` 按 `FINAL` 迁移当前逻辑记录，不复制重复物理版本；分析记录全部保留。
- Cloud 与本地队列隔离。5 份 spool 原文复制到 Cloud 应用的本机卷并逐份 SHA-256 校验，**不复制任务队列或旧导入 checkpoint**；`dataset://` 原文继续使用只读 `/datasets` 挂载。
- Cloud 连接显式使用 TLS；密钥只在被 Git 忽略的环境文件中，不写报告、命令参数或前端资源。

## 可复跑迁移工具

```bash
# 只读盘点，不建表、不插入
.venv/bin/python scripts/migrate_clickhouse.py --report var/migration/inventory.json

# 源端停止导入/worker，目标不应并发修改同一批 ID；勿并行运行多个迁移进程。
# 依次验证源/目标引擎、排序键、分区键、版本列与列类型，再分区、按键分页迁移。
.venv/bin/python scripts/migrate_clickhouse.py --apply \
  --source-env .env --target-env .env.cloud \
  --report docs/reports/cloud-migration.json

# 重跑会重新核验所有源记录；相同ID且内容相同跳过，内容冲突则停止，不覆盖。
.venv/bin/python scripts/migrate_clickhouse.py --apply \
  --report docs/reports/cloud-migration-rerun.json
```

迁移显式同步写入（`async_insert=0`），每批使用内容派生去重 token，并读回全部列做 SHA-256 比对。**不能仅依赖 ClickHouse 去重窗口**：恢复时重新读取目标，确认相同后才跳过。源端前后全列聚合、总数、唯一 ID 和目标行数检查均需通过；报告 `status=verified` 才表示验收通过。失败不删除源数据，不自动回滚已校验插入的批次。

本机的 1 GiB ClickHouse 限额下，后台 `system.metric_log` 合并曾抢占内存。此次迁移临时暂停本地后台合并、将上限升至 1.5 GiB，结束后恢复原配置与合并。脚本自身使用分区、有界分页、单线程和 512 MiB 查询限制，不要求永久提升生产配额。

## 兼容性修复

本地服务器为 26.8，Cloud 为 26.6，历史表含年份 `0102` 的 `sent_at`。直接交给 clickhouse-connect 1.10 的 C 日期解码会进程崩溃：

- 迁移使用 DateTime64 原始整数 tick 读写，保留原值，**不把异常日期偷偷改写**。
- 查询列表、详情与 SOP 的时间投影对 1900–2299 以外的值返回 `null`，数据库原值和原始 Date 头保留。
- 新解析同样拒绝索引超范围日期，并记录解析问题，而不是把异常值继续写入索引。
- 跨部署旧 spool 引用仅允许 `.../spool/raw/<sha256>.eml`，从当前授权根内寻找同摘要副本；拒绝穿越、符号链接、大小超限和内容不符。

ClickHouse 26.7 扩展了 DateTime64 年份范围；本项目为兼容 Cloud 26.6 与当前驱动，查询投影采用保守范围。[官方版本说明](https://clickhouse.com/blog/clickhouse-release-26-07)

## 智能检索改进

- Web 显式选择「JSON 邮件事件」或「历史 EML 邮件」，分别路由结构化检索、自然语言规划、统计、翻页、详情及分析。
- 切换数据源会清空旧计划/结果并禁用不适用字段，防止把事件风险/IP 条件静默用于历史邮件。
- 历史摘要不伪造总数、收件人或风险。详情中可查看原始邮件信息。
- 历史自然语言查询默认**只预览**；前端执行已验证的精确条件，不再次请求模型生成另一份计划。
- 邮箱/IP/URL 等先转换成本地占位符；未知占位符或丢弃私密约束的模型输出会被拒绝；时间必须带时区且顺序合法。
- 相对时间明确以 Asia/Shanghai 当前时间解析，上周采用自然周，包含上界减 1 毫秒。

## 运行与回退

```bash
sudo docker compose --env-file .env.cloud -f compose.yaml -f compose.cloud.yaml \
  up -d --build --no-deps api worker
```

网页：`http://127.0.0.1:8080/`；填写本机 `.env.cloud` 的 `MAILSEC_API_TOKEN`。默认 JSON 数据源；查询迁入的大语料时选择「历史 EML 邮件」。

回退仅切换本机服务，不删除云端数据：停止 API/worker 后使用原 `.env` 和 `compose.yaml` 启动本地 ClickHouse/API/worker。**回退不会自动将切换后 Cloud 新接收的数据反向同步回本地**，这部分须另行核验后处理；不能复制 Cloud 队列冒充数据库同步。

## 证据与未完成能力

- 首次迁移：`docs/reports/cloud-migration.json`。
- 幂等复跑：`docs/reports/cloud-migration-rerun.json`。
- 原文副本：`docs/reports/cloud-evidence-copy.json`。
- API/浏览器验收：`docs/reports/cloud-search-acceptance.json`。
- 测试、lint、类型检查详见报告；全仓库历史风格/类型问题不在本次迁移范围内。
- 未配置可用且获授权的第三方模型，真实自然语言模型联通与效果评测**不宣称完成**；此时接口明确返回 503，结构化检索可用。模型协议/规划安全采用模拟回归验证。
- 扫描服务仍是独立本机依赖；未运行扫描器时不能把分析失败或“未知”显示为“安全”。未完成生产多租户授权、企业盲测或容量承诺。

迁移依据：[Cloud SharedMergeTree](https://clickhouse.com/docs/products/cloud/features/infrastructure/shared-merge-tree)、[Python 写入 API](https://clickhouse.com/docs/integrations/language-clients/python/driver-api)、[重试去重边界](https://clickhouse.com/docs/concepts/features/operations/insert/deduplicating-inserts-on-retries)。
