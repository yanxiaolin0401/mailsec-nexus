# MailSec Smart Search

mailsec-nexus 的邮件接收、ClickHouse 检索与智能安全分析后端模块。用户页面统一在 `../mailsec-platform`，唯一用户入口为 **5173**。接入以前置 JSON 推送为主；原始 EML 和文件上传保持兼容。不接 SMTP，不依赖另外两个课题运行时，不实现 Elasticsearch DSL。

## 已实现与本轮优化

以下前五项主要属于既有 EML 链路。新 JSON 事件已通过自动化测试、真实容器的 API/worker/ClickHouse 闭环和 Chromium 控制台交互；容量与企业验收仍以[验证记录](docs/验证记录.md)为准。

- RFC 5322/MIME 有界解析、原文 SHA-256、重复头保留、附件元数据、异步落盘队列与重试。
- ClickHouse 批量导入、旧 EML 内容去重、多条件查询、摘要分页、详情及统计；内容去重**不适用于**新 JSON 投递事件。
- 本机 Rspamd / ClamAV 扫描；独立模型研判及保守融合。失败返回未知，不冒充正常。
- OpenAI-compatible / Anthropic-compatible 双协议、受限自然语言查询、三种排查 SOP。
- 数据集获取/校验、安全解压、断点续导、测试与评测脚本。
- 本轮新增：JSON 事件入持久队列、`mail_events` 初始 34 列（2026-11 已非破坏性扩展为 39 列，见下文）、事件检索和受限 NL2Query、由 platform 承载的统一 Web；单条事件可按需请求脱敏模型意见，历史意见追加存储，不冒充 EML 杀毒扫描。完整验收以[验证记录](docs/验证记录.md)为准。

**真实第三方模型联通尚需配置有效的 endpoint、model、API Key；协议模拟测试不等于真实联通。** 当前机器是小规格开发机，实测报告不代表生产容量承诺。

**后续验收**：10 万条新 JSON 负载、企业盲测、获授权的真实模型联通、生产多租户授权、历史回执归档与幂等保留期设计。既有 10 万封 EML 报告不能替代新事件压测。

## 统一输入流 v2 与存储管理（2026-11）

新主输入对齐 `docs/统一输入流交付包/邮件离线分析_统一输入流标准契约规范.md`：

- `POST /api/v2/mails` 接受规范扁平对象或原子批量数组；`X-Intake-Key` 仅限接入，查询/管理继续使用 `X-Mailsec-Token`。`MAILSEC_INTAKE_KEY` 默认关闭；仅隔离测试环境按交付约定显式配置测试密钥，不能用于公网生产。
- 单封返回回执，批量返回同序回执数组；`202` 只表示 SQLite 持久受理，查询 `jobId` 为 `done` 后才表示同步 ClickHouse 写入成功。非法 JSON 为400、类型415、契约422、身份冲突409、容量413、队列故障503；批量任何新项失败均不提交本批。
- 来源 `(sourceSystemId, sourceEventId)` **须跨租户全局唯一**。`eventId` 为UUID，未给时按来源对生成UUID5；不同负载重用同一来源对或UUID会409，不覆盖原记录。`tenantId` 仅为自报分类元数据，**不是租户授权隔离**；本版查询令牌为全局管理员权限。
- 新增 `tenant_id/mailbox/cc_accounts/body_html/security_meta_json` 五列；旧表仅增列、旧数据和待处理队列有兼容默认值。`receiver_accounts` 含to与cc并去重，一封多收件人仍只存一行。HTML仅按文本展示。
- 网页支持存储概览、队列状态/任务列表与来源事件ID、UUID、邮箱文件夹、租户元数据、附件名筛选；API增加 `GET /api/v1/storage`、`GET /api/v2/queue`、`GET /api/v2/jobs`；`subject_or_attachment_contains` 支持“主题或附件名”OR检索。
- 规范字段按上限截断并标记。发生内容截断或原JSON超过1MiB时，受控审计列保存**明确的省略manifest、原始SHA-256及字节数**，不伪装保存完整原件；完整原件由上游/本机交付包保留。securityMeta超过65536字符也保存摘要manifest。额外工程上限：每HTTP请求16MiB、批量1000封、单封to+cc总计10000；超限明确拒绝，不静默丢收件人。

交付包原件并非100%符合其规范：严格预检358有效、642拒绝；显式修复621个非UUID编号后的**派生文件**979有效、21条发件人/收件人无效仍隔离。未改动原件，不从旧格式字段补造规范字段。

```bash
# 只读预检；有不合规行退出码1，不代表工具故障
.venv/bin/python scripts/preflight_intake.py docs/统一输入流交付包/mail_offline_dataset_1000.jsonl
# 显式生成独立派生文件；输出拒绝覆盖既有文件，权限0600
mkdir -p var/intake
.venv/bin/python scripts/preflight_intake.py docs/统一输入流交付包/mail_offline_dataset_1000.jsonl \
  --repair-ids --output var/intake/valid.jsonl --rejects var/intake/rejected.jsonl \
  --report logs/intake-preflight.json
```

所有本轮操作、需求差异与验收结果写入仓库 `logs/`；本工作区执行规范见 `AGENTS.md`。未完成的真实模型联通、JSON事件SOP和十万级新流压测不能以已有EML测试替代。

## ClickHouse Cloud（2026-10-30）

已新增可复跑、逐批全列校验的迁移工具与 由 platform 承载的 JSON / 历史 EML 双数据源检索。迁移范围是本地数据库的已入库数据，原始语料仍在本机；云端启动、迁移/回退边界与实际验收报告见 [Cloud 迁移与智能检索验收](docs/ClickHouse/Cloud迁移与智能检索验收.md)。真实自然语言模型仍须配置有效凭据并授权，未配置时结构化检索不受影响。

## 启动

当前 Cloud + platform 单入口部署（保留现有 `.env.cloud` 和所有数据）：

```bash
# 私有父目录保护 IPC；容器用户仅能通过挂载子目录创建 socket。
install -d -m 700 var/platform-ipc
install -d -m 777 var/platform-ipc/search
sudo docker compose --env-file .env.cloud -f compose.yaml -f compose.cloud.yaml up -d --build --no-deps api worker
../mailsec-platform/api/.venv/bin/python ../mailsec-platform/scripts/run_cloud_preview.py --confirm-test-dataset
```

浏览器访问 platform 的 5173；已有远程映射需保留原 host/origin 参数。停止或重新部署 API 不删除队列、邮件或平台用户。CLI 直连内部 API 时给 `query/ask` 加 `--socket "$PWD/var/platform-ipc/search/search.sock"`。平台部署说明见 [platform README](../mailsec-platform/README.md)。

以下仅供本地数据库／扫描器开发使用，不是当前 Cloud 环境的启动命令：

```bash
cd mailsec-smart-search
# 仅首次新环境创建 .env；已有文件勿覆盖
cp -n .env.example .env
# 在 .env 填入独立随机 CLICKHOUSE_PASSWORD 和 MAILSEC_API_TOKEN
# 可用 python3 -c 'import secrets; print(secrets.token_hex(32))' 本地生成
sudo docker compose --profile detectors --profile malware up -d --build
```

本模块不提供独立网页，根路径及原 `/assets/` 返回 404。Cloud API 通过 `var/platform-ipc/search/search.sock` 与 platform 通信，不发布 8080；platform API 亦用私有 socket，仅 Web 监听 5173。所有模块业务接口须带服务端 `X-Mailsec-Token`，用户在 platform 使用账号登录。Rspamd 位于无外网内部网络；ClamAV 初次加载病毒库需要时间和较多内存。详细步骤见[部署与使用](docs/部署与使用.md)。

```bash
set -a; . ./.env; set +a
EVENT_ID="readme-$(date +%s)"
curl --unix-socket var/platform-ipc/search/search.sock -H "X-Mailsec-Token: $MAILSEC_API_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @- http://localhost/api/v2/mails <<JSON
{"sourceSystemId":"readme-demo","sourceEventId":"$EVENT_ID","eventTime":"2026-10-21T10:00:00+08:00","mail":{"senderaccount":"notice@example.test","toaccount":"analyst@example.test","subject":"合成测试邮件","textContent":"仅用于本地验证。"}}
JSON
# 202 仅表示本地持久队列已接收；用响应的 jobId 调
# GET /api/v2/jobs/{job_id}，状态为 done 后再检索。立即检索可能返回 0 条。
curl --unix-socket var/platform-ipc/search/search.sock -G -H "X-Mailsec-Token: $MAILSEC_API_TOKEN" \
  --data-urlencode 'subject_contains=合成测试邮件' \
  http://localhost/api/v1/mails
```

JSON 请求格式和幂等/异步接收语义见[嵌套 JSON 接入与字段映射](docs/detail/嵌套JSON接入与字段映射.md)。

## 数据与验证

数据统一在 [`data/`](data/README.md)，原始邮件及密钥不进入 Git。下载包在**完整解压、逐文件校验与清单落盘后**清理；保留原文和来源清单。Enron 用于容量/检索，不视为正常邮件金标准；SpamAssassin 和 Nazario 分别用于垃圾邮件与钓鱼评测。

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps -e .
.venv/bin/python -m pytest -q
set -a; . ./.env; set +a
.venv/bin/mailsec import-directory data/raw/enron/maildir \
  --limit 100000 --report docs/reports/enron-import.json
.venv/bin/mailsec query '{"subject_contains":"合成测试邮件","limit":10}'
.venv/bin/mailsec query --legacy-eml '{"sender_domain":"enron.com","limit":10}'
```

旧 EML 索引保存 `dataset://` 原文引用，不复制一份语料；导入后不要移动、编辑或删除 `data/raw/`。复跑会跳过已成功入库的内容；更换/清空数据库时不能沿用旧导入 checkpoint。

## 文档

- [需求依据与优先级](docs/detail/README.md) · [优化实施计划](docs/优化实施计划.md) · [嵌套 JSON 字段映射](docs/detail/嵌套JSON接入与字段映射.md)
- [架构与安全](docs/架构与安全.md) · [部署与使用](docs/部署与使用.md)
- [验证记录](docs/验证记录.md) · [错例台账](docs/错例台账.md)
- [原始任务书](docs/基于大模型的邮件数据分析与智能检索系统开发.md)
