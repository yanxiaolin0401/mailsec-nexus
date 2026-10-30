# MailSec Smart Search

独立的邮件接收、ClickHouse 检索与智能安全分析模块。HTTP **8080** 以前置嵌套 JSON 推送为主；原始 EML 和文件上传保持兼容。不接 SMTP，不依赖另外两个课题运行时，不实现 Elasticsearch DSL。

## 已实现与本轮优化

以下前五项主要属于既有 EML 链路。新 JSON 事件已通过自动化测试、真实容器的 API/worker/ClickHouse 闭环和 Chromium 控制台交互；容量与企业验收仍以[验证记录](docs/验证记录.md)为准。

- RFC 5322/MIME 有界解析、原文 SHA-256、重复头保留、附件元数据、异步落盘队列与重试。
- ClickHouse 批量导入、旧 EML 内容去重、多条件查询、摘要分页、详情及统计；内容去重**不适用于**新 JSON 投递事件。
- 本机 Rspamd / ClamAV 扫描；独立模型研判及保守融合。失败返回未知，不冒充正常。
- OpenAI-compatible / Anthropic-compatible 双协议、受限自然语言查询、三种排查 SOP。
- 数据集获取/校验、安全解压、断点续导、测试与评测脚本。
- 本轮新增：JSON 事件入持久队列、`mail_events` 34 列、事件检索和受限 NL2Query、无需新依赖的轻量 Web；单条事件可按需请求脱敏模型意见，历史意见追加存储，不冒充 EML 杀毒扫描。完整验收以[验证记录](docs/验证记录.md)为准。

**真实第三方模型联通尚需配置有效的 endpoint、model、API Key；协议模拟测试不等于真实联通。** 当前机器是小规格开发机，实测报告不代表生产容量承诺。

**后续验收**：10 万条新 JSON 负载、企业盲测、获授权的真实模型联通、生产多租户授权、历史回执归档与幂等保留期设计。既有 10 万封 EML 报告不能替代新事件压测。

## ClickHouse Cloud（2026-10-30）

已新增可复跑、逐批全列校验的迁移工具与 JSON / 历史 EML 双数据源网页检索。迁移范围是本地数据库的已入库数据，原始语料仍在本机；云端启动、迁移/回退边界与实际验收报告见 [Cloud 迁移与智能检索验收](docs/ClickHouse/Cloud迁移与智能检索验收.md)。真实自然语言模型仍须配置有效凭据并授权，未配置时结构化检索不受影响。

## 启动

```bash
cd mailsec-smart-search
# 仅首次新环境创建 .env；已有文件勿覆盖
cp -n .env.example .env
# 在 .env 填入独立随机 CLICKHOUSE_PASSWORD 和 MAILSEC_API_TOKEN
# 可用 python3 -c 'import secrets; print(secrets.token_hex(32))' 本地生成
sudo docker compose --profile detectors --profile malware up -d --build
```

访问 `http://127.0.0.1:8080/` 使用轻量 Web 控制台，`/docs` 查看 OpenAPI。所有业务接口须带 `X-Mailsec-Token`；默认仅监听本机。Rspamd 位于无外网内部网络；ClamAV 初次加载病毒库需要时间和较多内存。详细步骤见[部署与使用](docs/部署与使用.md)。

```bash
set -a; . ./.env; set +a
EVENT_ID="readme-$(date +%s)"
curl -H "X-Mailsec-Token: $MAILSEC_API_TOKEN" -H 'Content-Type: application/json' \
  --data-binary @- http://127.0.0.1:8080/api/v2/mails <<JSON
{"sourceSystemId":"readme-demo","sourceEventId":"$EVENT_ID","eventTime":"2026-10-21T10:00:00+08:00","mail":{"senderaccount":"notice@example.test","toaccount":"analyst@example.test","subject":"合成测试邮件","textContent":"仅用于本地验证。"}}
JSON
# 202 仅表示本地持久队列已接收；用响应的 jobId 调
# GET /api/v2/jobs/{job_id}，状态为 done 后再检索。立即检索可能返回 0 条。
curl -G -H "X-Mailsec-Token: $MAILSEC_API_TOKEN" \
  --data-urlencode 'subject_contains=合成测试邮件' \
  http://127.0.0.1:8080/api/v1/mails
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
