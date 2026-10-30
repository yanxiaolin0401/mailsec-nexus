# 邮件数据集（本机数据，不进入 Git）

本目录统一存放原始数据。2026-10-30 按用户授权将已入库的结构化邮件数据（含正文与邮件头）迁往 ClickHouse Cloud；原始 EML 文件仍保留本机。没有向收件人投递邮件、没有附件执行、没有模型调用。公开样本仍可能含个人信息、危险链接或恶意内容。

## 本次获取结果（2026-10-20）

| 数据 | 已验证邮件数 |
|---|---:|
| Enron | 517,401 |
| SpamAssassin | 6,046 |
| Nazario 2015—2025 | 3,466 |
| 合计（未跨源去重） | **526,913** |

17 份数据清单已完成；压缩包及 Range 分段已清理，`.downloads/` 为空。Enron 解压后逐封原始内容共 1,421,183,736 字节；Nazario 原始 mbox 额外保留用于追溯，不再次计入邮件总数。所有解压文件均已与归档流 SHA-256 读回复核，gzip/bzip2 完整流 CRC 检查通过；Nazario 拆分文件也已逐封复核。

## 目录

- `raw/enron/maildir/`：CMU Enron 按邮箱/文件夹保存的逐封原文。
- `raw/spamassassin-*/`：SpamAssassin 各分类逐封原文；`cmds` 是原语料的辅助文件，**不是邮件，不执行、不导入**。
- `raw/nazario-mbox/`：Nazario 原始年度 mbox，保留便于来源追溯。
- `raw/nazario-YYYY/`：mbox 拆分的 `.eml`；仅去除 mbox 信封分隔行，不经模型改写。
- `manifests/sources/`：2026-10-20 获取的一手来源说明及 Nazario 许可证快照。
- `manifests/*.json`：来源、下载对象 SHA-256、大小、实测数量、许可与限制，可提交 Git。
- `manifests/*.files.jsonl`：逐文件路径、SHA-256、字节数、标签和 `is_message`，本机保存，不提交 Git。
- `.downloads/`：断点续传缓存；压缩包只在完整解压、CRC 校验、每个文件 SHA-256 读回复核及清单写入成功后删除。

`data/.gitignore` 排除原始邮件、下载缓存、逐封清单和运行日志。不得将真实邮件复制到测试目录或仓库其他未忽略路径。

## 来源与用途

| 数据 | 版本/范围 | 标签与用途 | 限制 |
|---|---|---|---|
| [CMU Enron](https://www.cs.cmu.edu/~enron/) | 2015-05-07 发布包，服务器文件长 443,254,787 字节；[官方下载](https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz) | 无安全金标准；批量导入、全文检索、统计、问答 | 不可全部标为正常；附件已删除，部分地址修正；不能证明头部原始真实性或现代恶意邮件识别能力。官网说明为研究资源、要求尊重隐私，未声明通用开放许可证 |
| [SpamAssassin](https://spamassassin.apache.org/old/publiccorpus/) | easy_ham / easy_ham_2 / hard_ham / spam 使用 20030228 包，spam_2 使用修正后的 20050311 包 | ham / spam；解析与垃圾邮件基础评测 | 原发件人保留正文版权，不套用 Apache 软件许可证；部分头部脱敏。**禁止回放至真实对外邮件系统**；当前 DNS/黑名单结果不适合充当历史金标准 |
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | 2015—2025 年度语料；本次不包含更早的独立 mbox 包 | phishing；钓鱼正样本补充，须另配正常样本 | 个人收件箱人工分类可能误标；非恶意附件金标准；部分历史样本脱敏，后期未脱敏。署名 José Nazario，遵循 [CC BY 4.0](https://monkey.org/~jose/phishing/LICENSE.txt)；[作者说明](https://monkey.org/~jose/phishing/README.txt) |

### 计数口径

以本地清单为准，未做跨来源去重。SpamAssassin 本次实测 **6,046 封**：ham 4,150，spam 1,896。官网 README 的历史汇总 6,047 与最新修正包相差 1 封；所选 `20050311_spam_2.tar.bz2` 实测 1,396 封，不把 `cmds` 辅助文件当邮件。

训练/开发/测试切分之前须按内容去重并保留来源，避免泄漏；语料标签 **spam 不等于 phishing，不等于恶意附件**。大规模重复回放仅算吞吐测试，不充当独立安全评测样本。原始语料不得自动发送给第三方模型；模型输入边界仍由项目配置和授权控制。

## 重现与验证

在 `mailsec-smart-search/` 下使用 Python 3.12+，无需新增依赖：

```bash
python3 scripts/datasets.py enron --workers 4
python3 scripts/datasets.py spamassassin --workers 1
python3 scripts/datasets.py nazario --workers 1 --nazario-years 2015 2016 2017 2018 2019 2020 2021 2022 2023 2024 2025
python3 scripts/datasets.py verify
```

每个进程最多 4 路 Range，单段最多 3 次网络重试；响应必须为匹配字节范围的 HTTP 206。中断后原命令可继续；远端 ETag/Last-Modified 改变则停止并保留缓存。不要同时启动两个进程处理同一数据集。

压缩包解压仅允许普通文件和目录，拒绝绝对路径、`..`、符号链接、硬链接、设备文件、重复覆盖，并设解压总量限制。SHA-256 是**本地复现校验值，不是发布机构提供的真实性签名**。

已经完成的清单不会自动重新下载；`verify` 对全部本地逐封文件及保留的 mbox 重新计算 SHA-256。新增/缺失或损坏的文件应先检查，不能把历史 `verified=true` 当作永久保证。
