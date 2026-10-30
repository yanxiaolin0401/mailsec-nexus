# ClickHouse Cloud 注册与本机 mailsec 连接教程

适用于当前 `mailsec-smart-search` 项目。流程及官方文档核对日期：2026-10-30。控制台界面可能更新，以实际显示为准。

## 目标与安全边界

ClickHouse 在云端运行，本机 mailsec 通过 HTTPS 连接它。本机不再承担数据库计算，但 API、worker、Rspamd、ClamAV 仍会占用本机资源。若要本机仅保留浏览器，需要后续把这些服务也迁到远端。

本文是操作指南，不代表已经创建 Cloud 服务、修改部署或完成历史数据迁移。

- 不将数据库密码、凭据文件或含密码截图发到聊天、工单或 Git。
- 确认邮件数据允许上传所选云服务和地域，再启动写入。
- 保留原 `.env`、本地数据库数据卷及原始邮件，以便回退。
- 不执行 `docker compose down -v`。

## 一、注册并创建服务

1. 打开 [ClickHouse Cloud 控制台](https://console.clickhouse.cloud/)。
2. 使用邮箱或页面提供的第三方账号注册。邮箱注册需按邮件完成验证。
3. 登录后选择 **Create service**。
4. 服务名称可填写 `mailsec`；选择云厂商和地域。地域应接近运行 mailsec 的服务器，并满足邮件数据存储要求。
5. 核对资源配置和计费提示后确认。试用不等于永久免费，付款要求与默认资源以页面为准。
6. 等待服务可用，打开 **SQL Console**，执行：

```sql
SELECT 1;
```

返回 `1`，说明云端数据库正常工作。

三类凭据不要混淆：

| 凭据 | 用途 |
| --- | --- |
| 官网账号密码 | 登录网页控制台 |
| 数据库用户名和密码 | mailsec 连接数据库，本教程需要 |
| Cloud 管理 API Key | 管理云资源，本教程不需要 |

参考：[官方 Cloud 创建教程](https://clickhouse.com/docs/get-started/setup/cloud)。

## 二、保存数据库连接信息

进入服务，找到 **Connect**，选择 **HTTPS**，记录：

```text
Host：控制台提供的完整域名
Port：8443
Username：控制台提供的用户名，通常为 default
Password：生成的数据库密码
```

- Host 不带 `https://`、`:8443` 或路径。
- 本项目使用 HTTPS `8443`，不是 Native 协议的 `9440`。
- 首次显示的密码立即保存到密码管理器。关闭后通常不能再查看原密码，丢失需重置。

参考：[官方连接信息说明](https://clickhouse.com/docs/get-started/quickstarts/obtain-your-cloud-connection-details)。

## 三、配置公网出口 IP 白名单

当前项目运行于 Ubuntu 服务器：

```text
/home/ubuntu/projects/mailsec-nexus/mailsec-smart-search
```

应允许这台服务器的公网出口 IP，不一定是操作网页的个人电脑 IP。

1. 从服务器云厂商控制台确认公网出口地址。如果经过 NAT 网关，使用 NAT 出口 IP。
2. 在 ClickHouse Cloud 找到 **Settings → Security → IP access list → Add IPs**。
3. 选择只允许指定来源，添加 `服务器公网出口IPv4/32`，保存。
4. 如需从个人电脑直接连接，再单独添加个人电脑的公网出口 IP。

不要填写 `127.0.0.1`、`192.168.*` 或 Docker 内网地址。不要长期开放 `0.0.0.0/0`。出口 IP 变化后需同步更新白名单。

参考：[官方 IP 白名单设置](https://clickhouse.com/docs/products/cloud/guides/security/connectivity/setting-ip-filters)。

## 四、先测试连接，不迁移数据

在运行项目的 Ubuntu 服务器终端执行：

```bash
cd /home/ubuntu/projects/mailsec-nexus/mailsec-smart-search
```

项目已有 Python 虚拟环境和 ClickHouse 客户端，无需安装本地 ClickHouse 服务端。执行：

```bash
.venv/bin/python -c '
import getpass
import clickhouse_connect

host = input("Cloud Host（不带协议和端口）: ").strip()
user = input("数据库用户名（回车使用 default）: ").strip() or "default"
password = getpass.getpass("数据库密码（输入时不显示）: ")

client = clickhouse_connect.get_client(
    host=host,
    port=8443,
    username=user,
    password=password,
    secure=True,
    connect_timeout=15,
    send_receive_timeout=60,
)
try:
    print("连接成功:", client.query("SELECT 1, version()").result_rows)
finally:
    client.close()
'
```

密码输入时不显示字符属于正常现象。成功时看到类似：

```text
连接成功: [(1, '版本号')]
```

此步骤仅查询版本，不上传邮件。连接成功后再继续。

| 错误现象 | 优先检查 |
| --- | --- |
| 超时 | 出口 IP 白名单、服务器出站 8443、Cloud 服务是否就绪 |
| Authentication failed | 数据库用户名和密码，不是网页登录密码 |
| 域名解析失败 | Host 拼写、是否误加协议或端口、服务器 DNS |
| 证书错误 | 系统时间、代理、证书链；不要关闭证书验证 |
| 连接 9440 失败 | 改用 HTTPS 8443 |

## 五、准备独立的 Cloud 配置

### 1. 复制原配置，不覆盖 `.env`

```bash
cp -n .env .env.cloud
chmod 600 .env.cloud
nano .env.cloud
```

`cp -n` 不覆盖已有文件。如果已经存在 `.env.cloud`，直接检查并编辑。添加或修改以下字段，保证每个字段只出现一次：

```dotenv
CLICKHOUSE_HOST=你的Cloud域名
CLICKHOUSE_PORT=8443
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD='你的Cloud数据库密码'
CLICKHOUSE_DB=mailsec
```

用户名以 Connect 页面为准。密码包含特殊字符时须遵守 Compose `.env` 引号规则，不能把引号错误地当成密码内容。

保留其他已有配置，尤其是原 `MAILSEC_API_TOKEN`。数据库密码和应用访问令牌是不同凭据，不要互相替换。

nano 保存：`Ctrl+O`、回车；退出：`Ctrl+X`。

检查该文件是否被 Git 忽略：

```bash
git check-ignore .env.cloud
```

如没有输出，将 `.env.cloud` 加入 `.gitignore`，不要提交密钥文件。

### 2. 创建 Compose 覆盖文件

原 `compose.yaml` 把 `CLICKHOUSE_HOST` 写死为 `clickhouse`，只改环境文件不足以切换数据库。

```bash
nano compose.cloud.yaml
```

填入：

```yaml
x-cloud-db: &cloud-db
  CLICKHOUSE_HOST: ${CLICKHOUSE_HOST:?Set CLICKHOUSE_HOST}
  CLICKHOUSE_PORT: ${CLICKHOUSE_PORT:-8443}
  CLICKHOUSE_USER: ${CLICKHOUSE_USER:?Set CLICKHOUSE_USER}
  CLICKHOUSE_PASSWORD: ${CLICKHOUSE_PASSWORD:?Set CLICKHOUSE_PASSWORD}
  CLICKHOUSE_DB: ${CLICKHOUSE_DB:-mailsec}

services:
  clickhouse:
    profiles: [local-database]
  api:
    depends_on: !reset {}
    environment:
      <<: *cloud-db
    volumes:
      - cloud_app_data:/data

  worker:
    depends_on: !reset {}
    environment:
      <<: *cloud-db
    volumes:
      - cloud_app_data:/data

volumes:
  cloud_app_data:
```

该文件替换 API、worker 的数据库连接配置，移除本地 ClickHouse 启动依赖，并将本地数据库放入默认不启用的 profile。Cloud 模式使用独立的 `cloud_app_data` 队列卷，避免旧邮件自动上云；原 `app_data` 保持不变，其他环境变量及只读数据集挂载保留。`!reset` 需要支持该语法的 Compose；本机此前检查版本为 v5.5.1。

已检查项目安装的 `clickhouse-connect 1.10.0`：端口为 `8443` 时自动选择 HTTPS。当前项目没有实现 `CLICKHOUSE_SECURE` 环境变量，不要依赖添加该变量来开启 TLS。

### 3. 校验配置

如果当前 shell 之前导出过旧的 ClickHouse 变量，先清除，避免 shell 环境覆盖 `--env-file`：

```bash
unset CLICKHOUSE_HOST CLICKHOUSE_PORT CLICKHOUSE_USER CLICKHOUSE_PASSWORD CLICKHOUSE_DB
```

执行：

```bash
sudo docker compose \
  --env-file .env.cloud \
  -f compose.yaml \
  -f compose.cloud.yaml \
  config --quiet
```

没有报错即可。不要公开不带 `--quiet` 的配置输出，里面可能包含密码。

## 六、初始化云端空表

此步骤会创建数据库和空表，不导入邮件。首次可使用 Cloud 提供的管理员凭据；长期运行建议设置专用应用账户及所需权限。

下面使用现有应用镜像；若镜像尚不存在，先用相同 Compose 参数执行 `build api`。

```bash
sudo docker compose \
  --env-file .env.cloud \
  -f compose.yaml \
  -f compose.cloud.yaml \
  run --rm --no-deps -T api python - <<'PY'
from mailsec_smart_search.config import Settings
from mailsec_smart_search.storage import ClickHouseRepository
from mailsec_smart_search.event_storage import EventRepository

settings = Settings.from_env()
repo = ClickHouseRepository(settings)
repo.ensure_schema()
EventRepository(repo).ensure_schema()

print("数据库初始化成功")
print(repo.client.query("SHOW TABLES FROM mailsec").result_rows)
PY
```

预期看到：

```text
analysis_events
mail_events
mail_records
```

权限不足时检查用户是否具有建库、建表权限；放宽网络白名单不能解决数据库权限问题。

## 七、切换应用

### 1. 停止旧 API 和 worker

这会短暂中断业务，请在可接受的切换时段执行，避免旧 worker 继续写本地数据库。

```bash
sudo docker compose stop api worker
```

### 2. 只启动连接 Cloud 的 API

```bash
sudo docker compose \
  --env-file .env.cloud \
  -f compose.yaml \
  -f compose.cloud.yaml \
  up -d --no-deps api
```

不要省略末尾的 `api`。后续操作始终同时指定 `.env.cloud` 和两个 Compose 文件；误用原始 Compose 启动命令可能再次启动本地 ClickHouse。

检查数据库就绪状态：

```bash
curl -f http://127.0.0.1:8080/health/ready
```

成功后，在部署机器本机浏览器访问 `http://127.0.0.1:8080/`。业务操作仍需原来的应用访问令牌。

如果 Ubuntu 是远程服务器，在个人电脑终端建立 SSH 隧道：

```bash
ssh -N -L 18080:127.0.0.1:8080 ubuntu@服务器地址
```

保持该终端开启，再在个人电脑浏览器访问 `http://127.0.0.1:18080/`。无需公开 API 端口。

### 3. 确认数据允许上云后，启动 worker

**此覆盖文件使用独立的 Cloud 持久队列，不会自动处理原本地队列。** 新提交到 Cloud 模式 API 的邮件将写入 Cloud，先确认这些数据允许外发。不要未经审核改回原 `app_data` 卷或搬入旧队列。确认后执行：

```bash
sudo docker compose \
  --env-file .env.cloud \
  -f compose.yaml \
  -f compose.cloud.yaml \
  up -d --no-deps worker
```

先用合成测试邮件验证：API 接收成功、job 变为 `done`、页面可以检索、Cloud 中可查到对应记录。健康检查通过不能替代这项端到端验证。

### 4. 停止本地 ClickHouse

确认切换成功且没有其他程序依赖本地数据库后：

```bash
sudo docker compose stop clickhouse
```

不删除数据卷，不执行 `down -v`。Rspamd、ClamAV 是否继续运行，取决于是否需要原始 EML 本地扫描。

## 八、历史数据与回退注意事项

- 云端初始为空库，本地历史数据不会自动迁移。
- 已完成的队列任务不会因为切换数据库而自动重放。
- 旧导入断点不能证明云端完成了导入，不可直接复用它来判断迁移进度。
- 历史迁移应独立完成备份、传输、数量和内容核对，并验证三个表及原文引用。
- 若要回退，应先停止 Cloud 模式 API/worker，再使用原 `.env` 与原 Compose 配置恢复本地部署。切换期间新写入 Cloud 的数据不会自动回流，恢复前需明确如何对账和补齐，不能盲目反复切库。
- Cloud 支持当前项目所需的 MergeTree 家族能力，但会映射到 Shared 系列引擎，且不支持直接照搬本机 XML 配置。仍须实际验证建表、查询、去重及重试语义。

参考：[SharedMergeTree](https://clickhouse.com/docs/products/cloud/features/infrastructure/shared-merge-tree)、[Cloud 配置限制](https://clickhouse.com/docs/products/cloud/reference/settings)。

## 九、完成检查清单

- [ ] Cloud 服务创建成功，SQL Console 的 `SELECT 1` 返回正常。
- [ ] 已安全保存数据库凭据，白名单仅允许必要的公网出口地址。
- [ ] 本机 Python HTTPS 连接测试成功。
- [ ] `.env.cloud` 权限为 600，且不进入 Git。
- [ ] Compose 覆盖配置校验通过。
- [ ] 云端三张表创建成功。
- [ ] API 就绪检查通过，页面可访问。
- [ ] 已确认队列邮件允许上云，才启动 worker。
- [ ] 合成邮件完成接收、入库、检索闭环。
- [ ] 本地 ClickHouse 已停止，原数据卷保留。
- [ ] 历史数据迁移另行记录，未将空库切换误认为迁移完成。

至此数据库负担已转移到云端。若要进一步降低本机负担，可继续迁移 API、worker、扫描器和数据集，使本机只保留浏览器及远程开发客户端。

## 十、本机实际切换记录（2026-10-30）

第五至第七步已执行。原 `.env` 和本地数据卷未修改，Cloud 使用独立 `cloud_app_data` 卷。

- 已创建受保护的 `.env.cloud`（600 权限），并将其加入 Git 和 Docker 构建忽略规则；凭据文件也已加入 Git 忽略规则。
- 已创建 `compose.cloud.yaml`，默认只启用 API、worker；本地 ClickHouse、Rspamd、ClamAV 保持停止。
- 已创建云端三张表。Cloud 实际引擎为 `SharedReplacingMergeTree`（两张邮件表）和 `SharedMergeTree`（分析历史）。
- API `/health/ready` 返回 200；三个合成 JSON 事件均完成入队、worker 入库、查询、分页、统计、详情、幂等及冲突检查。报告见 [Cloud 合成事件验证](../reports/cloud-json-events-smoke.json)。
- 切换检查时云端 `mail_events=3`、`mail_records=0`、`analysis_events=0`；未迁移历史邮件、旧队列或导入断点，未调用外部模型。
- 本地完整测试：140 passed，1 条 Starlette/httpx 弃用警告；尚未进行 Cloud 容量压测、真实邮件扫描或历史迁移验收。
- 使用现有连接账户完成初始部署；正式生产前需收敛应用数据库权限。扫描器停用期间，原始 EML 本地扫描不可用。

后续查看运行状态：

```bash
sudo docker compose --env-file .env.cloud -f compose.yaml -f compose.cloud.yaml ps
```

后续重启已配置的应用（不要切回原始启动命令）：

```bash
sudo docker compose --env-file .env.cloud -f compose.yaml -f compose.cloud.yaml up -d --no-deps api worker
```

在个人电脑访问当前服务器控制台：

```bash
ssh -N -L 18080:127.0.0.1:8080 ubuntu@43.133.251.134
```

保持隧道连接，浏览器访问 `http://127.0.0.1:18080/`，使用原应用令牌；不要使用 ClickHouse 数据库密码登录应用。
