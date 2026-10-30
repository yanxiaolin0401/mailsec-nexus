# 测试与实测

在模块目录执行 `.venv/bin/python -m pytest -q`。pytest只收集本目录，不遍历 `data/` 的51万封邮件。测试使用合成EML和tmp_path，不读企业邮件、不执行附件、不调用付费模型。

覆盖：MIME/畸形/长头/子进程解析；spool去重、配额、崩溃恢复、ready索引；批次导入checkpoint；ClickHouse参数绑定与并发连接；API前置鉴权/体积/慢请求上限；本机扫描器故障；模型双协议/429/超时/非法输出/脱敏门禁；融合与SOP预算；数据下载Range/CRC/解压安全；证据路径与哈希；benchmark/evaluation逻辑；CLI失败退出码。

单元测试的假数据库/模拟模型不能证明真实部署或准确率。真实证据另见 `docs/reports/` 和 `scripts/smoke_http.py`、`benchmark.py`、`evaluate_detectors.py`、`smoke_model.py`。
