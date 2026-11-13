#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
邮件离线接入标准接口灌测客户端 (Bench Pusher)
零外部依赖，使用 Python 标准库向 POST /api/v2/mails 发起并发或顺序灌测，并输出统计报表。

用法：
    python bench_push.py --url http://127.0.0.1:8000/api/v2/mails --file mail_offline_dataset_1000.jsonl --limit 100
"""

import sys
import os
import json
import time
import argparse
import urllib.request
import urllib.error
from typing import Any, Dict, List, Tuple


def post_single(url: str, record: Dict[str, Any], api_key: str, timeout: float = 10.0) -> Tuple[int, float, str]:
    data = json.dumps(record, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "X-Intake-Key": api_key
        }
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - t0
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, elapsed, body
    except urllib.error.HTTPError as exc:
        elapsed = time.perf_counter() - t0
        err_body = exc.read().decode("utf-8", errors="replace")
        return exc.code, elapsed, err_body
    except Exception as exc:
        elapsed = time.perf_counter() - t0
        return 0, elapsed, str(exc)


def main():
    parser = argparse.ArgumentParser(description="邮件离线分析接口灌测工具")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8000/api/v2/mails", help="目标接收接口地址")
    parser.add_argument("--file", type=str, default="mail_offline_dataset_1000.jsonl", help="测试数据集路径 (JSONL)")
    parser.add_argument("--limit", type=int, default=100, help="灌测条数 (0 表示全量)")
    parser.add_argument("--key", type=str, default="dev-bench-key", help="X-Intake-Key 鉴权密钥")
    parser.add_argument("--delay", type=float, default=0.0, help="每条请求间隔时间(秒)")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[!] 找不到数据文件: {args.file}")
        sys.exit(1)

    print(f"[*] 开始向 {args.url} 推送测试数据...")
    print(f"[*] 数据集: {args.file}, 计划推送数量: {'全量' if args.limit <= 0 else args.limit}")

    records: List[Dict[str, Any]] = []
    with open(args.file, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            if args.limit > 0 and idx >= args.limit:
                break
            line_str = line.strip()
            if line_str:
                records.append(json.loads(line_str))

    total = len(records)
    print(f"[*] 成功装载 {total} 条标准格式报文，开始执行推送...\n")

    status_counts: Dict[int, int] = {}
    latencies: List[float] = []
    errors: List[str] = []

    start_all = time.perf_counter()

    for i, record in enumerate(records, 1):
        code, lat, resp_text = post_single(args.url, record, args.key)
        status_counts[code] = status_counts.get(code, 0) + 1
        latencies.append(lat)

        if code != 202:
            if len(errors) < 5:
                errors.append(f"第 {i} 条 [HTTP {code}] eventId={record.get('eventId')}: {resp_text[:100]}")

        if i % 20 == 0 or i == total:
            rps = i / (time.perf_counter() - start_all)
            print(f"  [进度: {i}/{total}] 当前吞吐: {rps:.1f} req/s, HTTP 202 成功: {status_counts.get(202, 0)}, 失败: {i - status_counts.get(202, 0)}")

        if args.delay > 0:
            time.sleep(args.delay)

    total_time = time.perf_counter() - start_all
    avg_lat = (sum(latencies) / len(latencies)) * 1000 if latencies else 0
    latencies.sort()
    p95_lat = latencies[int(len(latencies) * 0.95)] * 1000 if latencies else 0

    print("\n" + "=" * 50)
    print("           灌测统计结果报表")
    print("=" * 50)
    print(f"总发送邮件数:   {total} 封")
    print(f"总耗时:         {total_time:.2f} 秒")
    print(f"平均吞吐率:     {total / total_time:.1f} req/s")
    print(f"平均响应延迟:   {avg_lat:.2f} ms")
    print(f"P95 响应延迟:   {p95_lat:.2f} ms")
    print("状态码分布:")
    for c, cnt in sorted(status_counts.items()):
        status_desc = "Accepted (成功受理)" if c == 202 else "Error (异常)"
        print(f"  HTTP {c}: {cnt} 次 ({status_desc})")

    if errors:
        print("\n部分异常回包样例:")
        for err in errors:
            print(f"  [!] {err}")

    if status_counts.get(202, 0) == total:
        print("\n[+] 验收通过！所有邮件均以 HTTP 202 成功受理并排队。")
    else:
        print("\n[!] 存在未按 202 成功受理的请求，请检查各组错误回包与 Pydantic 校验日志。")


if __name__ == "__main__":
    main()
