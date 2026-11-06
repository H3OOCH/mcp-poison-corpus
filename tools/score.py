#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""score.py — 用真实扫描器给语料打分（召回 / 误报）

契约（你的扫描器要遵守）：
    命令行执行 `scanner <样本文件路径>` 或从 stdin 读样本 JSON，
    向 stdout 打印一行 JSON：  {"signals": ["prompt_injection", "hidden_unicode"]}
    信号名必须来自本文档约定的清单，未知信号会被忽略并提示。

用法：
    python tools/score.py --scanner "python my_scanner.py {sample}"
    python tools/score.py --scanner "mytool --stdin"        # 不给 {sample} 就走 stdin
    python tools/score.py --scanner "..." --json            # 输出机器可读结果

退出码：0 = 跑完（不管分数）；2 = 扫描器不可用/输出不合契约
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

def split_cmd(cmd):
    """按空格拆分命令，保留引号内内容与 Windows 反斜杠路径。

    不用 shlex.split：posix 模式会把 C:\\path 的反斜杠吃掉。
    """
    parts = re.findall(r'"[^"]*"|\'[^\']*\'|\S+', cmd)
    return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in '"\' ' else p for p in parts]

SIGNALS = [
    "prompt_injection",
    "hidden_unicode",
    "html_comment",
    "encoded_payload",
    "credential_path",
    "schema_bloat",
]


def run_scanner(cmd, sample):
    """把单条样本交给外部扫描器，返回 (signals_set, error)。"""
    blob = json.dumps(sample, ensure_ascii=False)
    if "{sample}" in cmd:
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(blob)
            argv = split_cmd(cmd.replace("{sample}", path))
            r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    else:
        argv = split_cmd(cmd)
        r = subprocess.run(argv, input=blob, capture_output=True, text=True, timeout=60)

    if r.returncode != 0:
        return None, f"退出码 {r.returncode}: {r.stderr.strip()[:200]}"

    out = r.stdout.strip()
    line = out.splitlines()[-1] if out else ""
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None, f"输出不是 JSON: {line[:120]!r}"

    raw = data.get("signals") or data.get("findings") or []
    got = set()
    unknown = []
    for s in raw:
        name = s.get("signal") if isinstance(s, dict) else s
        if name in SIGNALS:
            got.add(name)
        else:
            unknown.append(name)
    return (got, unknown), None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scanner", required=True, help='例如 "python my_scanner.py {sample}"')
    ap.add_argument("--corpus", default="corpus/samples.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    with open(args.corpus, encoding="utf-8") as f:
        samples = json.load(f)

    per_signal = {s: {"tp": 0, "fn": 0} for s in SIGNALS}
    flagged_positive = 0
    positives = 0
    fp_samples = []
    details = []
    errors = []

    for s in samples:
        res, err = run_scanner(args.scanner, s)
        if err:
            errors.append((s["id"], err))
            continue

        got, unknown = res
        expect = set(s.get("expect") or [])
        should = bool(s.get("should_flag"))

        row = {
            "id": s["id"],
            "should_flag": should,
            "expect": sorted(expect),
            "got": sorted(got),
            "unknown": unknown,
            "ok": False,
        }

        if should:
            positives += 1
            if got:
                flagged_positive += 1
            for sig in expect:
                if sig in got:
                    per_signal[sig]["tp"] += 1
                else:
                    per_signal[sig]["fn"] += 1
            # 正样本：命中了它声明的任一信号就算这一条通过
            row["ok"] = bool(got & expect)
        else:
            # 负样本：报了任何信号都算误报
            row["ok"] = not got
            if got:
                fp_samples.append(s["id"])

        details.append(row)

    if errors and len(errors) == len(samples):
        print("扫描器完全不可用：", file=sys.stderr)
        for sid, e in errors:
            print(f"  {sid}: {e}", file=sys.stderr)
        return 2

    total_tp = sum(v["tp"] for v in per_signal.values())
    total_fn = sum(v["fn"] for v in per_signal.values())
    recall = total_tp / (total_tp + total_fn) * 100 if (total_tp + total_fn) else 0
    negatives = len(details) - positives
    fp_rate = len(fp_samples) / negatives * 100 if negatives else 0

    result = {
        "samples": len(details),
        "positives": positives,
        "negatives": negatives,
        "sample_detection_rate": round(flagged_positive / positives * 100, 1) if positives else 0,
        "signal_recall": round(recall, 1),
        "false_positive_rate": round(fp_rate, 1),
        "false_positive_samples": fp_samples,
        "per_signal": per_signal,
        "errors": errors,
        "details": details,
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    print(f"{'id':<28}{'应为':<8}{'实际':<34}结果")
    print("-" * 78)
    for d in details:
        print(f"{d['id']:<28}{'报警' if d['should_flag'] else '清净':<8}{','.join(d['got']) or '-':<34}{'OK' if d['ok'] else 'FAIL'}")
    print()
    print(f"正样本 {positives} 条：任报即中的比例 {result['sample_detection_rate']}%")
    print(f"信号级召回 {result['signal_recall']}%（{total_tp} 命中 / {total_fn} 漏报）")
    print(f"负样本 {negatives} 条：误报率 {result['false_positive_rate']}%  {fp_samples or ''}")
    if errors:
        print(f"另有 {len(errors)} 条样本扫描器执行失败（未计入统计）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

