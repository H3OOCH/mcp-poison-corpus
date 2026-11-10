#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ci_summary.py — 把 score.py 的 JSON 结果渲染成 markdown 表格（给 GitHub Step Summary 用）

用法：python tools/ci_summary.py score-baseline.json >> "$GITHUB_STEP_SUMMARY"
"""
import json
import os
import sys

MD = os.environ.get("GITHUB_STEP_SUMMARY")


def render(path):
    if not os.path.exists(path):
        return "| 注意 | 打分文件不存在，检查上一步 |\n"
    raw = open(path, "rb").read()
    for enc in ("utf-8-sig", "utf-16", "utf-8"):
        try:
            d = json.loads(raw.decode(enc))
            break
        except Exception:
            d = None
    if d is None:
        return "| 注意 | 打分文件无法解析 |\n"
    rows = [
        "| 指标 | 数值 |",
        "|---|---|",
        f"| 样本数 | {d['samples']}（正 {d['positives']} / 负 {d['negatives']}） |",
        f"| 样本级检出 | {d['sample_detection_rate']}% |",
        f"| 信号级召回 | {d['signal_recall']}% |",
        f"| 负样本误报 | {d['false_positive_rate']}% |",
    ]
    fp = d.get("false_positive_samples") or []
    if fp:
        rows.append(f"| 误报样本 | {', '.join(fp)} |")
    errs = d.get("errors") or []
    if errs:
        rows.append(f"| 扫描器错误 | {len(errs)} 条 |")
    return "\n".join(rows) + "\n"


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "score-baseline.json"
    text = render(path)
    if MD:
        with open(MD, "a", encoding="utf-8") as f:
            f.write("## mcp-poison-corpus 打分\n\n" + text)
        print(text)
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
