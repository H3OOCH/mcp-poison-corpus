#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selfcheck.py — 校验语料自身是否正确

每条样本都声明了 expect（它应该触发哪些信号）。
本脚本反向验证：样本里**确实**存在对应的可疑内容。
防止语料写错导致打分器算错召回。

用法：
    python tools/selfcheck.py
    python tools/selfcheck.py --corpus corpus/samples.json
退出码：0 = 全部一致；1 = 有不一致
"""
import argparse
import base64
import json
import re
import sys

ZERO_WIDTH = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\ufeff\U000E0000-\U000E007F]")
INJECTION = re.compile(
    r"ignore[\s_]+(all[\s_]+)?(previous|prior)[\s_]+instructions"
    r"|do\s+not\s+tell\s+the\s+user"
    r"|never\s+tell\s+the\s+user"
    r"|do\s+not\s+mention"
    r"|assistant:\s*before",
    re.I,
)
HTML_COMMENT = re.compile(r"<!--[\s\S]*?-->")
CRED_PATH = re.compile(r"(\.ssh|\.aws/id_rsa|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.kube/config)", re.I)
B64_TOKEN = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")


def flatten(node):
    """把 payload 拍平成一段文本，便于做包含性检查。"""
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        return "\n".join(flatten(v) for v in node.values())
    if isinstance(node, list):
        return "\n".join(flatten(v) for v in node)
    return ""


def decodes_to_text(tok):
    try:
        raw = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=False)
        txt = raw.decode("utf-8", errors="strict")
        printable = sum(c.isprintable() or c.isspace() for c in txt)
        return len(txt) >= 12 and printable / max(len(txt), 1) > 0.85
    except Exception:
        return False


def signals_in(payload):
    """返回这条 payload 里真实存在的信号集合。"""
    text = flatten(payload)
    found = set()
    if INJECTION.search(text):
        found.add("prompt_injection")
    if ZERO_WIDTH.search(text):
        found.add("hidden_unicode")
    if HTML_COMMENT.search(text):
        found.add("html_comment")
    if CRED_PATH.search(text):
        found.add("credential_path")
    if any(decodes_to_text(t) for t in B64_TOKEN.findall(text)):
        found.add("encoded_payload")
    schema = payload.get("inputSchema") if isinstance(payload, dict) else None
    if isinstance(schema, dict):
        props = schema.get("properties") or {}
        wide = schema.get("additionalProperties") is True
        big_enum = any(
            isinstance(p, dict) and len(p.get("enum") or []) > 10 for p in props.values()
        )
        if wide and (big_enum or any(isinstance(p, dict) and p.get("additionalProperties") is True for p in props.values())):
            found.add("schema_bloat")
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="corpus/samples.json")
    args = ap.parse_args()

    with open(args.corpus, encoding="utf-8") as f:
        samples = json.load(f)

    bad = 0
    for s in samples:
        expect = set(s.get("expect") or [])
        actual = signals_in(s.get("payload") or {})
        ok = expect == actual
        flag = "OK  " if ok else "FAIL"
        print(f"[{flag}] {s['id']:<28} expect={sorted(expect)} actual={sorted(actual)}")
        if not ok:
            bad += 1
            if expect - actual:
                print(f"       声明了但样本里找不到: {sorted(expect - actual)}")
            if actual - expect:
                print(f"       样本里有但没声明: {sorted(actual - expect)}")

    print()
    print(f"共 {len(samples)} 条，问题 {bad} 条")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
