#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""baseline.py — 参考扫描器（故意做得“笨”，用来说明语料能区分好坏）

它不是最优解，只是一条基准线：正则 + 结构规则，无模型。
用它跑分：
    python tools/score.py --scanner "python tools/baseline.py {sample}"

它会漏（改写得巧的注入）也会误报（正常引用注入短语的文档）——
这正是语料存在的意义：让改进有数字可量。
"""
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


def scan(payload):
    text = flatten(payload)
    out = []
    if INJECTION.search(text):
        out.append("prompt_injection")
    if ZERO_WIDTH.search(text):
        out.append("hidden_unicode")
    if HTML_COMMENT.search(text):
        out.append("html_comment")
    if CRED_PATH.search(text):
        out.append("credential_path")
    if any(decodes_to_text(t) for t in B64_TOKEN.findall(text)):
        out.append("encoded_payload")

    schema = payload.get("inputSchema") if isinstance(payload, dict) else None
    if isinstance(schema, dict):
        props = schema.get("properties") or {}
        wide = schema.get("additionalProperties") is True
        big_enum = any(isinstance(p, dict) and len(p.get("enum") or []) > 10 for p in props.values())
        loose = any(isinstance(p, dict) and p.get("additionalProperties") is True for p in props.values())
        if wide and (big_enum or loose):
            out.append("schema_bloat")
    return out


def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], encoding="utf-8") as f:
            sample = json.load(f)
    else:
        sample = json.load(sys.stdin)

    payload = sample.get("payload") if isinstance(sample, dict) and "payload" in sample else sample
    print(json.dumps({"signals": scan(payload)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
