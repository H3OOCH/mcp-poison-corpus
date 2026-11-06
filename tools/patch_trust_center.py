#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给 dsh-trust-center 打 6 个补丁（语料实测暴露的问题）。可重复执行，幂等。"""
import io
import os
import sys

SRC = r"D:\DSH WorkSpace\dsh-trust-center\src\heuristics.js"

PATCHES = []


def patch(old, new, name):
    PATCHES.append((old, new, name))


# 1) 兼容 MCP 规范的 inputSchema
patch(
    "  const parameters = schema?.parameters ?? {}",
    "  const parameters = schema?.parameters ?? schema?.inputSchema ?? {}",
    "inputSchema 兼容",
)

# 2) 扫工具名（只针对提示注入）
patch(
    "  if (parameterText.length > OVERSIZED_SCHEMA) {",
    "  if (scanPromptText(name)) {\n"
    "    findings.push(makeFinding({\n"
    "      ...base,\n"
    "      rule: 'prompt-injection-override',\n"
    "      field: 'name',\n"
    "      severity: 'high',\n"
    "      evidence: [{ field: 'name', offset: 0, snippet: truncate(name, 120) }],\n"
    "    }))\n"
    "  }\n\n"
    "  if (parameterText.length > OVERSIZED_SCHEMA) {",
    "扫工具名",
)

# 3) 宽松 schema：有 properties 但全开放 / 超大枚举也算
patch(
    "  if (hasProperties) return false\n"
    "  const keys = Object.keys(parameters)\n"
    "  return parameters.additionalProperties === true || keys.length === 0",
    "  const keys = Object.keys(parameters)\n"
    "  if (parameters.additionalProperties === true && keys.length === 0) return true\n"
    "  if (!hasProperties) return parameters.additionalProperties === true || keys.length === 0\n"
    "  // 有 properties 但形同虚设：根级或任一属性允许任意附加字段 / 枚举大到等于没有约束\n"
    "  if (parameters.additionalProperties === true) return true\n"
    "  for (const value of Object.values(parameters.properties)) {\n"
    "    if (value === null || typeof value !== 'object') continue\n"
    "    if (value.additionalProperties === true) return true\n"
    "    if (Array.isArray(value.enum) && value.enum.length >= 10) return true\n"
    "  }\n"
    "  return false",
    "宽松 schema",
)

# 4) 凭据路径补全（两处正则）
CRED_OLD = r"\.env|\.ssh|id_rsa|id_ed25519|credentials|auth\.json"
CRED_NEW = r"\.env|\.ssh|id_rsa|id_ed25519|credentials|auth\.json|\.npmrc|\.kube[\\/]config|\.aws[\\/]credentials"
patch(CRED_OLD, CRED_NEW, "凭据路径补全")

# 5) 短 base64 也能查：解码后看到指令词就报
patch(
    "const pattern = /[A-Za-z0-9+/]{400,}={0,2}/g",
    "const pattern = /[A-Za-z0-9+/]{40,}={0,2}/g",
    "base64 长度阈值 400→40",
)
patch(
    "    if (/\\b(?:base64|atob|decode|decrypt|execute|exec|eval|payload)\\b/i.test(around)) return match.index",
    "    if (/\\b(?:base64|atob|decode|decrypt|execute|exec|eval|payload)\\b/i.test(around)) return match.index\n"
    "    // 解码看一眼：内容里出现指令/凭据词，就不再要求附近有 decode 字样\n"
    "    try {\n"
    "      const decoded = atob(match[0].replace(/-/g, '+').replace(/_/g, '/'))\n"
    "      if (containsInstruction(decoded) || containsCredentialAccess(decoded)) return match.index\n"
    "    } catch { /* 不是合法 base64，忽略 */ }",
    "base64 解码判断",
)

# 6) 引用/示例里的注入短语不报（降误报）
patch(
    "    while ((match = pattern.regex.exec(source)) !== null && evidence.length < 2) {\n"
    "      evidence.push(evidenceAt(source, match.index, field, input.lineBase))",
    "    while ((match = pattern.regex.exec(source)) !== null && evidence.length < 2) {\n"
    "      if (!isQuotedExample(source, match.index, match[0].length)) {\n"
    "        evidence.push(evidenceAt(source, match.index, field, input.lineBase))\n"
    "      }",
    "引用不判注入",
)

HELPERS = """
/** 只用于工具名：是否命中提示注入模式 */
function scanPromptText(text) {
  const source = String(text ?? '')
  if (source.length === 0) return false
  return PROMPT_PATTERNS.some((pattern) => {
    pattern.regex.lastIndex = 0
    return pattern.regex.test(source)
  })
}

/** 匹配片段是否处在"引用/举例"语境里（正常文档引用攻击短语不该报） */
function isQuotedExample(source, index, length) {
  const before = source.slice(Math.max(0, index - 2), index)
  const after = source.slice(index + length, index + length + 2)
  const quoted = /["'\\u201c\\u201d\\u2018\\u2019]/.test(before) || /["'\\u201c\\u201d\\u2018\\u2019]/.test(after)
  if (!quoted) return false
  const window = source.slice(Math.max(0, index - 120), index + length + 120)
  return /example|e\\.g\\.|for instance|as examples|示例|举例|引用/i.test(window)
}
"""


def main():
    with io.open(SRC, encoding="utf-8") as f:
        src = f.read()

    changed = []
    for old, new, name in PATCHES:
        if old not in src:
            print(f"[skip] {name}: 目标片段不存在（可能已打过）")
            continue
        src = src.replace(old, new, 1)
        changed.append(name)

    if "function isQuotedExample(" not in src:
        # 插到 scanField 之前，保证函数提升可用（ESM 函数声明会提升，位置不敏感）
        anchor = "export function scanField(input) {"
        if anchor in src:
            src = src.replace(anchor, HELPERS.strip() + "\n\n" + anchor, 1)
            changed.append("新增两个辅助函数")

    with io.open(SRC, "w", encoding="utf-8", newline="\n") as f:
        f.write(src)

    print("已改动:", ", ".join(changed) if changed else "无")
    return 0


if __name__ == "__main__":
    sys.exit(main())
