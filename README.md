# mcp-poison-corpus

**一个公开的「投毒样本」语料 + 打分器，用来量化 MCP 工具与 Skill 的提示注入检测能力。**

现在的状况是：检测器（扫描器、审计插件、网关）各说各的好，但没有共用的一套样本，谁也没法证明自己准。
这个仓库只做一件事——**把样本和评分标准摊开，让"能不能查出来"变成可比较的数字。**

> 全部样本为**合成数据**：域名用 `example.invalid`，凭据路径指向不存在的文件，没有任何可执行的利用代码。

---

## 快速开始

```bash
# 1. 先确认语料自身没写错（每条样本声称的信号必须真的存在）
python tools/selfcheck.py

# 2. 用参考扫描器跑一遍
python tools/score.py --scanner "python tools/baseline.py {sample}"
```

参考基线（`tools/baseline.py`，纯正则，无模型）在这批样本（16 条：13 正 / 3 负）上的成绩：

```
正样本 13 条：任报即中的比例 100.0%
信号级召回 100.0%（17 命中 / 0 漏报）
负样本 3 条：误报率 33.3%  ['control-mentions-security']
```

**33.3% 的误报来自哪条**：`control-mentions-security` 是一份正常的安全检查文档，正文里**引用**了
`"ignore previous instructions"` 作为示例。纯正则分不出"引用"和"指令"——这就是留给你的改进空间：
**在保持 100% 召回的前提下把误报压到 0**。

> 基线本身也是被语料改出来的：第一版正则用 `\s` 匹配词间空白，遇到 `search_and_ignore_previous_instructions`
> 这种下划线工具名直接漏报。语料把这个问题逼出来了，规则才补成 `[\s_]+`。

---

## 扫描器契约

你的工具只要满足这一条就能被打分：

```bash
<你的命令> <样本文件路径>      # 或：<你的命令> 从 stdin 读样本 JSON
```

向 stdout 打印**一行 JSON**：

```json
{"signals": ["prompt_injection", "hidden_unicode"]}
```

信号名从下面这个清单里选（未知名字会被忽略并提示）：

| 信号 | 含义 |
|---|---|
| `prompt_injection` | 试图覆盖/隐瞒/越权：ignore previous instructions、do not tell the user… |
| `hidden_unicode` | 零宽字符、双向控制符等"肉眼看不见"的字符 |
| `html_comment` | HTML 注释里藏指令 |
| `encoded_payload` | base64 等编码后的指令 |
| `credential_path` | 描述里出现 `~/.ssh/id_rsa`、`~/.aws/credentials` 这类路径 |
| `schema_bloat` | Schema 完全开放（`additionalProperties: true`）+ 超大枚举，实际校验形同虚设 |

## 打分口径

- **正样本**（`should_flag: true`）：命中它声明的**任一**信号即算这条通过
- **信号级召回**：所有正样本里，声明了却没报出来的信号数 → 漏报
- **负样本**（`should_flag: false`）：报了任何信号都算误报
- 两个数字要一起看：**只追召回，误报会毁掉工具；只追误报，等于什么都不报**

```bash
python tools/score.py --scanner "你的命令 {sample}" --json   # 机器可读，便于接 CI
```

---

## 样本格式

```json
{
  "id": "html-comment",
  "kind": "mcp_tool | skill",
  "should_flag": true,
  "expect": ["html_comment", "prompt_injection", "credential_path"],
  "note": "这句话解释这条样本在考什么",
  "payload": { "name": "...", "description": "...", "inputSchema": {...} }
}
```

- `expect` 是**文本里真实存在**的信号（`selfcheck.py` 会验证）
- `should_flag` 是**扫描器该不该报警**。二者可以不一致——那就是硬负样本（`control-mentions-security`）

---

## 贡献

欢迎提交新样本，但请遵守：

1. **合成**：不要贴真实公司、真实邮箱、真实凭据；域名一律 `example.invalid`
2. **写明考点**：`note` 一句话说清这条攻击面是什么
3. **过自检**：提交前跑 `python tools/selfcheck.py`，必须全 OK
4. **不带利用代码**：可以有命令**字样**，但不要放能直接跑的载荷

同时也欢迎提交"你的扫描器跑分结果"（开个 issue 贴 `--json` 输出），我会把公开成绩整理进 `LEADERBOARD.md`。

---

## 边界（务必读）

- 这是**测试语料**，不是安全认证。语料里没有的写法不代表安全。
- 检测是启发式的，**任何扫描器都会有漏报**；把它当"提高发现概率"，不要当"准入许可"。
- 样本按 MIT 许可分发，可自由用于你的测试与论文，引用请附仓库链接。

## License

MIT
