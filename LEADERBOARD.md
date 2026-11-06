# Leaderboard

用 `python tools/score.py --scanner "你的命令 {sample}" --json` 跑完，把 JSON 贴到 issue，或提 PR 加到下表。

| 扫描器 | 方法 | 样本数 | 信号召回 | 误报率 | 备注 |
|---|---|---|---|---|---|
| baseline（本仓库） | 正则 + 结构规则 | 16 | 100.0% | 33.3% | 硬负样本过不去 |
| _你的_ | | | | | |

**记分口径**：召回和误报必须同时报。只报召回的，等于没报。
| trust-center 0.2.1（dsh-trust-center） | 规则匹配 + 结构启发式 | 16 | 52.9% | 66.7% | 见下方"已知缺口" |

## 已知缺口（trust-center 0.2.1 实测，2026-11-06）

用 `tools/adapters/trust-center.mjs` 接入后跑出的结果：**样本级 53.8% / 信号级 52.9% / 误报 66.7%**。

漏报（该报没报）：
1. `encoded-payload`、`encoded-in-schema-desc` —— 没有 base64 解码检测
2. `credential-path`、`cred-npmrc-kube` —— 凭据规则要求"动词 + 路径"同现，且路径表里没有 `~/.npmrc`、`~/.kube/config`
3. `schema-bloat` —— `isBroadSchema` 没覆盖"additionalProperties 全开 + 超大枚举"这种组合
4. `inj-tool-name` —— 只扫描述和 schema，不扫工具名

误报（不该报却报了）：
1. `control-mentions-security` —— 文档里**引用**注入短语作为示例
2. `control-long-legit-doc` —— 正文出现 "system prompt" 字样就被判 role 注入

接口问题：
- 读的是 `schema.parameters`，而 MCP `tools/list` 的字段是 `inputSchema`；按规范接入时 schema 会被读成空对象，`broad-schema` 全线误报。
