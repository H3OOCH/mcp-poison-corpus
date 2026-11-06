// trust-center 适配器：把 dsh-trust-center 的启发式规则接到 mcp-poison-corpus 的打分器上
// 用法： node trust-center.mjs <sample.json>      或从 stdin 读
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const PLUGIN = 'file:///D:/DSH%20WorkSpace/dsh-trust-center/src/heuristics.js';

const MAP = [
  [/^prompt-injection/, 'prompt_injection'],
  [/^hidden-unicode/, 'hidden_unicode'],
  [/^hidden-html-comment/, 'html_comment'],
  [/encoded|base64/, 'encoded_payload'],
  [/^credential-access/, 'credential_path'],
  [/^broad-schema/, 'schema_bloat'],
];

function toSignal(rule) {
  const r = String(rule || '').toLowerCase();
  for (const [re, sig] of MAP) if (re.test(r)) return sig;
  return null;
}

async function main() {
  let raw;
  if (process.argv[2]) raw = readFileSync(process.argv[2], 'utf8');
  else raw = readFileSync(0, 'utf8');

  const sample = JSON.parse(raw);
  const payload = sample.payload ?? sample;
  const kind = sample.kind ?? 'mcp_tool';

  const { scanMcpTool, scanSkill } = await import(PLUGIN);
  const pick = (res) => (Array.isArray(res) ? res : res?.findings ?? []);
  let findings = [];

  if (kind === 'skill') {
    findings = pick(scanSkill({ name: payload.skill_name ?? 'sample' }, { content: payload.body ?? '' }));
  } else {
    findings = pick(
      scanMcpTool(
        {
          name: payload.name ?? 'sample',
          description: payload.description ?? '',
          // 注意：trust-center 读的是 parameters；MCP 规范里字段叫 inputSchema。
          // 两个都传，兼容两种来源。
          parameters: payload.inputSchema ?? payload.parameters,
          inputSchema: payload.inputSchema ?? payload.parameters,
        },
        0,
      ),
    );
  }

  const signals = new Set();
  for (const f of findings) {
    const sig = toSignal(f.rule ?? f.id ?? f.ruleId);
    if (sig) signals.add(sig);
  }
  process.stdout.write(JSON.stringify({ signals: [...signals] }) + '\n');
}

main().catch((e) => {
  process.stderr.write(String(e && e.stack ? e.stack : e) + '\n');
  process.exit(1);
});
