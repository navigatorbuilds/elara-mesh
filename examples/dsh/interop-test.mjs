// dsh↔elara-mcp interop test — drives @deepseek-ai/dsh-mcp-client (the real dsh
// MCP bridge plugin: stdio transport spawn, env scrubbing, tool discovery, public
// naming, callTool dispatch) against a release elara-mcp binary on a LIVE chain.
// Only dsh's internal ToolRegistry bookkeeping is stubbed with a Map — pulling the
// real registry drags the systemPrompt/llm service chain, which adds no interop
// surface. Everything that crosses the process boundary is dsh's own code.
//
// Setup (see README.md + docs/QUICKSTART-ISSUER.md):
//   npm install @deepseek-ai/dsh-mcp-client        # peers auto-install
//   export ELARA_MCP_BIN=/path/to/elara-mcp        # cargo build --release -p elara-mcp --features node
//   export ELARA_MCP_CLI=/path/to/elara-cli
//   export ELARA_MCP_NODE_URL=http://127.0.0.1:9474
//   export ELARA_NETWORK_ID=<your network id>
//   export ELARA_MCP_IDENTITY=/path/to/agent-identity.json
//   export ELARA_MCP_MANDATE_ID=<mandate id from elara-cli mandate-issue>
//   node interop-test.mjs
//
// NOTE: the act_emit leg writes a REAL record to the configured chain under the
// configured mandate (and spends one unit of the identity's daily emission cap).
import { Context } from '@deepseek-ai/cordis'
import * as mcpClient from '@deepseek-ai/dsh-mcp-client'

const need = (k) => {
  const v = (process.env[k] ?? '').trim()
  if (!v) { console.error(`${k} is required`); process.exit(2) }
  return v
}
const BIN = need('ELARA_MCP_BIN')
const ENV = Object.fromEntries(['ELARA_MCP_NODE_URL', 'ELARA_NETWORK_ID', 'ELARA_MCP_IDENTITY',
  'ELARA_MCP_MANDATE_ID', 'ELARA_MCP_CLI'].map(k => [k, need(k)]))
ENV.ELARA_MCP_AGENT_ID = process.env.ELARA_MCP_AGENT_ID ?? 'dsh-interop-test'

const registered = new Map()
const ctx = new Context()
ctx.provide('tools', {
  register(def) {
    registered.set(def.name, def)
    return () => registered.delete(def.name)
  },
})
if (!ctx.logger) {
  ctx.provide('logger', null)
  ctx.logger = { info: () => {}, warn: (...a) => console.error('[w]', ...a), error: (...a) => console.error('[e]', ...a), debug: () => {} }
}

const results = []
const check = (name, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`)
}

const fiber = ctx.plugin(mcpClient, {
  transport: 'stdio',
  serverName: 'elara',
  command: BIN,
  args: [],
  cwd: process.cwd(),
  env: ENV,
  toolCallTimeoutMs: 90000,
  failOnStartupError: true,
})
await fiber.await()

const t0 = Date.now()
while (registered.size < 4 && Date.now() - t0 < 20000) await new Promise(r => setTimeout(r, 200))

const names = [...registered.keys()].sort()
check('dsh registers the 4 tools under mcp__elara__mandate_*',
  JSON.stringify(names) === JSON.stringify([
    'mcp__elara__mandate_act_emit',
    'mcp__elara__mandate_act_status',
    'mcp__elara__mandate_bundle_verify',
    'mcp__elara__mandate_my_mandate',
  ]), names.join(','))

const exec = { signal: new AbortController().signal }
const callJson = async (pub, args) => {
  const def = registered.get(pub)
  if (!def) throw new Error(`tool not registered: ${pub}`)
  const out = await def.execute(args, exec)
  const text = out.content?.filter(b => b.type === 'text').map(b => b.text).join('\n') ?? ''
  return JSON.parse(text)
}

const mm = await callJson('mcp__elara__mandate_my_mandate', {})
check('my_mandate found + not revoked',
  mm.ok === true && mm.mandate?.found !== false && mm.mandate?.revoked !== true,
  `revoked=${mm.mandate?.revoked}`)

const em = await callJson('mcp__elara__mandate_act_emit', {
  tool: 'dsh-mcp-client',
  action: 'interop-test',
  args: { event: 'dsh-mcp-client end-to-end against elara-mcp', example: 'examples/dsh' },
  session_id: 'dsh-interop',
})
const rid = em.record_id
check('act_emit accepted through dsh dispatch', em.ok === true && typeof rid === 'string' && rid.length > 8,
  `record_id=${rid} args_hash=${String(em.args_hash ?? '').slice(0, 16)}…`)

if (em.ok === true && typeof rid === 'string') {
  const st = await callJson('mcp__elara__mandate_act_status', { record_id: rid })
  check('act_status authorized+valid', st.ok === true && st.status?.authorized === true && st.status?.flag === 'valid',
    `flag=${st.status?.flag}`)
}

const fails = results.filter(ok => !ok).length
console.log(`\n${results.length - fails}/${results.length} PASS${fails ? ` — ${fails} FAIL` : ''}`)
process.exit(fails ? 1 : 0)
