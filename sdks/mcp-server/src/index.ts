#!/usr/bin/env node
// Elara MCP Server — gives AI agents cryptographic identity on the Elara mesh.
// MCP server for AI agents, exposing 5 tools.
//
// Configuration (CLI flags or env vars):
//   --node-url=http://...        ELARA_NODE_URL=http://127.0.0.1:9473
//   --default-identity=hex       ELARA_DEFAULT_IDENTITY=...
//   --timeout-ms=8000            ELARA_TIMEOUT_MS=8000
//
// Transport: stdio (the standard for MCP servers spawned by an AI client).

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { NodeClient } from "./node-client.js";
import {
  TOOL_DEFS,
  handleBalance,
  handleProve,
  handleRecord,
  handleWitness,
  handleSign,
  type ToolContext,
} from "./tools.js";

interface CliConfig {
  nodeUrl: string;
  defaultIdentity?: string;
  timeoutMs: number;
}

function parseConfig(): CliConfig {
  const argv = process.argv.slice(2);
  const flags = new Map<string, string>();
  for (const a of argv) {
    const m = a.match(/^--([\w-]+)=(.*)$/);
    if (m) flags.set(m[1]!, m[2]!);
  }
  const nodeUrl =
    flags.get("node-url") ??
    process.env.ELARA_NODE_URL ??
    "http://127.0.0.1:9473";
  const defaultIdentity =
    flags.get("default-identity") ?? process.env.ELARA_DEFAULT_IDENTITY ?? undefined;
  const timeoutMs = Number(
    flags.get("timeout-ms") ?? process.env.ELARA_TIMEOUT_MS ?? 8000,
  );
  return { nodeUrl, defaultIdentity, timeoutMs };
}

export function buildServer(ctx: ToolContext): Server {
  const server = new Server(
    { name: "elara-mcp", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFS.map((t) => ({ ...t })),
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const { name, arguments: args } = req.params;
    const a = (args ?? {}) as Record<string, unknown>;
    let result: unknown;
    try {
      switch (name) {
        case "elara_balance":
          result = await handleBalance(ctx, a as { identity?: string });
          break;
        case "elara_prove":
          result = await handleProve(ctx, a as { identity: string });
          break;
        case "elara_record":
          result = await handleRecord(ctx, a as { record: unknown });
          break;
        case "elara_witness":
          result = await handleWitness(
            ctx,
            a as { record_id: string; signature?: string; public_key?: string },
          );
          break;
        case "elara_sign":
          result = await handleSign(ctx, a as Parameters<typeof handleSign>[1]);
          break;
        default:
          throw new Error(`unknown tool: ${name}`);
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        content: [{ type: "text" as const, text: `error: ${msg}` }],
        isError: true,
      };
    }
    return {
      content: [
        { type: "text" as const, text: JSON.stringify(result, null, 2) },
      ],
    };
  });

  return server;
}

async function main(): Promise<void> {
  const cfg = parseConfig();
  const client = new NodeClient({ baseUrl: cfg.nodeUrl, timeoutMs: cfg.timeoutMs });
  const server = buildServer({ client, defaultIdentity: cfg.defaultIdentity });
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Stays alive until stdin closes.
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  main().catch((e) => {
    console.error("[elara-mcp] fatal:", e);
    process.exit(1);
  });
}
