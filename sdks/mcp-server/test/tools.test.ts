// Smoke tests for the five MCP tool handlers. Spins up a tiny HTTP stub
// that mirrors the public REST API shape so we don't need a live node.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { NodeClient } from "../src/node-client.js";
import {
  TOOL_DEFS,
  handleBalance,
  handleProve,
  handleRecord,
  handleWitness,
  handleSign,
} from "../src/tools.js";

interface StubRoute {
  method: string;
  path: string;
  body: unknown;
  status?: number;
}

function startStub(routes: StubRoute[]): Promise<{
  url: string;
  close: () => Promise<void>;
  hits: { method: string; path: string; body: string }[];
}> {
  const hits: { method: string; path: string; body: string }[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      hits.push({ method: req.method ?? "", path: req.url ?? "", body });
      const route = routes.find(
        (r) =>
          r.method === req.method && req.url && req.url.startsWith(r.path),
      );
      if (!route) {
        res.statusCode = 404;
        return res.end("not found");
      }
      res.statusCode = route.status ?? 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(route.body));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address() as AddressInfo;
      resolve({
        url: `http://127.0.0.1:${addr.port}`,
        hits,
        close: () =>
          new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

test("TOOL_DEFS exposes exactly the 5 expected tools", () => {
  const names = TOOL_DEFS.map((t) => t.name).sort();
  assert.deepEqual(names, [
    "elara_balance",
    "elara_prove",
    "elara_record",
    "elara_sign",
    "elara_witness",
  ]);
});

test("elara_balance reads /proof/account and projects account_state + flags", async () => {
  const stub = await startStub([
    {
      method: "GET",
      path: "/proof/account/abc123",
      body: {
        identity: "abc123",
        exists: true,
        root: "0".repeat(64),
        account_state: {
          available: 5_000_000,
          staked: 2_000_000,
          total_received: 7_000_000,
          total_sent: 0,
          tx_count: 4,
          last_active: 1_700_000_000,
        },
        bound_to_seal: true,
      },
    },
  ]);
  try {
    const client = new NodeClient({ baseUrl: stub.url });
    const out: any = await handleBalance({ client }, { identity: "abc123" });
    assert.equal(out.available, 5_000_000);
    assert.equal(out.staked, 2_000_000);
    assert.equal(out.exists, true);
    assert.equal(out.bound_to_seal, true);
    // Must read the public proof endpoint, never the loopback-only /account.
    assert.equal(stub.hits[0]!.path, "/proof/account/abc123");
  } finally {
    await stub.close();
  }
});

test("elara_balance falls back to default_identity and reports exists:false", async () => {
  const stub = await startStub([
    {
      method: "GET",
      path: "/proof/account/deadbeef",
      body: { identity: "deadbeef", exists: false, root: "0".repeat(64) },
    },
  ]);
  try {
    const client = new NodeClient({ baseUrl: stub.url });
    const out: any = await handleBalance(
      { client, defaultIdentity: "deadbeef" },
      {},
    );
    assert.equal(out.identity, "deadbeef");
    assert.equal(out.exists, false);
    assert.equal(out.bound_to_seal, false);
  } finally {
    await stub.close();
  }
});

test("elara_balance errors clearly when no identity available", async () => {
  const client = new NodeClient({ baseUrl: "http://127.0.0.1:1" });
  await assert.rejects(
    () => handleBalance({ client }, {}),
    /identity is required/,
  );
});

test("elara_prove hits /proof/account/{identity} and surfaces siblings", async () => {
  const stub = await startStub([
    {
      method: "GET",
      path: "/proof/account/abc123",
      body: {
        identity: "abc123",
        exists: true,
        root: "0".repeat(64),
        state_hash: "1".repeat(64),
        siblings: [{ hash: "2".repeat(64), is_right: true }],
        depth: 1,
        bound_to_seal: true,
      },
    },
  ]);
  try {
    const client = new NodeClient({ baseUrl: stub.url });
    const out: any = await handleProve({ client }, { identity: "abc123" });
    assert.equal(out.depth, 1);
    assert.equal(out.bound_to_seal, true);
    assert.equal(out.siblings.length, 1);
  } finally {
    await stub.close();
  }
});

test("elara_record posts to /records and returns the node response", async () => {
  const stub = await startStub([
    { method: "POST", path: "/records", body: { accepted: true, id: "rec1" } },
  ]);
  try {
    const client = new NodeClient({ baseUrl: stub.url });
    const out: any = await handleRecord(
      { client },
      { record: { id: "rec1", payload: "x" } },
    );
    assert.equal(out.accepted, true);
    assert.equal(stub.hits[0]!.method, "POST");
    assert.match(stub.hits[0]!.body, /"id":"rec1"/);
  } finally {
    await stub.close();
  }
});

test("elara_witness in build mode returns to_sign_hex without hitting the network", async () => {
  const client = new NodeClient({ baseUrl: "http://127.0.0.1:1" });
  const out: any = await handleWitness({ client }, { record_id: "rec42" });
  assert.equal(out.mode, "build");
  // "witness:rec42" hex
  const want = Buffer.from("witness:rec42", "utf8").toString("hex");
  assert.equal(out.to_sign_hex, want);
});

test("elara_witness in submit mode posts to /witness", async () => {
  const stub = await startStub([
    { method: "POST", path: "/witness", body: { ok: true } },
  ]);
  try {
    const client = new NodeClient({ baseUrl: stub.url });
    const out: any = await handleWitness(
      { client },
      { record_id: "rec1", signature: "ff", public_key: "aa" },
    );
    assert.equal(out.ok, true);
    assert.match(stub.hits[0]!.body, /"signature":"ff"/);
  } finally {
    await stub.close();
  }
});

test("elara_sign(transfer) returns a stable canonical hex preimage", async () => {
  const client = new NodeClient({ baseUrl: "http://127.0.0.1:1" });
  const a: any = await handleSign(
    { client },
    { intent: "transfer", from: "aa", to: "bb", amount: 1_000_000 },
  );
  const b: any = await handleSign(
    { client },
    { intent: "transfer", to: "bb", from: "aa", amount: 1_000_000 },
  );
  assert.equal(a.to_sign_hex, b.to_sign_hex, "key order must not change preimage");
  assert.equal(a.intent, "transfer");
  // Round-trip check: preimage decodes to JSON we can parse.
  const parsed = JSON.parse(Buffer.from(a.to_sign_hex, "hex").toString("utf8"));
  assert.equal(parsed.intent, "transfer");
  assert.equal(parsed.from, "aa");
  assert.equal(parsed.to, "bb");
  assert.equal(parsed.amount, 1_000_000);
});

test("elara_sign rejects missing required fields per intent", async () => {
  const client = new NodeClient({ baseUrl: "http://127.0.0.1:1" });
  await assert.rejects(
    () => handleSign({ client }, { intent: "transfer", from: "aa", amount: 1 } as any),
    /to is required/,
  );
  await assert.rejects(
    () => handleSign({ client }, { intent: "unstake", from: "aa" } as any),
    /record_id is required/,
  );
});
