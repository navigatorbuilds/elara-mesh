// Smoke tests for @elara/sdk. Spins up an in-process HTTP stub mirroring
// the public REST shape so we don't need a live node.

import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";

import { Agent, NodeClient, ElaraHttpError } from "../src/index.js";

interface StubRoute {
  method: string;
  pathPrefix: string;
  body: unknown;
  status?: number;
}

function startStub(routes: StubRoute[]): Promise<{
  url: string;
  hits: { method: string; path: string; body: string }[];
  close: () => Promise<void>;
}> {
  const hits: { method: string; path: string; body: string }[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      hits.push({ method: req.method ?? "", path: req.url ?? "", body });
      const route = routes.find(
        (r) =>
          r.method === req.method &&
          req.url &&
          req.url.startsWith(r.pathPrefix),
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
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

const ID = "a".repeat(64);

test("Agent.create probes /status before returning", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: { ledger_supply: 1 } },
  ]);
  try {
    const agent = await Agent.create({ nodeUrl: stub.url, identity: ID });
    assert.equal(agent.identity, ID);
    assert.equal(stub.hits[0]!.path, "/status");
  } finally {
    await stub.close();
  }
});

test("Agent.create surfaces ElaraHttpError when node is down", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: "boom", status: 500 },
  ]);
  try {
    await assert.rejects(
      () => Agent.create({ nodeUrl: stub.url, identity: ID }),
      (e: unknown) => {
        assert.ok(e instanceof ElaraHttpError);
        assert.equal((e as ElaraHttpError).status, 500);
        return true;
      },
    );
  } finally {
    await stub.close();
  }
});

test("agent.balance() projects /proof/account account_state + flags", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: {} },
    {
      method: "GET",
      pathPrefix: `/proof/account/${ID}`,
      body: {
        identity: ID,
        exists: true,
        root: "0".repeat(64),
        state_hash: "1".repeat(64),
        account_state: {
          available: 7_500_000,
          staked: 1_500_000,
          total_received: 9_000_000,
          total_sent: 0,
          tx_count: 12,
          last_active: 1_700_000_000,
        },
        live_state_matches_sealed: true,
        bound_to_seal: true,
      },
    },
  ]);
  try {
    const agent = await Agent.create({ nodeUrl: stub.url, identity: ID });
    const bal = await agent.balance();
    assert.equal(bal.available, 7_500_000);
    assert.equal(bal.staked, 1_500_000);
    assert.equal(bal.exists, true);
    assert.equal(bal.bound_to_seal, true);
    // balance() must hit the public proof endpoint, never the raw /account.
    assert.ok(stub.hits.some((h) => h.path.startsWith(`/proof/account/${ID}`)));
    assert.ok(!stub.hits.some((h) => h.path.startsWith(`/account/${ID}`)));
  } finally {
    await stub.close();
  }
});

test("agent.balance(unknown) reports exists:false without crashing", async () => {
  const OTHER = "b".repeat(64);
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: {} },
    {
      // Unknown identity → /proof/account returns 200 + exists:false, no account_state.
      method: "GET",
      pathPrefix: `/proof/account/${OTHER}`,
      body: { identity: OTHER, exists: false, root: "0".repeat(64) },
    },
  ]);
  try {
    const agent = await Agent.create({ nodeUrl: stub.url, identity: ID });
    const bal = await agent.balance(OTHER);
    assert.equal(bal.identity, OTHER);
    assert.equal(bal.exists, false);
    assert.equal(bal.bound_to_seal, false);
    assert.equal(bal.available, undefined);
  } finally {
    await stub.close();
  }
});

test("agent.prove() returns siblings + bound_to_seal flag", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: {} },
    {
      method: "GET",
      pathPrefix: `/proof/account/${ID}`,
      body: {
        identity: ID,
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
    const agent = await Agent.create({ nodeUrl: stub.url, identity: ID });
    const proof = await agent.prove();
    assert.equal(proof.depth, 1);
    assert.equal(proof.bound_to_seal, true);
    assert.equal(proof.siblings?.[0]?.is_right, true);
  } finally {
    await stub.close();
  }
});

test("agent.record() rejects records missing signature or public_key", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: {} },
  ]);
  try {
    const agent = await Agent.create({ nodeUrl: stub.url, identity: ID });
    await assert.rejects(
      () =>
        agent.record({
          id: "rec1",
          identity: ID,
          signature: "",
          public_key: "pk",
          payload: {},
          timestamp: 0,
        }),
      /signature.*public_key/,
    );
  } finally {
    await stub.close();
  }
});

test("agent.record() POSTs to /records when fully signed", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: {} },
    { method: "POST", pathPrefix: "/records", body: { accepted: true, id: "rec1" } },
  ]);
  try {
    const agent = await Agent.create({ nodeUrl: stub.url, identity: ID });
    const out = await agent.record({
      id: "rec1",
      identity: ID,
      signature: "ff",
      public_key: "aa",
      payload: { kind: "transfer" },
      timestamp: 1700000000,
    });
    assert.equal(out.accepted, true);
    const post = stub.hits.find((h) => h.method === "POST");
    assert.match(post!.body, /"signature":"ff"/);
  } finally {
    await stub.close();
  }
});

test("Agent.create rejects malformed identity", async () => {
  await assert.rejects(
    () => Agent.create({ nodeUrl: "http://127.0.0.1:1", identity: "not-hex" }),
    /must be 64 hex chars/,
  );
});

test("Agent.unchecked skips the liveness probe", () => {
  // Should not throw despite an unreachable URL.
  const agent = Agent.unchecked({ nodeUrl: "http://127.0.0.1:1", identity: ID });
  assert.equal(agent.identity, ID);
  assert.equal(agent.client.url, "http://127.0.0.1:1");
});

test("Agent without default identity errors when method called without arg", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: {} },
  ]);
  try {
    const agent = await Agent.create({ nodeUrl: stub.url });
    await assert.rejects(() => agent.balance(), /identity is required/);
  } finally {
    await stub.close();
  }
});

test("NodeClient is exported for advanced use", () => {
  const c = new NodeClient({ nodeUrl: "http://x" });
  assert.equal(c.url, "http://x");
});

test("3-line integration mirrors the README quickstart", async () => {
  const stub = await startStub([
    { method: "GET", pathPrefix: "/status", body: {} },
    {
      method: "GET",
      pathPrefix: `/proof/account/${ID}`,
      body: {
        identity: ID,
        exists: true,
        root: "0".repeat(64),
        account_state: { available: 1, staked: 0 },
        bound_to_seal: true,
      },
    },
  ]);
  try {
    // Three lines:
    const agent = await Agent.create({ nodeUrl: stub.url, identity: ID });
    const balance = await agent.balance();
    const proof = await agent.prove();

    assert.equal(balance.exists, true);
    assert.equal(proof.exists, true);
  } finally {
    await stub.close();
  }
});
