#!/usr/bin/env node
// Smoke tests for the Elara Agent Register GitHub Action.
//
//   node test/smoke.test.js
//
// Boots an in-process http.Server stub, sets the INPUT_* env vars the
// way GitHub Actions does, runs dist/index.js as a child process, and
// asserts on the captured stdout + GITHUB_OUTPUT file.
'use strict';

const assert = require('assert');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ID = 'a'.repeat(64);
const ACTION = path.join(__dirname, '..', 'dist', 'index.js');

function startStub(routes) {
  const server = http.createServer((req, res) => {
    for (const [prefix, payload] of Object.entries(routes)) {
      if (req.url.startsWith(prefix)) {
        res.statusCode = payload.status;
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(payload.body));
        return;
      }
    }
    res.statusCode = 404;
    res.end('not found');
  });
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, url: `http://127.0.0.1:${port}` });
    });
  });
}

// Async spawn — the parent event loop must stay live so the stub HTTP
// server can accept the child's requests.
function runAction(env) {
  return new Promise((resolve, reject) => {
    const outFile = path.join(os.tmpdir(), `gh-out-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.txt`);
    fs.writeFileSync(outFile, '');
    const child = spawn(process.execPath, [ACTION], {
      env: { ...process.env, GITHUB_OUTPUT: outFile, ...env },
    });
    const stdoutChunks = [];
    const stderrChunks = [];
    child.stdout.on('data', (c) => stdoutChunks.push(c));
    child.stderr.on('data', (c) => stderrChunks.push(c));
    child.on('error', reject);
    child.on('close', (code) => {
      const outputs = {};
      for (const line of fs.readFileSync(outFile, 'utf8').split('\n')) {
        const eq = line.indexOf('=');
        if (eq > 0) outputs[line.slice(0, eq)] = line.slice(eq + 1);
      }
      fs.unlinkSync(outFile);
      resolve({
        status: code,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        outputs,
      });
    });
  });
}

async function test(name, fn) {
  process.stdout.write(`  • ${name} ... `);
  try {
    await fn();
    process.stdout.write('ok\n');
  } catch (e) {
    process.stdout.write('FAIL\n');
    console.error(e);
    process.exitCode = 1;
  }
}

(async () => {
  console.log('Elara Agent Register — smoke tests');

  // GitHub Actions exports inputs with dashes converted to underscores:
  //   `node-url` → `INPUT_NODE_URL`, `fail-if-missing` → `INPUT_FAIL_IF_MISSING`.
  await test('rejects malformed identity before any I/O', async () => {
    const r = await runAction({
      INPUT_NODE_URL: 'http://127.0.0.1:1',
      INPUT_IDENTITY: 'not-hex',
    });
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /64 hex chars/);
  });

  await test('fails fast on dead node', async () => {
    const r = await runAction({
      INPUT_NODE_URL: 'http://127.0.0.1:1',
      INPUT_IDENTITY: ID,
    });
    assert.strictEqual(r.status, 1);
    assert.match(r.stdout, /liveness probe failed/i);
  });

  await test('emits outputs for an existing account', async () => {
    // Balance + proof both come from the public /proof/account endpoint.
    const { server, url } = await startStub({
      '/status': { status: 200, body: { ok: true } },
      [`/proof/account/${ID}`]: {
        status: 200,
        body: {
          identity: ID,
          exists: true,
          root: '0'.repeat(64),
          bound_to_seal: true,
          account_state: {
            available: 7_500_000,
            staked: 1_500_000,
            total_received: 9_000_000,
            total_sent: 0,
            tx_count: 12,
            last_active: 1_700_000_000,
          },
        },
      },
    });
    try {
      const r = await runAction({
        INPUT_NODE_URL: url,
        INPUT_IDENTITY: ID,
      });
      assert.strictEqual(r.status, 0, `expected exit 0, got ${r.status}: ${r.stderr}`);
      assert.strictEqual(r.outputs.available, '7500000');
      assert.strictEqual(r.outputs.staked, '1500000');
      assert.strictEqual(r.outputs.total, '9000000');
      assert.strictEqual(r.outputs.exists, 'true');
      assert.strictEqual(r.outputs['proof-root'], '0'.repeat(64));
      assert.strictEqual(r.outputs['bound-to-seal'], 'true');
    } finally {
      server.close();
    }
  });

  await test('fails when identity has no account (default)', async () => {
    // Unknown identity → /proof/account returns 200 with exists:false (not 404).
    const { server, url } = await startStub({
      '/status': { status: 200, body: {} },
      [`/proof/account/${ID}`]: {
        status: 200,
        body: { identity: ID, exists: false, root: '0'.repeat(64) },
      },
    });
    try {
      const r = await runAction({
        INPUT_NODE_URL: url,
        INPUT_IDENTITY: ID,
      });
      assert.strictEqual(r.status, 1);
      assert.match(r.stdout, /no account on this node/);
    } finally {
      server.close();
    }
  });

  await test('does not fail on missing account when fail-if-missing=false', async () => {
    const { server, url } = await startStub({
      '/status': { status: 200, body: {} },
      [`/proof/account/${ID}`]: {
        status: 200,
        body: { identity: ID, exists: false, root: '0'.repeat(64) },
      },
    });
    try {
      const r = await runAction({
        INPUT_NODE_URL: url,
        INPUT_IDENTITY: ID,
        INPUT_FAIL_IF_MISSING: 'false',
      });
      assert.strictEqual(r.status, 0, `expected exit 0, got ${r.status}: ${r.stderr}`);
      assert.strictEqual(r.outputs.exists, 'false');
      assert.strictEqual(r.outputs['bound-to-seal'], 'false');
    } finally {
      server.close();
    }
  });

  await test('strips trailing slash from node-url', async () => {
    const { server, url } = await startStub({
      '/status': { status: 200, body: {} },
      [`/proof/account/${ID}`]: {
        status: 200,
        body: {
          identity: ID,
          exists: true,
          root: '1'.repeat(64),
          bound_to_seal: false,
          account_state: { available: 1, staked: 0 },
        },
      },
    });
    try {
      const r = await runAction({
        INPUT_NODE_URL: url + '////',
        INPUT_IDENTITY: ID,
      });
      assert.strictEqual(r.status, 0, `expected exit 0, got ${r.status}: ${r.stderr}`);
      assert.strictEqual(r.outputs['proof-root'], '1'.repeat(64));
    } finally {
      server.close();
    }
  });

  await test('lower-cases identity input', async () => {
    const upper = 'A'.repeat(64);
    const { server, url } = await startStub({
      '/status': { status: 200, body: {} },
      [`/proof/account/${'a'.repeat(64)}`]: {
        status: 200,
        body: {
          identity: 'a'.repeat(64),
          exists: true,
          root: '2'.repeat(64),
          account_state: { available: 1, staked: 0 },
        },
      },
    });
    try {
      const r = await runAction({
        INPUT_NODE_URL: url,
        INPUT_IDENTITY: upper,
      });
      assert.strictEqual(r.status, 0, `expected exit 0, got ${r.status}: ${r.stderr}`);
      assert.strictEqual(r.outputs['proof-root'], '2'.repeat(64));
    } finally {
      server.close();
    }
  });

  if (process.exitCode) {
    console.log('\nFAIL');
  } else {
    console.log('\nOK — 7 tests passed');
  }
})();
