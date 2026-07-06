#!/usr/bin/env node
// Pure-stdlib Node 20+ — no `npm install` at action runtime, so the action
// works in every workflow without bundling node_modules.
'use strict';

const http = require('http');
const https = require('https');
const { URL } = require('url');
const fs = require('fs');

const HEX64 = /^[0-9a-f]{64}$/;

function actionInput(name) {
  // GitHub Actions exposes inputs as INPUT_<UPPER_NAME_WITH_DASHES_AS_UNDERSCORES>.
  const key = 'INPUT_' + name.toUpperCase().replace(/-/g, '_');
  const raw = process.env[key];
  return raw === undefined ? '' : raw.trim();
}

function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  const line = `${name}=${String(value)}\n`;
  if (file) {
    fs.appendFileSync(file, line);
  } else {
    // Local-run fallback: print so smoke tests can capture.
    process.stdout.write(`::set-output name=${name}::${value}\n`);
  }
}

function fail(msg) {
  process.stdout.write(`::error::${msg}\n`);
  process.exit(1);
}

function info(msg) {
  process.stdout.write(`${msg}\n`);
}

function getJson(rawUrl, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const u = new URL(rawUrl);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.get(rawUrl, { timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        if (res.statusCode >= 200 && res.statusCode < 300) {
          try {
            resolve(body ? JSON.parse(body) : {});
          } catch (e) {
            reject(new Error(`GET ${u.pathname} → invalid JSON: ${e.message}`));
          }
        } else {
          reject(new Error(`GET ${u.pathname} → HTTP ${res.statusCode}: ${body}`));
        }
      });
    });
    req.on('timeout', () => {
      req.destroy(new Error(`GET ${u.pathname} → timed out after ${timeoutMs}ms`));
    });
    req.on('error', reject);
  });
}

async function main() {
  const nodeUrl = actionInput('node-url').replace(/\/+$/, '');
  const identity = actionInput('identity').toLowerCase();
  const failIfMissing = actionInput('fail-if-missing') !== 'false';

  if (!nodeUrl) fail('`node-url` input is required.');
  if (!HEX64.test(identity)) {
    fail(`\`identity\` must be 64 hex chars (32-byte SHA3-256), got ${identity.length} chars.`);
  }

  info(`Elara Agent Register → ${nodeUrl}`);

  // 1. Liveness probe — fail-fast on a wrong/dead node.
  try {
    await getJson(`${nodeUrl}/status`);
  } catch (e) {
    fail(`Node liveness probe failed: ${e.message}`);
  }

  // 2. Account read + Merkle proof in ONE call. The balance and the proof
  //    both come from the public /proof/account endpoint — the raw /account
  //    route is loopback/data-plane only and 404s off-host. An unknown
  //    identity returns 200 with exists:false (not 404).
  let proof;
  try {
    proof = await getJson(`${nodeUrl}/proof/account/${identity}`);
  } catch (e) {
    fail(`Account lookup failed: ${e.message}`);
  }

  const account = proof.account_state ?? {};
  const exists = proof.exists === true;

  if (!exists && failIfMissing) {
    fail(
      `Identity ${identity.slice(0, 8)}… has no account on this node. ` +
      `Stake or fund it first (or set fail-if-missing: false to allow).`
    );
  }

  const available = account.available ?? 0;
  const staked = account.staked ?? 0;
  setOutput('available', available);
  setOutput('staked', staked);
  setOutput('total', available + staked);
  setOutput('exists', exists ? 'true' : 'false');
  setOutput('proof-root', proof.root ?? '');
  setOutput('bound-to-seal', proof.bound_to_seal ? 'true' : 'false');

  info(`  identity:       ${identity}`);
  info(`  exists:         ${exists}`);
  info(`  available:      ${available} base units`);
  info(`  staked:         ${staked} base units`);
  info(`  proof root:     ${proof.root ?? '(none)'}`);
  info(`  bound-to-seal:  ${proof.bound_to_seal ?? false}`);
}

main().catch((e) => fail(e.message || String(e)));
