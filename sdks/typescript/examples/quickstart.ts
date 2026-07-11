// Three-line @elara/sdk quickstart. Run against a node you operate (no public testnet endpoints yet):
//
//   ELARA_NODE_URL=http://127.0.0.1:9473 \
//   ELARA_IDENTITY=<your-64-hex-identity> \
//   npx tsx examples/quickstart.ts

import { Agent } from "../src/index.js";

const nodeUrl = process.env.ELARA_NODE_URL ?? "http://127.0.0.1:9473";
const identity = process.env.ELARA_IDENTITY;
if (!identity) {
  console.error("set ELARA_IDENTITY=<64-hex-char identity>");
  process.exit(2);
}

const agent = await Agent.create({ nodeUrl, identity });
const balance = await agent.balance();
const proof = await agent.prove();

console.log(`identity ${identity.slice(0, 8)}…`);
if (!balance.exists) {
  console.log("  (no account on this node yet — stake or fund it first)");
} else {
  // 1 beat = 1_000_000_000 (10^9) base units — see node accounting/types.rs BASE_UNITS_PER_BEAT.
  console.log(`  available : ${((balance.available ?? 0) / 1_000_000_000).toFixed(9)} beats`);
  console.log(`  staked    : ${((balance.staked ?? 0) / 1_000_000_000).toFixed(9)} beats`);
  console.log(`  tx_count  : ${balance.tx_count ?? 0}`);
  // The balance is self-describing: bound_to_seal means it's verified against
  // the latest signed epoch seal (every Elara balance comes with a proof).
  console.log(
    `  verified  : ${balance.bound_to_seal ? "yes (bound to latest signed seal)" : "no (post-seal state — retry next epoch)"}`,
  );
}
console.log(
  `  full proof bound to seal: ${proof.bound_to_seal ? "yes" : "no (post-seal state)"}`,
);
