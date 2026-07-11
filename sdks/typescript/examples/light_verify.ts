// Light-client verification flow:
//   1. Fetch the latest signed epoch seal from the node.
//   2. Fetch a fresh account proof.
//   3. Confirm the proof's account_smt_root matches the seal's signed root.
//
// In production you'd verify the seal's Dilithium3 signature against a
// trusted anchor public key. Here we trust the node and only check that
// the proof binds to a sealed root — enough for the "did this account
// state make it into a finalized epoch?" question. Pair this with the
// `pq_verify_account` primitive in browser-node for full
// cryptographic verification.

import { Agent } from "../src/index.js";

const nodeUrl = process.env.ELARA_NODE_URL ?? "http://127.0.0.1:9473";
const identity = process.env.ELARA_IDENTITY;
if (!identity) {
  console.error("set ELARA_IDENTITY=<64-hex-char identity>");
  process.exit(2);
}

const agent = await Agent.create({ nodeUrl, identity });
const proof = await agent.prove();

if (!proof.exists) {
  console.log(`account ${identity.slice(0, 8)}… is not in the ledger`);
  process.exit(0);
}

const sealed = proof.latest_sealed_account;
if (!sealed) {
  console.log("no sealed binding yet — wait for the next epoch seal.");
  process.exit(0);
}

console.log(`account-SMT root in proof : ${proof.root}`);
console.log(`account-SMT root in seal  : ${sealed.account_smt_root}`);
console.log(`epoch ${sealed.epoch_number} zone ${sealed.zone}`);
console.log(`bound_to_seal             : ${proof.bound_to_seal}`);
if (!proof.bound_to_seal) {
  console.log(
    "note: proof reflects post-seal ledger state — for finality, wait for " +
      "the next seal then re-run prove().",
  );
}
