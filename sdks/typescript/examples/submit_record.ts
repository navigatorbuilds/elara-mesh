// Sketch of the sign-and-submit flow.
//
// @elara/sdk does not hold private keys — see src/agent.ts header for the
// rationale. This example shows how the SDK plugs into a separately-owned
// signer (here stubbed as `signWithWallet`). In practice you'd swap it for
// one of:
//   - hardware signer driver
//   - elara-cli child process
//   - @elara/mcp-server's elara_sign tool surfaced through your MCP client

import { Agent, type SignedRecord } from "../src/index.js";

const nodeUrl = process.env.ELARA_NODE_URL ?? "http://127.0.0.1:9473";
const identity = process.env.ELARA_IDENTITY;
if (!identity) {
  console.error("set ELARA_IDENTITY=<64-hex-char identity>");
  process.exit(2);
}

// Stand-in for a real wallet. Replace with your signer of choice; see
// the comment block above for concrete options.
async function signWithWallet(_canonicalHex: string): Promise<{
  signature: string;
  public_key: string;
}> {
  throw new Error(
    "this example expects a real signer — wire your wallet here.",
  );
}

const agent = await Agent.create({ nodeUrl, identity });

// 1. Build the record body the protocol expects (same shape as the public
//    REST endpoint POST /records). The to-be-signed bytes are the JSON of
//    the record minus the signature/public_key fields.
const body = {
  id: crypto.randomUUID(),
  identity,
  // amount is in base units: 1 beat = 1_000_000_000 (10^9). This sends 1 beat.
  payload: { kind: "transfer", to: "<recipient hex>", amount: 1_000_000_000 },
  timestamp: Math.floor(Date.now() / 1000),
};

// 2. Hand off to the wallet for canonicalization + signing. (See
//    @elara/mcp-server's elara_sign tool for one valid canonicalization.)
const canonicalHex = Buffer.from(JSON.stringify(body), "utf8").toString("hex");
const { signature, public_key } = await signWithWallet(canonicalHex);

// 3. Submit. The node validates the signature and gossips the record.
const signed: SignedRecord = { ...body, signature, public_key };
const result = await agent.record(signed);
console.log("submit result:", result);
