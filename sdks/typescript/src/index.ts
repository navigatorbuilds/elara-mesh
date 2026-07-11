// @elara/sdk — TypeScript client for the Elara mesh.
//
// Quickstart:
//
//   import { Agent } from "@elara/sdk";
//
//   const agent = await Agent.create({
//     nodeUrl: "http://127.0.0.1:9473",
//     identity: "<64-hex-char identity>",
//   });
//
//   const balance = await agent.balance();
//   const proof   = await agent.prove();
//   const result  = await agent.record(signedRecord);

export { Agent, type AgentConfig } from "./agent.js";
export { NodeClient, ElaraHttpError, type NodeClientConfig } from "./client.js";
export type {
  AccountDetail,
  AccountProof,
  AccountState,
  ProofSibling,
  SealedAccountBinding,
  SignedRecord,
  SubmitResult,
} from "./types.js";
