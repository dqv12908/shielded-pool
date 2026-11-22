/**
 * Regenerates the Groth16 test vectors in programs/zkcash/tests/unit/{groth16,utils}_test.rs
 * for the current proving key (a deposit with two dummy inputs).
 *
 *   npx ts-node -P client/tsconfig.json client/gen_test_vector.ts
 */
import * as fs from "fs";
import * as path from "path";
import BN from "bn.js";
import { Keypair as SolKeypair } from "@solana/web3.js";
import { groth16 } from "snarkjs";
import { MerkleTree } from "../tests/lib/merkle_tree";
import { prove, parseProofToBytesArray, parseToBytesArray } from "../tests/lib/prover";
import { getExtDataHash } from "../tests/lib/utils";
import { Utxo } from "../tests/lib/utxo";
import { Keypair as ZkKeypair } from "../tests/lib/keypair";
import { FIELD_SIZE, KEY_BASE_PATH, SOL_MINT, TREE_HEIGHT, getLightWasm } from "./pool";

async function main() {
  const lightWasm = await getLightWasm();
  const tree = new MerkleTree(TREE_HEIGHT, lightWasm);
  const owner = ZkKeypair.generateNew(lightWasm);
  const inputs = [0, 1].map(() => new Utxo({ lightWasm, keypair: ZkKeypair.generateNew(lightWasm), blinding: new BN(7) }));
  const outputs = [new Utxo({ lightWasm, amount: 1_000_000, keypair: owner, blinding: new BN(11) }), new Utxo({ lightWasm, keypair: owner, blinding: new BN(13) })];
  const who = SolKeypair.generate().publicKey;
  const extData = {
    recipient: who,
    extAmount: new BN(1_000_000),
    encryptedOutput1: Buffer.from("out1"),
    encryptedOutput2: Buffer.from("out2"),
    fee: new BN(0),
    feeRecipient: who,
    mintAddress: SOL_MINT,
  };
  const input = {
    root: tree.root(),
    publicAmount: new BN(1_000_000).add(FIELD_SIZE).mod(FIELD_SIZE).toString(),
    extDataHash: getExtDataHash(extData),
    mintAddress: SOL_MINT.toBase58(),
    inputNullifier: await Promise.all(inputs.map((u) => u.getNullifier())),
    inAmount: ["0", "0"],
    inPrivateKey: inputs.map((u) => u.keypair.privkey.toString()),
    inBlinding: inputs.map((u) => u.blinding.toString()),
    inPathIndices: [0, 0],
    inPathElements: [0, 1].map(() => new Array(TREE_HEIGHT).fill("0")),
    outputCommitment: await Promise.all(outputs.map((u) => u.getCommitment())),
    outAmount: outputs.map((u) => u.amount.toString()),
    outBlinding: outputs.map((u) => u.blinding.toString()),
    outPubkey: outputs.map((u) => u.keypair.pubkey.toString()),
  };
  const { proof, publicSignals } = await prove(input, KEY_BASE_PATH);
  const vk = JSON.parse(fs.readFileSync(path.join(path.dirname(KEY_BASE_PATH), "verifyingkey2.json"), "utf8"));
  if (!(await (groth16 as any).verify(vk, publicSignals, proof))) throw new Error("snarkjs rejected the proof");

  const p = parseProofToBytesArray(proof as any);
  const pub = parseToBytesArray(publicSignals);
  const arr = (a: number[]) => `[${a.join(", ")}]`;
  for (const name of ["groth16_test.rs", "utils_test.rs"]) {
  const file = path.resolve(__dirname, "../programs/zkcash/tests/unit", name);
  let src = fs.readFileSync(file, "utf8");
  src = src.replace(/pub const PROOF_A: \[u8; 64\] = \[[^\]]*\];/, `pub const PROOF_A: [u8; 64] = ${arr(p.proofA)};`);
  src = src.replace(/pub const PROOF_B: \[u8; 128\] = \[[^\]]*\];/, `pub const PROOF_B: [u8; 128] = ${arr(p.proofB.flat())};`);
  src = src.replace(/pub const PROOF_C: \[u8; 64\] = \[[^\]]*\];/, `pub const PROOF_C: [u8; 64] = ${arr(p.proofC)};`);
  src = src.replace(
    /pub const PUBLIC_INPUTS: \[\[u8; 32\]; 7\] = \[[\s\S]*?\n\];/,
    `pub const PUBLIC_INPUTS: [[u8; 32]; 7] = [\n${pub.map((x) => `    ${arr(x)},`).join("\n")}\n];`,
  );
  fs.writeFileSync(file, src);
  console.log("updated test vector in", file);
  }
  process.exit(0); // snarkjs keeps worker threads alive
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
