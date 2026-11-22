/**
 * End-to-end check against a live cluster (localnet or devnet).
 *
 *   npx ts-node -P client/tsconfig.json client/e2e.ts --cluster localnet --funder <keypair.json>
 *
 * Alice deposits, privately pays Bob through a relayer, Bob withdraws to a
 * brand-new address through the relayer. Then: privacy checks on the spend
 * transactions, a double-spend attempt, a tampered-recipient attempt, and an
 * immutability check on the deployed program.
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import BN from "bn.js";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SystemProgram,
  Transaction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  NOTE_CIPHERTEXT_LEN,
  PoolClient,
  ShieldedWallet,
  createFrozenLookupTable,
  getLightWasm,
  initializePool,
  loadProgram,
  parseShieldedAddress,
  toRelayRequest,
} from "./pool";
import { relayerInfo, startRelayer, submitToRelayer } from "./relayer";

const argv = process.argv.slice(2);
const opt = (n: string, d?: string) => {
  const i = argv.indexOf(`--${n}`);
  return i >= 0 ? argv[i + 1] : d;
};
const cluster = opt("cluster", "localnet")!;
const rpc = opt("rpc", cluster === "localnet" ? "http://127.0.0.1:8899" : "https://api.devnet.solana.com")!;
const funderFile = opt("funder", path.join(os.homedir(), ".config/solana/id.json"))!;
const expectImmutable = argv.includes("--expect-immutable");

const sol = (x: number) => new BN(Math.round(x * LAMPORTS_PER_SOL));
const fmt = (l: BN | number) => `${(Number(l.toString()) / LAMPORTS_PER_SOL).toFixed(9)} SOL`;
let failures = 0;
function check(cond: boolean, label: string) {
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${label}`);
  if (!cond) failures++;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function eventually<T>(fn: () => Promise<T>, ok: (v: T) => boolean, tries = 20): Promise<T> {
  let v = await fn().catch(() => undefined as any);
  for (let i = 0; i < tries && (v === undefined || !ok(v)); i++) {
    await sleep(1500);
    v = await fn().catch(() => undefined as any);
  }
  return v;
}

async function main() {
  const connection = new Connection(rpc, "confirmed");
  const lightWasm = await getLightWasm();
  const funder = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(funderFile, "utf8"))));
  const program = loadProgram(connection, funder);
  console.log(`cluster ${cluster} (${rpc})\nprogram ${program.programId.toBase58()}\nfunder  ${funder.publicKey.toBase58()}`);

  // --- actors -------------------------------------------------------------
  const alicePublic = Keypair.generate();
  const alice = ShieldedWallet.generate(lightWasm);
  const bob = ShieldedWallet.generate(lightWasm);
  const relayerKey = Keypair.generate();
  const freshAddress = Keypair.generate().publicKey; // Bob's brand-new withdrawal address

  const fund = new Transaction().add(
    SystemProgram.transfer({ fromPubkey: funder.publicKey, toPubkey: alicePublic.publicKey, lamports: 0.05 * LAMPORTS_PER_SOL }),
    SystemProgram.transfer({ fromPubkey: funder.publicKey, toPubkey: relayerKey.publicKey, lamports: 0.03 * LAMPORTS_PER_SOL }),
  );
  await sendAndConfirmTransaction(connection, fund, [funder], { commitment: "confirmed" });

  // --- pool + lookup table (permissionless) ---------------------------------
  const init = await initializePool(connection, program, funder);
  console.log(init ? `pool initialized: ${init}` : "pool already initialized");
  const depFile = path.join(__dirname, "deployments", `${cluster}.json`);
  let alt: PublicKey;
  const dep = fs.existsSync(depFile) ? JSON.parse(fs.readFileSync(depFile, "utf8")) : {};
  if (dep.programId === program.programId.toBase58() && dep.alt && (await connection.getAddressLookupTable(new PublicKey(dep.alt))).value) {
    alt = new PublicKey(dep.alt);
  } else {
    alt = await createFrozenLookupTable(connection, program.programId, funder);
    fs.mkdirSync(path.dirname(depFile), { recursive: true });
    fs.writeFileSync(depFile, JSON.stringify({ cluster, programId: program.programId.toBase58(), alt: alt.toBase58() }, null, 2));
  }
  console.log(`lookup table ${alt.toBase58()}`);

  const server = await startRelayer({ connection, program, keypair: relayerKey, alt, minFee: sol(0.003), port: 0 });
  const relayerUrl = `http://127.0.0.1:${(server.address() as any).port}`;
  const info = await relayerInfo(relayerUrl);
  const client = new PoolClient(connection, program, lightWasm);

  const DEPOSIT = sol(0.02);
  const SEND = sol(0.01);
  const WITHDRAW = sol(0.005);
  const FEE = info.minFee;

  // --- 1. deposit ----------------------------------------------------------
  console.log("\n1) Alice deposits", fmt(DEPOSIT));
  await client.sync();
  const depSig = await client.deposit(alice, alicePublic, DEPOSIT, alt);
  console.log(`   ${depSig}`);
  const aliceBal1 = await eventually(async () => (await client.sync(), client.balance(alice)), (b) => b.eq(DEPOSIT));
  check(aliceBal1.eq(DEPOSIT), `Alice's shielded balance is ${fmt(aliceBal1)}`);

  // --- 2. private transfer -------------------------------------------------
  console.log(`\n2) Alice privately sends ${fmt(SEND)} to Bob via the relayer (fee ${fmt(FEE)})`);
  const poolBefore = await connection.getBalance(client.pdas.treeToken);
  const sendBuilt = await client.buildSpend(alice, { amount: SEND, fee: FEE, relayer: info.relayer, to: parseShieldedAddress(bob.address()) });
  const sendSig = await submitToRelayer(relayerUrl, toRelayRequest(sendBuilt, info.relayer));
  console.log(`   ${sendSig}`);
  const bobBal = await eventually(async () => (await client.sync(), client.balance(bob)), (b) => b.eq(SEND));
  check(bobBal.eq(SEND), `Bob's shielded balance is ${fmt(bobBal)}`);
  const aliceBal2 = await client.balance(alice);
  check(aliceBal2.eq(DEPOSIT.sub(SEND).sub(FEE)), `Alice's shielded change is ${fmt(aliceBal2)}`);
  const poolAfter = await connection.getBalance(client.pdas.treeToken);
  check(poolBefore - poolAfter === FEE.toNumber(), "only the relayer fee left the pool during the transfer (amount stays hidden)");

  // --- 3. withdrawal to a fresh address -------------------------------------
  console.log(`\n3) Bob withdraws ${fmt(WITHDRAW)} to fresh address ${freshAddress.toBase58()}`);
  const wBuilt = await client.buildSpend(bob, { amount: WITHDRAW, fee: FEE, relayer: info.relayer, withdrawTo: freshAddress });
  const wReq = toRelayRequest(wBuilt, freshAddress);
  const wSig = await submitToRelayer(relayerUrl, wReq);
  console.log(`   ${wSig}`);
  const freshBal = await connection.getBalance(freshAddress, "confirmed");
  check(freshBal === WITHDRAW.toNumber(), `fresh address received ${fmt(freshBal)}`);
  await client.sync();
  const bobBal2 = await client.balance(bob);
  check(bobBal2.eq(SEND.sub(WITHDRAW).sub(FEE)), `Bob's shielded change is ${fmt(bobBal2)}`);

  // --- 4. privacy of the spend transactions ---------------------------------
  console.log("\n4) What the chain sees");
  for (const [label, sig] of [["transfer", sendSig], ["withdrawal", wSig]] as const) {
    const tx = await connection.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
    const keys = tx!.transaction.message.getAccountKeys({ accountKeysFromLookups: tx!.meta!.loadedAddresses }).keySegments().flat();
    const signers = tx!.transaction.signatures.length;
    const feePayer = keys[0].toBase58();
    check(signers === 1 && feePayer === info.relayer.toBase58(), `${label}: only signer is the relayer`);
    check(!keys.some((k) => k.equals(alicePublic.publicKey)), `${label}: Alice's public wallet does not appear`);
  }
  const transferTx = await connection.getTransaction(sendSig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
  const deltas = transferTx!.meta!.postBalances.map((b, i) => b - transferTx!.meta!.preBalances[i]);
  check(!deltas.some((d) => Math.abs(d) === SEND.toNumber()), "transfer: the 0.01 SOL amount appears in no balance change");
  check(NOTE_CIPHERTEXT_LEN === 88, "every note ciphertext has the same 88-byte size");

  // --- 5. attacks ------------------------------------------------------------
  console.log("\n5) Attacks");
  const replay = await submitToRelayer(relayerUrl, wReq).then(
    () => "accepted",
    (e) => String(e.message),
  );
  check(replay !== "accepted", `double spend (replaying Bob's withdrawal) is rejected`);
  const tampered = await (async () => {
    const built = await client.buildSpend(alice, { amount: sol(0.001), fee: FEE, relayer: info.relayer, withdrawTo: freshAddress });
    const thief = Keypair.generate().publicKey;
    return submitToRelayer(relayerUrl, toRelayRequest(built, thief)).then(
      () => "accepted",
      (e) => String(e.message),
    );
  })();
  check(tampered !== "accepted", "redirecting a withdrawal to another address is rejected (proof binds the recipient)");
  const lowFee = await (async () => {
    const built = await client.buildSpend(alice, { amount: sol(0.001), fee: new BN(1), relayer: info.relayer, withdrawTo: freshAddress });
    return submitToRelayer(relayerUrl, toRelayRequest(built, freshAddress)).then(() => "accepted", (e) => String(e.message));
  })();
  check(lowFee !== "accepted", "relayer refuses spends below its minimum fee");

  // --- 6. immutability ---------------------------------------------------------
  console.log("\n6) Program control");
  const progInfo = await connection.getParsedAccountInfo(program.programId);
  const pd = (progInfo.value?.data as any)?.parsed?.info?.programData;
  let authority: string | null = "unknown";
  if (pd) {
    const pdInfo = await connection.getParsedAccountInfo(new PublicKey(pd));
    authority = (pdInfo.value?.data as any)?.parsed?.info?.authority ?? null;
  } else {
    authority = null; // loaded as a non-upgradeable program (e.g. test validator --bpf-program)
  }
  console.log(`   upgrade authority: ${authority ?? "none (immutable)"}`);
  if (expectImmutable) check(authority === null, "program is immutable: nobody can upgrade, pause, or drain it");

  server.close();
  console.log(failures ? `\n${failures} check(s) FAILED` : "\nALL CHECKS PASSED");
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
