/**
 * Client library for the permissionless shielded pool (SOL).
 *
 * - Shielded wallet: a 32-byte seed derives the spend key (Poseidon keypair used
 *   inside the circuit) and an X25519 viewing key (to receive encrypted notes).
 * - Notes are encrypted to the recipient's viewing key and published in the
 *   program's CommitmentData events; wallets find their notes by scanning them.
 * - Spends (transfers / withdrawals) are signed and paid by a relayer, so the
 *   user's public wallet never appears in them.
 */
import * as anchor from "@coral-xyz/anchor";
import { BorshCoder, EventParser, Idl, Program } from "@coral-xyz/anchor";
import {
  AddressLookupTableAccount,
  AddressLookupTableProgram,
  ComputeBudgetProgram,
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  TransactionMessage,
  VersionedTransaction,
} from "@solana/web3.js";
import BN from "bn.js";
import nacl from "tweetnacl";
import { createHash, randomBytes } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { LightWasm, WasmFactory } from "@lightprotocol/hasher.rs";
import { MerkleTree } from "../tests/lib/merkle_tree";
import { prove, parseProofToBytesArray, parseToBytesArray } from "../tests/lib/prover";
import { getExtDataHash } from "../tests/lib/utils";
import { Utxo } from "../tests/lib/utxo";
import { Keypair as ZkKeypair } from "../tests/lib/keypair";

export const SOL_MINT = new PublicKey("11111111111111111111111111111112");
export const TREE_HEIGHT = 26;
export const FIELD_SIZE = new BN("21888242871839275222246405745257275088548364400416034343698204186575808495617");
export const NOTE_CIPHERTEXT_LEN = 32 + 40 + nacl.box.overheadLength; // eph pubkey + (amount||blinding) + MAC
const bs58 = anchor.utils.bytes.bs58;

const REPO_ROOT = path.resolve(__dirname, "../..");
export const KEY_BASE_PATH = path.join(REPO_ROOT, "artifacts/circuits/transaction2");
export const IDL_PATH = path.resolve(__dirname, "../target/idl/zkcash.json");

let wasmPromise: Promise<LightWasm> | null = null;
export const getLightWasm = () => (wasmPromise ??= WasmFactory.getInstance());

const sha256 = (...parts: (Buffer | Uint8Array | string)[]) => {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return h.digest();
};
const randomFieldElement = () => new BN(randomBytes(31)); // < 2^248, always inside the field

// ---------------------------------------------------------------------------
// Program handles
// ---------------------------------------------------------------------------

export function loadProgram(connection: Connection, payer?: Keypair): Program<Idl> {
  const idl = JSON.parse(fs.readFileSync(IDL_PATH, "utf8"));
  const wallet = new anchor.Wallet(payer ?? Keypair.generate());
  const provider = new anchor.AnchorProvider(connection, wallet, { commitment: "confirmed" });
  return new Program(idl as Idl, provider);
}

export function poolPdas(programId: PublicKey) {
  const pda = (seed: string) => PublicKey.findProgramAddressSync([Buffer.from(seed)], programId)[0];
  return { tree: pda("merkle_tree"), treeToken: pda("tree_token"), globalConfig: pda("global_config") };
}

export function nullifierPdas(programId: PublicKey, nullifiers: number[][]) {
  const pda = (prefix: string, n: number[]) =>
    PublicKey.findProgramAddressSync([Buffer.from(prefix), Buffer.from(n)], programId)[0];
  return {
    nullifier0: pda("nullifier0", nullifiers[0]),
    nullifier1: pda("nullifier1", nullifiers[1]),
    nullifier2: pda("nullifier0", nullifiers[1]),
    nullifier3: pda("nullifier1", nullifiers[0]),
  };
}

// ---------------------------------------------------------------------------
// Shielded wallet and addresses
// ---------------------------------------------------------------------------

export class ShieldedWallet {
  readonly zk: ZkKeypair;
  readonly viewing: nacl.BoxKeyPair;

  private constructor(readonly seed: Buffer, lightWasm: LightWasm) {
    const spend = sha256("shielded-pool/spend-key", seed);
    this.zk = new ZkKeypair("0x" + spend.toString("hex"), lightWasm);
    this.viewing = nacl.box.keyPair.fromSecretKey(sha256("shielded-pool/viewing-key", seed));
  }

  static fromSeed(seed: Buffer, lightWasm: LightWasm) {
    if (seed.length !== 32) throw new Error("seed must be 32 bytes");
    return new ShieldedWallet(seed, lightWasm);
  }

  static generate(lightWasm: LightWasm) {
    return new ShieldedWallet(randomBytes(32), lightWasm);
  }

  /** Shareable receive address: zk + base58(spend pubkey || viewing pubkey). */
  address(): string {
    return "zk" + bs58.encode(Buffer.concat([this.zk.pubkey.toArrayLike(Buffer, "be", 32), Buffer.from(this.viewing.publicKey)]));
  }
}

export interface ShieldedAddress {
  pubkey: BN;
  viewingKey: Uint8Array;
}

export function parseShieldedAddress(addr: string): ShieldedAddress {
  if (!addr.startsWith("zk")) throw new Error("shielded addresses start with 'zk'");
  const raw = Buffer.from(bs58.decode(addr.slice(2)));
  if (raw.length !== 64) throw new Error("malformed shielded address");
  const pubkey = new BN(raw.subarray(0, 32), "be");
  if (pubkey.gte(FIELD_SIZE)) throw new Error("malformed shielded address");
  return { pubkey, viewingKey: new Uint8Array(raw.subarray(32)) };
}

// ---------------------------------------------------------------------------
// Note encryption (X25519 + XSalsa20-Poly1305, ephemeral sender key)
// ---------------------------------------------------------------------------

export function encryptNote(amount: BN, blinding: BN, viewingKey: Uint8Array): Buffer {
  const eph = nacl.box.keyPair();
  const nonce = sha256(eph.publicKey, viewingKey).subarray(0, nacl.box.nonceLength);
  const plain = Buffer.concat([amount.toArrayLike(Buffer, "le", 8), blinding.toArrayLike(Buffer, "be", 32)]);
  const ct = nacl.box(plain, nonce, viewingKey, eph.secretKey);
  return Buffer.concat([Buffer.from(eph.publicKey), Buffer.from(ct)]);
}

export function decryptNote(data: Buffer, viewing: nacl.BoxKeyPair): { amount: BN; blinding: BN } | null {
  if (data.length !== NOTE_CIPHERTEXT_LEN) return null;
  const ephPub = data.subarray(0, 32);
  const nonce = sha256(ephPub, viewing.publicKey).subarray(0, nacl.box.nonceLength);
  const plain = nacl.box.open(data.subarray(32), nonce, ephPub, viewing.secretKey);
  if (!plain) return null;
  const buf = Buffer.from(plain);
  return { amount: new BN(buf.subarray(0, 8), "le"), blinding: new BN(buf.subarray(8, 40), "be") };
}

/** A UTXO owned by someone we only know the public key of. */
function outputUtxo(lightWasm: LightWasm, amount: BN, ownerPubkey: BN): Utxo {
  const keypair = { pubkey: ownerPubkey } as unknown as ZkKeypair;
  return new Utxo({ lightWasm, amount, keypair, blinding: randomFieldElement() });
}

function dummyInput(lightWasm: LightWasm): Utxo {
  return new Utxo({ lightWasm, amount: 0, keypair: ZkKeypair.generateNew(lightWasm), blinding: randomFieldElement() });
}

// ---------------------------------------------------------------------------
// Chain scanning: rebuild the commitment tree from CommitmentData events
// ---------------------------------------------------------------------------

export interface Leaf {
  index: number;
  commitment: string; // decimal field element
  encryptedOutput: string; // base64
}

interface LeafCache {
  programId: string;
  newestSignature?: string;
  leaves: Leaf[];
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function withRetry<T>(fn: () => Promise<T>, tries = 6): Promise<T> {
  for (let i = 0; ; i++) {
    try {
      return await fn();
    } catch (e: any) {
      if (i >= tries - 1) throw e;
      await sleep(500 * 2 ** i);
    }
  }
}

export class PoolClient {
  readonly pdas: ReturnType<typeof poolPdas>;
  private tree: MerkleTree | null = null;
  private leaves: Leaf[] = [];

  constructor(
    readonly connection: Connection,
    readonly program: Program<Idl>,
    readonly lightWasm: LightWasm,
    readonly cacheFile?: string,
  ) {
    this.pdas = poolPdas(program.programId);
  }

  /** Fetch all CommitmentData events (incrementally, using a local cache). */
  async sync(): Promise<{ leaves: Leaf[]; tree: MerkleTree }> {
    let cache: LeafCache = { programId: this.program.programId.toBase58(), leaves: [] };
    if (this.cacheFile && fs.existsSync(this.cacheFile)) {
      const c = JSON.parse(fs.readFileSync(this.cacheFile, "utf8"));
      if (c.programId === cache.programId) cache = c;
    }

    // Walk signatures of the tree account newest -> oldest until we reach the cache.
    const newSigs: string[] = [];
    let before: string | undefined;
    outer: for (;;) {
      const page = await withRetry(() =>
        this.connection.getSignaturesForAddress(this.pdas.tree, { before, limit: 1000 }, "confirmed"),
      );
      for (const s of page) {
        if (s.signature === cache.newestSignature) break outer;
        if (!s.err) newSigs.push(s.signature);
      }
      if (page.length < 1000) break;
      before = page[page.length - 1].signature;
    }

    const parser = new EventParser(this.program.programId, new BorshCoder(this.program.idl));
    const byIndex = new Map<number, Leaf>(cache.leaves.map((l) => [l.index, l]));
    for (const sig of newSigs.reverse()) {
      const tx = await withRetry(() =>
        this.connection.getTransaction(sig, { commitment: "confirmed", maxSupportedTransactionVersion: 0 }),
      );
      if (!tx?.meta || tx.meta.err) continue;
      for (const ev of parser.parseLogs(tx.meta.logMessages ?? [])) {
        if (ev.name !== "commitmentData") continue;
        const d: any = ev.data;
        byIndex.set(d.index.toNumber(), {
          index: d.index.toNumber(),
          commitment: new BN(Buffer.from(d.commitment)).toString(10),
          encryptedOutput: Buffer.from(d.encryptedOutput).toString("base64"),
        });
      }
    }
    if (newSigs.length) cache.newestSignature = newSigs[newSigs.length - 1];

    const leaves = [...byIndex.values()].sort((a, b) => a.index - b.index);
    leaves.forEach((l, i) => {
      if (l.index !== i) throw new Error(`missing leaf ${i}; RPC history is incomplete`);
    });

    const tree = new MerkleTree(TREE_HEIGHT, this.lightWasm, leaves.map((l) => l.commitment));
    const onchain: any = await (this.program.account as any).merkleTreeAccount.fetch(this.pdas.tree);
    const onchainRoot = new BN(Buffer.from(onchain.root)).toString(10);
    if (tree.root() !== onchainRoot || onchain.nextIndex.toNumber() !== leaves.length) {
      throw new Error("local tree does not match on-chain root yet (RPC lag); retry in a few seconds");
    }

    cache.leaves = leaves;
    if (this.cacheFile) {
      fs.mkdirSync(path.dirname(this.cacheFile), { recursive: true });
      fs.writeFileSync(this.cacheFile, JSON.stringify(cache));
    }
    this.leaves = leaves;
    this.tree = tree;
    return { leaves, tree };
  }

  /** Unspent notes owned by `wallet`. */
  async notes(wallet: ShieldedWallet): Promise<Utxo[]> {
    if (!this.tree) await this.sync();
    const owned: Utxo[] = [];
    for (const leaf of this.leaves) {
      const note = decryptNote(Buffer.from(leaf.encryptedOutput, "base64"), wallet.viewing);
      if (!note || note.amount.isZero()) continue;
      const utxo = new Utxo({
        lightWasm: this.lightWasm,
        amount: note.amount,
        keypair: wallet.zk,
        blinding: note.blinding,
        index: leaf.index,
      });
      if ((await utxo.getCommitment()) !== leaf.commitment) continue; // not ours / malformed
      owned.push(utxo);
    }
    if (!owned.length) return [];

    // A note is spent if its nullifier PDA exists under either prefix.
    const keys: PublicKey[] = [];
    for (const u of owned) {
      const n = Array.from(new BN(await u.getNullifier()).toArrayLike(Buffer, "be", 32));
      const p = nullifierPdas(this.program.programId, [n, n]);
      keys.push(p.nullifier0, p.nullifier1);
    }
    const infos = await this.connection.getMultipleAccountsInfo(keys, "confirmed");
    return owned.filter((_, i) => !infos[2 * i] && !infos[2 * i + 1]);
  }

  async balance(wallet: ShieldedWallet): Promise<BN> {
    return (await this.notes(wallet)).reduce((s, u) => s.add(u.amount), new BN(0));
  }

  // -------------------------------------------------------------------------
  // Proof + instruction building
  // -------------------------------------------------------------------------

  /**
   * Build a `transact` instruction.
   * extAmount > 0: deposit (signer pays it in). extAmount < 0: withdrawal to `recipient`.
   * `fee` is paid from the pool to `feeRecipient` (the relayer tip).
   */
  async buildTransact(args: {
    inputs: Utxo[];
    outputs: { amount: BN; owner: ShieldedAddress }[];
    extAmount: BN;
    fee: BN;
    recipient: PublicKey;
    feeRecipient: PublicKey;
    signer: PublicKey;
  }): Promise<{ instructions: TransactionInstruction[]; nullifiers: number[][] }> {
    if (!this.tree) await this.sync();
    const tree = this.tree!;
    const { lightWasm } = this;
    if (args.inputs.length > 2 || args.outputs.length !== 2) throw new Error("circuit is 2-in / 2-out");

    const inputs = [...args.inputs];
    while (inputs.length < 2) inputs.push(dummyInput(lightWasm));
    const outputs = args.outputs.map((o) => outputUtxo(lightWasm, o.amount, o.owner.pubkey));

    const sumIn = inputs.reduce((s, u) => s.add(u.amount), new BN(0));
    const sumOut = outputs.reduce((s, u) => s.add(u.amount), new BN(0));
    if (!sumIn.add(args.extAmount).sub(args.fee).eq(sumOut)) throw new Error("amounts do not balance");

    const encryptedOutput1 = encryptNote(outputs[0].amount, outputs[0].blinding, args.outputs[0].owner.viewingKey);
    const encryptedOutput2 = encryptNote(outputs[1].amount, outputs[1].blinding, args.outputs[1].owner.viewingKey);

    const extData = {
      recipient: args.recipient,
      extAmount: args.extAmount,
      encryptedOutput1,
      encryptedOutput2,
      fee: args.fee,
      feeRecipient: args.feeRecipient,
      mintAddress: SOL_MINT,
    };

    const pathIndices: number[] = [];
    const pathElements: string[][] = [];
    for (const u of inputs) {
      if (u.amount.gtn(0)) {
        pathIndices.push(u.index);
        pathElements.push(tree.path(u.index).pathElements.map(String));
      } else {
        pathIndices.push(0);
        pathElements.push(new Array(TREE_HEIGHT).fill("0"));
      }
    }

    const circuitInput = {
      root: tree.root(),
      publicAmount: args.extAmount.sub(args.fee).add(FIELD_SIZE).mod(FIELD_SIZE).toString(10),
      extDataHash: getExtDataHash(extData),
      mintAddress: SOL_MINT.toBase58(), // matches getMintAddressField(SOL)
      inputNullifier: await Promise.all(inputs.map((u) => u.getNullifier())),
      inAmount: inputs.map((u) => u.amount.toString(10)),
      inPrivateKey: inputs.map((u) => u.keypair.privkey.toString(10)),
      inBlinding: inputs.map((u) => u.blinding.toString(10)),
      inPathIndices: pathIndices,
      inPathElements: pathElements,
      outputCommitment: await Promise.all(outputs.map((u) => u.getCommitment())),
      outAmount: outputs.map((u) => u.amount.toString(10)),
      outBlinding: outputs.map((u) => u.blinding.toString(10)),
      outPubkey: outputs.map((u) => u.keypair.pubkey.toString(10)),
    };

    const { proof, publicSignals } = await prove(circuitInput, KEY_BASE_PATH);
    const p = parseProofToBytesArray(proof as any);
    const pub = parseToBytesArray(publicSignals);
    const proofArg = {
      proofA: p.proofA,
      proofB: p.proofB.flat(),
      proofC: p.proofC,
      root: pub[0],
      publicAmount: pub[1],
      extDataHash: pub[2],
      inputNullifiers: [pub[3], pub[4]],
      outputCommitments: [pub[5], pub[6]],
    };

    const ix = await (this.program.methods as any)
      .transact(proofArg, { extAmount: args.extAmount, fee: args.fee }, encryptedOutput1, encryptedOutput2)
      .accountsStrict({
        treeAccount: this.pdas.tree,
        ...nullifierPdas(this.program.programId, proofArg.inputNullifiers),
        treeTokenAccount: this.pdas.treeToken,
        recipient: args.recipient,
        feeRecipientAccount: args.feeRecipient,
        signer: args.signer,
        systemProgram: SystemProgram.programId,
      })
      .instruction();

    return {
      instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix],
      nullifiers: proofArg.inputNullifiers,
    };
  }

  // -------------------------------------------------------------------------
  // High-level flows
  // -------------------------------------------------------------------------

  private pickInputs(notes: Utxo[], needed: BN): Utxo[] {
    const sorted = [...notes].sort((a, b) => b.amount.cmp(a.amount));
    const picked = sorted.slice(0, 2);
    const total = picked.reduce((s, u) => s.add(u.amount), new BN(0));
    if (total.lt(needed)) {
      const all = notes.reduce((s, u) => s.add(u.amount), new BN(0));
      throw new Error(
        all.gte(needed)
          ? `funds are split across ${notes.length} notes; merge them first (send to your own address)`
          : `insufficient shielded balance: have ${all.toString()} lamports, need ${needed.toString()}`,
      );
    }
    return picked;
  }

  /** Public SOL -> shielded note for `to` (defaults to the depositor's own wallet). */
  async deposit(wallet: ShieldedWallet, payer: Keypair, lamports: BN, alt: PublicKey, to?: ShieldedAddress) {
    const self = { pubkey: wallet.zk.pubkey, viewingKey: wallet.viewing.publicKey };
    const built = await this.buildTransact({
      inputs: [],
      outputs: [
        { amount: lamports, owner: to ?? self },
        { amount: new BN(0), owner: self },
      ],
      extAmount: lamports,
      fee: new BN(0),
      recipient: payer.publicKey,
      feeRecipient: payer.publicKey,
      signer: payer.publicKey,
    });
    return sendV0(this.connection, built.instructions, payer, alt);
  }

  /** Build a relayed spend: private transfer (to set) or withdrawal (recipient set). */
  async buildSpend(
    wallet: ShieldedWallet,
    params: { amount: BN; fee: BN; relayer: PublicKey; to?: ShieldedAddress; withdrawTo?: PublicKey },
  ) {
    await this.sync();
    const self = { pubkey: wallet.zk.pubkey, viewingKey: wallet.viewing.publicKey };
    const inputs = this.pickInputs(await this.notes(wallet), params.amount.add(params.fee));
    const change = inputs.reduce((s, u) => s.add(u.amount), new BN(0)).sub(params.amount).sub(params.fee);

    if (params.to) {
      // The program only accepts a fee alongside a deposit or withdrawal, so a
      // private transfer pays the relayer as a public "withdrawal" of exactly the
      // fee to the relayer itself. The transferred amount stays hidden.
      return this.buildTransact({
        inputs,
        outputs: [
          { amount: params.amount, owner: params.to },
          { amount: change, owner: self },
        ],
        extAmount: params.fee.neg(),
        fee: new BN(0),
        recipient: params.relayer,
        feeRecipient: params.relayer,
        signer: params.relayer,
      });
    }
    if (!params.withdrawTo) throw new Error("need a shielded recipient or a withdrawal address");
    return this.buildTransact({
      inputs,
      outputs: [
        { amount: change, owner: self },
        { amount: new BN(0), owner: self },
      ],
      extAmount: params.amount.neg(),
      fee: params.fee,
      recipient: params.withdrawTo,
      feeRecipient: params.relayer,
      signer: params.relayer,
    });
  }
}

// ---------------------------------------------------------------------------
// Transactions, lookup table, pool bootstrap
// ---------------------------------------------------------------------------

export async function sendV0(
  connection: Connection,
  instructions: TransactionInstruction[],
  payer: Keypair,
  alt?: PublicKey,
): Promise<string> {
  const tables: AddressLookupTableAccount[] = [];
  if (alt) {
    const t = await connection.getAddressLookupTable(alt);
    if (!t.value) throw new Error(`lookup table ${alt.toBase58()} not found`);
    tables.push(t.value);
  }
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
  const msg = new TransactionMessage({ payerKey: payer.publicKey, recentBlockhash: blockhash, instructions }).compileToV0Message(
    tables,
  );
  const tx = new VersionedTransaction(msg);
  tx.sign([payer]);
  const sig = await connection.sendTransaction(tx, { preflightCommitment: "confirmed" });
  const res = await connection.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight }, "confirmed");
  if (res.value.err) throw new Error(`transaction ${sig} failed: ${JSON.stringify(res.value.err)}`);
  return sig;
}

/** Permissionless one-time pool creation. Returns null if it already exists. */
export async function initializePool(connection: Connection, program: Program<Idl>, payer: Keypair) {
  const pdas = poolPdas(program.programId);
  if (await connection.getAccountInfo(pdas.tree)) return null;
  const ix = await (program.methods as any)
    .initialize()
    .accountsStrict({
      treeAccount: pdas.tree,
      treeTokenAccount: pdas.treeToken,
      globalConfig: pdas.globalConfig,
      payer: payer.publicKey,
      systemProgram: SystemProgram.programId,
    })
    .instruction();
  return sendV0(connection, [ix], payer);
}

/**
 * Create an address lookup table with the pool's static accounts and freeze it,
 * so nobody (including its creator) can change or close it.
 */
export async function createFrozenLookupTable(connection: Connection, programId: PublicKey, payer: Keypair) {
  const pdas = poolPdas(programId);
  // A few slots back: load-balanced RPC nodes may not have seen the newest slot yet.
  const recentSlot = (await connection.getSlot("finalized")) - 20;
  const [create, table] = AddressLookupTableProgram.createLookupTable({
    authority: payer.publicKey,
    payer: payer.publicKey,
    recentSlot,
  });
  const extend = AddressLookupTableProgram.extendLookupTable({
    lookupTable: table,
    authority: payer.publicKey,
    payer: payer.publicKey,
    addresses: [programId, pdas.tree, pdas.treeToken, pdas.globalConfig, SystemProgram.programId, ComputeBudgetProgram.programId],
  });
  const freeze = AddressLookupTableProgram.freezeLookupTable({ lookupTable: table, authority: payer.publicKey });
  await sendV0(connection, [create, extend, freeze], payer);
  // A new table becomes usable one slot after its last extension.
  for (let i = 0; i < 30; i++) {
    const t = await connection.getAddressLookupTable(table);
    const slot = await connection.getSlot("confirmed");
    if (t.value && t.value.state.addresses.length === 6 && slot > Number(t.value.state.lastExtendedSlot)) break;
    await sleep(500);
  }
  return table;
}

// ---------------------------------------------------------------------------
// Relayer wire format: only the encoded `transact` data plus the withdrawal
// recipient travel to the relayer. The relayer re-derives every account itself
// (signer = fee recipient = relayer), so it never signs anything it did not build.
// ---------------------------------------------------------------------------

export interface RelayRequest {
  ixData: string; // base64 of the transact instruction data
  recipient: string; // base58 withdrawal recipient (relayer's own key for transfers)
}

export function toRelayRequest(built: { instructions: TransactionInstruction[] }, recipient: PublicKey): RelayRequest {
  return { ixData: built.instructions[1].data.toString("base64"), recipient: recipient.toBase58() };
}

/** Relayer side: decode, check, and rebuild the instruction list from a request. */
export async function rebuildRelayedTransact(program: Program<Idl>, req: RelayRequest, relayer: PublicKey, minFee: BN) {
  const decoded: any = (program.coder.instruction as anchor.BorshInstructionCoder).decode(Buffer.from(req.ixData, "base64"));
  if (!decoded || decoded.name !== "transact") throw new Error("only `transact` can be relayed");
  const { proof, extDataMinified, encryptedOutput1, encryptedOutput2 } = decoded.data;
  const extAmount = new BN(extDataMinified.extAmount.toString());
  const recipient = new PublicKey(req.recipient);
  if (extAmount.gtn(0)) throw new Error("deposits are signed by the depositor, not relayed");
  // Relayer pay = the fee, plus the "withdrawal" itself when it goes to the relayer
  // (that is how private transfers pay their fee).
  const fee = new BN(extDataMinified.fee.toString()).add(recipient.equals(relayer) ? extAmount.neg() : new BN(0));
  if (fee.lt(minFee)) throw new Error(`fee ${fee.toString()} below relayer minimum ${minFee.toString()}`);
  const pdas = poolPdas(program.programId);
  const ix = await (program.methods as any)
    .transact(proof, extDataMinified, encryptedOutput1, encryptedOutput2)
    .accountsStrict({
      treeAccount: pdas.tree,
      ...nullifierPdas(program.programId, proof.inputNullifiers),
      treeTokenAccount: pdas.treeToken,
      recipient,
      feeRecipientAccount: relayer,
      signer: relayer,
      systemProgram: SystemProgram.programId,
    })
    .instruction();
  return { instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1_000_000 }), ix], fee, extAmount };
}
