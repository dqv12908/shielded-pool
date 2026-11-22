/**
 * shielded-pool CLI
 *
 *   npx ts-node -P client/tsconfig.json client/cli.ts <command> [options]
 *
 * Commands
 *   new-wallet                       create a wallet (shielded seed + public keypair)
 *   address                          show shielded and public addresses
 *   airdrop <sol>                    devnet/localnet faucet to the public address
 *   setup-pool                       create the pool (permissionless, once) + frozen lookup table
 *   deposit <sol> [zkAddress]        public SOL -> shielded note (yours, or someone else's)
 *   balance                          shielded + public balance
 *   send <sol> <zkAddress>           private transfer via a relayer
 *   withdraw <sol> <publicAddress>   shielded -> public SOL via a relayer
 *   relayer                          run a relayer (--keypair file --port 8787 --min-fee 0.003)
 *
 * Options: --cluster devnet|localnet (default devnet), --rpc <url>,
 *          --wallet <name> (default "default"), --relayer <url>, --fee <sol>
 */
import * as fs from "fs";
import * as path from "path";
import BN from "bn.js";
import { Connection, Keypair, LAMPORTS_PER_SOL, PublicKey } from "@solana/web3.js";
import {
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
function opt(name: string, def?: string): string | undefined {
  const i = argv.indexOf(`--${name}`);
  if (i < 0) return def;
  const v = argv[i + 1];
  argv.splice(i, 2);
  return v;
}

const cluster = opt("cluster", "devnet")!;
const rpc = opt("rpc", cluster === "localnet" ? "http://127.0.0.1:8899" : "https://api.devnet.solana.com")!;
const walletName = opt("wallet", "default")!;
const relayerUrl = opt("relayer");
const feeOpt = opt("fee");
const port = Number(opt("port", "8787"));
const relayerKeyFile = opt("keypair");
const minFeeOpt = opt("min-fee", "0.003")!;
const [command, ...args] = argv;

const CLIENT_DIR = __dirname;
const deploymentFile = path.join(CLIENT_DIR, "deployments", `${cluster}.json`);
const walletFile = path.join(CLIENT_DIR, ".wallets", `${walletName}.json`);
const cacheFile = path.join(CLIENT_DIR, ".cache", `${cluster}-leaves.json`);

/** Parse a decimal SOL string into lamports without floating point. */
export function parseSol(s: string): BN {
  if (!/^\d+(\.\d{1,9})?$/.test(s)) throw new Error(`invalid SOL amount: ${s}`);
  const [whole, frac = ""] = s.split(".");
  return new BN(whole).mul(new BN(LAMPORTS_PER_SOL)).add(new BN(frac.padEnd(9, "0")));
}
export const fmtSol = (l: BN) => {
  const s = l.toString().padStart(10, "0");
  return `${s.slice(0, -9)}.${s.slice(-9)}`.replace(/\.?0+$/, "") + " SOL";
};

function loadDeployment(): { programId: string; alt?: string } {
  if (!fs.existsSync(deploymentFile)) throw new Error(`no deployment file ${deploymentFile}; run setup-pool first`);
  return JSON.parse(fs.readFileSync(deploymentFile, "utf8"));
}

async function loadWallet() {
  if (!fs.existsSync(walletFile)) throw new Error(`no wallet '${walletName}'; run new-wallet --wallet ${walletName}`);
  const w = JSON.parse(fs.readFileSync(walletFile, "utf8"));
  return {
    shielded: ShieldedWallet.fromSeed(Buffer.from(w.seed, "hex"), await getLightWasm()),
    payer: Keypair.fromSecretKey(Uint8Array.from(w.publicKeypair)),
  };
}

async function main() {
  const connection = new Connection(rpc, "confirmed");
  const lightWasm = await getLightWasm();

  switch (command) {
    case "new-wallet": {
      if (fs.existsSync(walletFile)) throw new Error(`${walletFile} already exists`);
      const seed = require("crypto").randomBytes(32);
      const payer = Keypair.generate();
      fs.mkdirSync(path.dirname(walletFile), { recursive: true });
      fs.writeFileSync(walletFile, JSON.stringify({ seed: seed.toString("hex"), publicKeypair: Array.from(payer.secretKey) }), {
        mode: 0o600,
      });
      const sw = ShieldedWallet.fromSeed(seed, lightWasm);
      console.log(`wallet '${walletName}' saved to ${walletFile} (back it up: it holds your keys)`);
      console.log(`shielded address: ${sw.address()}`);
      console.log(`public address:   ${payer.publicKey.toBase58()}`);
      return;
    }
    case "address": {
      const w = await loadWallet();
      console.log(`shielded address: ${w.shielded.address()}`);
      console.log(`public address:   ${w.payer.publicKey.toBase58()}`);
      return;
    }
    case "airdrop": {
      const w = await loadWallet();
      const sig = await connection.requestAirdrop(w.payer.publicKey, parseSol(args[0] ?? "1").toNumber());
      await connection.confirmTransaction(sig, "confirmed");
      console.log(`airdropped ${args[0] ?? "1"} SOL: ${sig}`);
      return;
    }
    case "setup-pool": {
      const w = await loadWallet();
      const program = loadProgram(connection, w.payer);
      const init = await initializePool(connection, program, w.payer);
      console.log(init ? `pool initialized: ${init}` : "pool already initialized");
      const existing = fs.existsSync(deploymentFile) ? JSON.parse(fs.readFileSync(deploymentFile, "utf8")) : {};
      let alt = existing.programId === program.programId.toBase58() ? existing.alt : undefined;
      if (!alt) alt = (await createFrozenLookupTable(connection, program.programId, w.payer)).toBase58();
      fs.mkdirSync(path.dirname(deploymentFile), { recursive: true });
      fs.writeFileSync(deploymentFile, JSON.stringify({ cluster, programId: program.programId.toBase58(), alt }, null, 2));
      console.log(`lookup table (frozen): ${alt}\nsaved ${deploymentFile}`);
      return;
    }
    case "deposit": {
      const w = await loadWallet();
      const dep = loadDeployment();
      const client = new PoolClient(connection, loadProgram(connection, w.payer), lightWasm, cacheFile);
      await client.sync();
      const to = args[1] ? parseShieldedAddress(args[1]) : undefined;
      const sig = await client.deposit(w.shielded, w.payer, parseSol(args[0]), new PublicKey(dep.alt!), to);
      console.log(`deposited ${args[0]} SOL into the pool: ${sig}`);
      return;
    }
    case "balance": {
      const w = await loadWallet();
      const client = new PoolClient(connection, loadProgram(connection), lightWasm, cacheFile);
      await client.sync();
      const notes = await client.notes(w.shielded);
      const total = notes.reduce((s, u) => s.add(u.amount), new BN(0));
      console.log(`shielded: ${fmtSol(total)} in ${notes.length} note(s)`);
      console.log(`public:   ${fmtSol(new BN(await connection.getBalance(w.payer.publicKey)))}`);
      return;
    }
    case "send":
    case "withdraw": {
      if (!relayerUrl) throw new Error("--relayer <url> is required (your public wallet must not sign spends)");
      const w = await loadWallet();
      const client = new PoolClient(connection, loadProgram(connection), lightWasm, cacheFile);
      const info = await relayerInfo(relayerUrl);
      const fee = feeOpt ? parseSol(feeOpt) : info.minFee;
      const amount = parseSol(args[0]);
      const target = args[1];
      if (!target) throw new Error(`usage: ${command} <sol> <${command === "send" ? "zkAddress" : "publicAddress"}>`);
      const built =
        command === "send"
          ? await client.buildSpend(w.shielded, { amount, fee, relayer: info.relayer, to: parseShieldedAddress(target) })
          : await client.buildSpend(w.shielded, { amount, fee, relayer: info.relayer, withdrawTo: new PublicKey(target) });
      const recipient = command === "send" ? info.relayer : new PublicKey(target);
      const sig = await submitToRelayer(relayerUrl, toRelayRequest(built, recipient));
      console.log(`${command === "send" ? "sent" : "withdrew"} ${args[0]} SOL (relayer fee ${fmtSol(fee)}): ${sig}`);
      return;
    }
    case "relayer": {
      if (!relayerKeyFile) throw new Error("--keypair <file> is required");
      const dep = loadDeployment();
      const keypair = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(relayerKeyFile, "utf8"))));
      const program = loadProgram(connection, keypair);
      await startRelayer({ connection, program, keypair, alt: new PublicKey(dep.alt!), minFee: parseSol(minFeeOpt), port });
      console.log(`relayer ${keypair.publicKey.toBase58()} listening on http://127.0.0.1:${port} (min fee ${minFeeOpt} SOL)`);
      return "keep-alive";
    }
    default:
      console.log(fs.readFileSync(__filename, "utf8").split("*/")[0]);
  }
}

if (require.main === module) {
  main().then((r) => {
    if (r !== "keep-alive") process.exit(0); // snarkjs keeps worker threads alive
  }).catch((e) => {
    console.error(e?.message ?? e);
    process.exit(1);
  });
}
