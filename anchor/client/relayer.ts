/**
 * Minimal relayer. It signs and pays for spends so the user's public wallet
 * never touches them, and is paid the fee committed inside the proof.
 * Anyone can run one; it holds no user funds and cannot alter a spend
 * (recipient, amount and fee are bound by the proof's ext_data_hash).
 */
import http from "http";
import BN from "bn.js";
import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import { Idl, Program } from "@coral-xyz/anchor";
import { RelayRequest, rebuildRelayedTransact, sendV0 } from "./pool";

export interface RelayerOptions {
  connection: Connection;
  program: Program<Idl>;
  keypair: Keypair;
  alt: PublicKey;
  minFee: BN;
  port: number;
  host?: string;
}

export function startRelayer(o: RelayerOptions): Promise<http.Server> {
  const server = http.createServer(async (req, res) => {
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    try {
      if (req.method === "GET" && req.url === "/info") {
        return reply(200, { relayer: o.keypair.publicKey.toBase58(), minFee: o.minFee.toString() });
      }
      if (req.method === "POST" && req.url === "/relay") {
        let raw = "";
        for await (const chunk of req) {
          raw += chunk;
          if (raw.length > 16_384) return reply(413, { error: "request too large" });
        }
        const body = JSON.parse(raw) as RelayRequest;
        const { instructions, fee, extAmount } = await rebuildRelayedTransact(o.program, body, o.keypair.publicKey, o.minFee);
        const signature = await sendV0(o.connection, instructions, o.keypair, o.alt);
        console.log(`[relayer] ${body.recipient === o.keypair.publicKey.toBase58() ? "transfer" : "withdrawal"} relayed, fee ${fee.toString()} lamports: ${signature}`);
        return reply(200, { signature });
      }
      reply(404, { error: "not found" });
    } catch (e: any) {
      const logs = e?.logs ? `\n${e.logs.join("\n")}` : "";
      console.error(`[relayer] rejected: ${e?.message ?? e}${logs}`);
      reply(400, { error: String(e?.message ?? e) });
    }
  });
  return new Promise((resolve) => server.listen(o.port, o.host ?? "127.0.0.1", () => resolve(server)));
}

/** Client side helpers. */
export async function relayerInfo(url: string): Promise<{ relayer: PublicKey; minFee: BN }> {
  const r = await fetch(`${url}/info`);
  if (!r.ok) throw new Error(`relayer /info failed: ${r.status}`);
  const j: any = await r.json();
  return { relayer: new PublicKey(j.relayer), minFee: new BN(j.minFee) };
}

export async function submitToRelayer(url: string, req: RelayRequest): Promise<string> {
  const r = await fetch(`${url}/relay`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(req),
  });
  const j: any = await r.json();
  if (!r.ok) throw new Error(`relayer refused: ${j.error}`);
  return j.signature;
}
