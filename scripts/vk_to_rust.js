#!/usr/bin/env node
// Converts a snarkjs Groth16 verification key (JSON) into the Rust
// `VERIFYING_KEY` constant used by anchor/programs/zkcash/src/utils.rs.
//
// Usage:
//   node scripts/vk_to_rust.js <vk.json>            # print the Rust block
//   node scripts/vk_to_rust.js <vk.json> <utils.rs> # replace the block in place
//
// Byte layout (groth16-solana convention): G1 = x||y, G2 = x.c1||x.c0||y.c1||y.c0,
// every coordinate 32 bytes big-endian.
const fs = require("fs");

const be32 = (dec) => {
  const hex = BigInt(dec).toString(16).padStart(64, "0");
  return Array.from(Buffer.from(hex, "hex"));
};
const g1 = (p) => [...be32(p[0]), ...be32(p[1])];
const g2 = (p) => [...be32(p[0][1]), ...be32(p[0][0]), ...be32(p[1][1]), ...be32(p[1][0])];

const rows = (bytes, indent) => {
  const out = [];
  for (let i = 0; i < bytes.length; i += 32) out.push(indent + bytes.slice(i, i + 32).join(",") + ",");
  return out.join("\n");
};

function toRust(vk) {
  if (vk.protocol !== "groth16" || vk.curve !== "bn128") throw new Error("expected groth16/bn128 key");
  const ic = vk.IC.map((p) => `\t\t[\n${rows(g1(p), "\t\t\t")}\n\t\t],`).join("\n");
  return [
    "pub const VERIFYING_KEY: Groth16Verifyingkey =  Groth16Verifyingkey {",
    `\tnr_pubinputs: ${vk.nPublic},`,
    "",
    `\tvk_alpha_g1: [\n${rows(g1(vk.vk_alpha_1), "\t\t")}\n\t],`,
    "",
    `\tvk_beta_g2: [\n${rows(g2(vk.vk_beta_2), "\t\t")}\n\t],`,
    "",
    `\tvk_gamme_g2: [\n${rows(g2(vk.vk_gamma_2), "\t\t")}\n\t],`,
    "",
    `\tvk_delta_g2: [\n${rows(g2(vk.vk_delta_2), "\t\t")}\n\t],`,
    "",
    `\tvk_ic: &[\n${ic}\n\t]`,
    "};",
  ].join("\n");
}

const [vkPath, rsPath] = process.argv.slice(2);
if (!vkPath) {
  console.error("usage: vk_to_rust.js <vk.json> [utils.rs]");
  process.exit(1);
}
const block = toRust(JSON.parse(fs.readFileSync(vkPath, "utf8")));
if (!rsPath) {
  process.stdout.write(block + "\n");
} else {
  const src = fs.readFileSync(rsPath, "utf8");
  const re = /pub const VERIFYING_KEY: Groth16Verifyingkey =\s+Groth16Verifyingkey \{[\s\S]*?\n\};/;
  if (!re.test(src)) throw new Error("VERIFYING_KEY block not found in " + rsPath);
  fs.writeFileSync(rsPath, src.replace(re, block));
  console.log("updated VERIFYING_KEY in " + rsPath);
}
