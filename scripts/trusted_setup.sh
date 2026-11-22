#!/usr/bin/env bash
# Independent Groth16 setup for the transaction circuit.
#
# Phase 1: the public PSE Perpetual Powers of Tau (2^18 slice, 80 contributions).
# Phase 2: a fresh contribution with entropy from /dev/urandom that is never
#          written to disk, followed by a public random beacon (a Solana mainnet
#          blockhash fetched after the contribution).
#
# The resulting key does NOT depend on Privacy Cash's ceremony. It is sound as
# long as this machine's contribution entropy was not leaked.
#
# Usage: bash scripts/trusted_setup.sh <repo-root> <work-dir>
set -euo pipefail
REPO="${1:?repo root}"; WORK="${2:?work dir}"
export NODE_OPTIONS="--max-old-space-size=8192"
SNARK="node $REPO/scripts/node_modules/snarkjs/build/cli.cjs"
PTAU="$WORK/ppot_0080_18.ptau"
mkdir -p "$WORK" && cd "$WORK"

echo "== compile circuit from source (circom $(circom --version))"
circom "$REPO/circuits/transaction2.circom" --r1cs --wasm --sym -o "$WORK"
$SNARK r1cs info transaction2.r1cs

if [ ! -s "$PTAU" ]; then
  echo "== download PSE perpetual powers of tau (ppot_0080, 2^18)"
  curl -fL -o "$PTAU.part" https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau
  mv "$PTAU.part" "$PTAU"
fi
b2sum "$PTAU" | tee ptau.b2sum

echo "== phase 2"
$SNARK groth16 setup transaction2.r1cs "$PTAU" t0.zkey
$SNARK zkey contribute t0.zkey t1.zkey --name="shielded-pool independent contribution" \
  -e="$(head -c 64 /dev/urandom | base64 -w0)"

BH=$(curl -s -X POST -H 'Content-Type: application/json' https://api.mainnet-beta.solana.com \
  -d '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}' \
  | grep -o '"blockhash":"[^"]*"' | cut -d'"' -f4)
SLOT=$(curl -s -X POST -H 'Content-Type: application/json' https://api.mainnet-beta.solana.com \
  -d '{"jsonrpc":"2.0","id":1,"method":"getSlot","params":[{"commitment":"finalized"}]}' | grep -o '"result":[0-9]*' | cut -d: -f2)
BEACON=$(printf '%s' "$BH" | sha256sum | cut -d' ' -f1)
echo "beacon: sha256(mainnet blockhash $BH, slot ~$SLOT) = $BEACON" | tee beacon.txt
$SNARK zkey beacon t1.zkey transaction2.zkey "$BEACON" 10 -n="Final beacon: Solana mainnet blockhash $BH"

echo "== verify final key against r1cs + ptau"
$SNARK zkey verify transaction2.r1cs "$PTAU" transaction2.zkey | tee zkey_verify.log
$SNARK zkey export verificationkey transaction2.zkey verifyingkey2.json
shred -u t0.zkey t1.zkey
echo SETUP_DONE
