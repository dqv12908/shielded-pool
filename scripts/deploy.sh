#!/usr/bin/env bash
# Deploy the shielded pool, make it immutable, create the pool, run the e2e check.
#
#   bash scripts/deploy.sh <cluster: devnet|mainnet-beta> <deployer-keypair.json> [program-keypair.json]
#
# WARNING: --final makes the program permanently immutable. Nobody (you
# included) can fix bugs, pause it, or reclaim its rent afterwards.
set -euo pipefail
CLUSTER="${1:?cluster}"; DEPLOYER="${2:?deployer keypair}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROGRAM_KP="${3:-$ROOT/keys/program-keypair.json}"
URL=$([ "$CLUSTER" = "mainnet-beta" ] && echo https://api.mainnet-beta.solana.com || echo "https://api.$CLUSTER.solana.com")
PROGRAM_ID=$(solana-keygen pubkey "$PROGRAM_KP")

cd "$ROOT/anchor"
mkdir -p target/deploy && cp "$PROGRAM_KP" target/deploy/zkcash-keypair.json
anchor build
grep -q "$PROGRAM_ID" programs/zkcash/src/lib.rs || { echo "declare_id! does not match $PROGRAM_ID"; exit 1; }
sha256sum target/deploy/zkcash.so

echo "== deploy $PROGRAM_ID to $CLUSTER (deployer $(solana-keygen pubkey "$DEPLOYER"), balance $(solana -u "$URL" balance "$DEPLOYER"))"
solana program deploy -u "$URL" --keypair "$DEPLOYER" --upgrade-authority "$DEPLOYER" \
  --program-id "$PROGRAM_KP" --with-compute-unit-price 10000 target/deploy/zkcash.so

echo "== revoke upgrade authority (irreversible)"
solana program set-upgrade-authority -u "$URL" --keypair "$DEPLOYER" "$PROGRAM_ID" \
  --upgrade-authority "$DEPLOYER" --final
solana program show -u "$URL" --keypair "$DEPLOYER" "$PROGRAM_ID"

echo "== end-to-end check"
npx ts-node -P client/tsconfig.json client/e2e.ts --cluster "$CLUSTER" --rpc "$URL" --funder "$DEPLOYER" --expect-immutable
