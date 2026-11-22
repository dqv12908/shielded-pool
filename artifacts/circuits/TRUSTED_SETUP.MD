# Trusted setup (fork)

These keys were produced by `scripts/trusted_setup.sh` and do **not** depend on
Privacy Cash's original ceremony.

* Circuit: `circuits/transaction2.circom` compiled with circom 2.2.2. The
  `transaction2.r1cs` is byte-identical to upstream's audited artifact
  (sha256 `9f5361fc817ec638728b16246b455c33485636e78d2c1d799061f1b2e69f28a1`).
* Phase 1: PSE Perpetual Powers of Tau `ppot_0080_18.ptau`
  (https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/ppot_0080_18.ptau),
  blake2b in `setup/ptau.b2sum`.
* Phase 2, contribution #1: fresh entropy from `/dev/urandom`, never stored.
* Phase 2, final beacon: sha256 of a Solana mainnet blockhash fetched after
  contribution #1 (`setup/beacon.txt`), 2^10 iterations.
* `setup/zkey_verify.log`: full `snarkjs zkey verify` output (`ZKey Ok!`) with
  contribution hashes. `setup/artifacts.sha256`: hashes of the shipped files.

Re-verify:

```
export NODE_OPTIONS="--max-old-space-size=8192"
npx snarkjs zkey verify transaction2.r1cs ppot_0080_18.ptau transaction2.zkey
```

Phase 2 has one contributor so far. Add independent contributions
(`snarkjs zkey contribute`) before anyone else relies on a deployment, then
regenerate the on-chain key with `scripts/vk_to_rust.js`.
