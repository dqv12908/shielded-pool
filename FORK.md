# Permissionless shielded pool (fork of Privacy Cash)

A Solana shielded pool that hides **who paid whom and how much** for transfers
inside the pool, with **no admin, no fees to anyone but your relayer, and no
upgrade key** once deployed.

It is a fork of [Privacy Cash](https://github.com/Privacy-Cash/privacy-cash)
(audited by Accretion, HashCloak, Zigtur, Kriko, Sherlock and Veridise). The
circuit and the core `transact` logic are unchanged; this fork only **removes**
powers and replaces the trusted setup.

> **License:** Privacy Cash is under the Business Source License 1.1 until
> 2027-12-27 (then GPL-2.0-or-later). Research, personal and other
> non-commercial use is allowed; offering it as a competing paid or hosted
> service is not. See `LICENSE.md`.

## Live on devnet (immutable)

| | |
| --- | --- |
| Program | `12tHGHwtEci5KSM8agUEXuk3FYnWN4nMidE3oFccj1pJ` |
| Upgrade authority | **none**: finalized right after deploy (slot 524756557) |
| Program binary sha256 | `e05f2a432f497e93002eb01059e7b06ea86d624248547b88fc172d0ae184d5da` |
| Pool lookup table (frozen) | `7ywMUApwyNaAyVEcp1a3iyPA3YKuvsvi7DyWcVi4msxR` |

Check it yourself:
`solana program show -u devnet 12tHGHwtEci5KSM8agUEXuk3FYnWN4nMidE3oFccj1pJ` shows `Authority: none`.

Example spends on devnet. Only the relayer appears as signer, and the
transferred amount is not visible:

* private transfer: `56XkUXVAuSs1SedducXUjkN21PL7iP78qKNt8X4vhRUhpQwAswd9MiKDvixjhWLxUQJeVpF7FK7AwN7voBgnqt8G`
* withdrawal to a fresh address: `RLew6K2my9C98ZzLkHbMvpewXXpees8ZycohWT8gq8VJ4fxxHhT6s96tXAwqseYY8DnQep3E8L9Je9Zusx94P1Q`

## What changed versus upstream

| Upstream power | This fork |
| --- | --- |
| Admin key gates `initialize` and SPL pool creation | Anyone can create a pool once; the creator gets no privileges |
| `update_global_config`: admin sets deposit/withdraw fee rates up to 100% | Removed. No protocol fee. The only fee is the relayer tip the user commits to inside the proof |
| `update_deposit_limit[_for_spl_token]`: admin can cap or block deposits | Removed, no limits |
| Hard-coded SPL token allowlist | Removed: any classic SPL Token mint |
| Upgradeable by a Squads multisig | Deploy script runs `set-upgrade-authority --final`: nobody can change the code |
| Groth16 keys from Privacy Cash's 4-person ceremony | Fresh setup (below); the fork does not trust that ceremony |

The account layouts drop the now-meaningless `authority` / fee / limit fields;
`transact` (SOL) no longer takes the `global_config` account.

## How it hides sender, recipient and amount

```
 public wallet ──deposit──▶  pool program: SOL vault + Merkle tree of note commitments
 (visible)                   + nullifier PDAs (spent notes) + Groth16 verifier
                                         ▲
 shielded wallet ──proof──▶ relayer ─────┘  signs & pays; the user's wallet never appears
                                         └──withdraw──▶ any public address (visible)
```

* A **note** is `Poseidon(amount, owner_pubkey, blinding, mint)`. Only that hash
  goes on-chain.
* Spending proves in zero knowledge: "I own notes in this tree, here are their
  nullifiers, and outputs + public amount balance the inputs". It never says
  which notes.
* Output notes are encrypted to the recipient's **viewing key**
  (X25519 + XSalsa20-Poly1305, 88 bytes each). Wallets find their notes by
  scanning `CommitmentData` events.
* A **relayer** signs and pays for spends. The proof binds the recipient,
  amounts and relayer fee (`ext_data_hash`), so a relayer can refuse but can
  never redirect or skim. Anyone can run one (`cli.ts relayer`).

**What stays public:** deposits (source, amount), withdrawals (destination,
amount), and the relayer's fee. A private transfer shows only "the relayer
received its fee". Privacy grows with the number of users. A pool with five
users gives little cover, so avoid unique amounts and immediate withdrawals.

## Trusted setup

`scripts/trusted_setup.sh` (records in `artifacts/circuits/setup/`):

1. **Circuit**: compiled from `circuits/transaction2.circom` with circom 2.2.2.
   The `.r1cs` is byte-identical to upstream's audited artifact
   (sha256 `9f5361fc…69f28a1`).
2. **Phase 1**: PSE Perpetual Powers of Tau, `ppot_0080_18.ptau`
   (80 public contributions; blake2b in `setup/ptau.b2sum`).
3. **Phase 2**: one fresh contribution with 64 bytes from `/dev/urandom`.
   The entropy was never written to disk, and the intermediate keys were shredded.
   Then a public beacon: sha256 of a Solana mainnet blockhash fetched *after* the
   contribution (`setup/beacon.txt`).
4. `snarkjs zkey verify` against r1cs and ptau: `ZKey Ok!` (`setup/zkey_verify.log`).

Phase 2 currently has one contributor: this build machine. Before anyone
else trusts a deployment, add contributions from independent people
(`snarkjs zkey contribute`) and re-export the verifying key with
`node scripts/vk_to_rust.js artifacts/circuits/verifyingkey2.json anchor/programs/zkcash/src/utils.rs`.

## Using it

Prerequisites (Linux/WSL): Solana CLI **2.1.x** (newer platform-tools break
`light-hasher 4`), Anchor 0.31.1, Node 22, circom 2.2.2.

```bash
cd anchor && npm ci
anchor build                        # program id: 12tHGHwtEci5KSM8agUEXuk3FYnWN4nMidE3oFccj1pJ
cargo test                          # unit tests, incl. Groth16 vector for the new key
TEST_FILES=tests/sol_tests.ts anchor test   # ported upstream SOL suite
TEST_FILES=tests/spl_tests.ts anchor test   # ported upstream SPL suite

# local end-to-end: deposit -> private transfer -> withdrawal + attack checks
solana-test-validator --reset --bpf-program 12tHGHwtEci5KSM8agUEXuk3FYnWN4nMidE3oFccj1pJ target/deploy/zkcash.so
npx ts-node -P client/tsconfig.json client/e2e.ts --cluster localnet --funder ~/.config/solana/id.json

# deploy + make immutable + e2e (devnet or mainnet-beta)
bash ../scripts/deploy.sh devnet <deployer.json>
```

CLI (`anchor/client/cli.ts`, SOL only):

```bash
alias zk="npx ts-node -P client/tsconfig.json client/cli.ts --cluster devnet"
zk new-wallet --wallet alice            # keys in client/.wallets/ (back them up)
zk setup-pool --wallet alice            # once per cluster: pool + frozen lookup table
zk relayer --keypair relayer.json --port 8787 &   # anyone can run one
zk deposit 0.5 --wallet alice
zk send 0.2 zk<bob's address> --wallet alice --relayer http://127.0.0.1:8787
zk balance --wallet bob
zk withdraw 0.1 <fresh public address> --wallet bob --relayer http://127.0.0.1:8787
```

## Known limits

* SPL pools work on-chain (`initialize_tree_account_for_spl_token`,
  `transact_spl`, covered by the ported SPL suite), but the CLI only handles SOL.
  Token-2022 mints are not supported. A mint whose issuer holds a freeze
  authority (e.g. USDC) can still freeze the pool's token account.
* 2-in/2-out circuit: if funds are spread over more than two notes, send to your
  own address first to merge them.
* Private transfers pay the relayer as a small public withdrawal of exactly the
  fee to the relayer (the program only accepts fees alongside a deposit or
  withdrawal). The transferred amount stays hidden.
* The relayer you use learns your IP and the withdrawal destination. It cannot
  link the spend to your deposit.
* The fork's changes are deletions, but the fork itself has not been audited.
  Immutable means bugs can never be patched: deploy with that in mind.
