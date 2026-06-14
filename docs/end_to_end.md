# End-to-end: encrypt → prove → verify on-chain

A complete public-key BFV encryption proof, from a ciphertext to an on-chain UltraHonk verification.
The secret-key flow is identical with `--scheme sk` and the `circuit_digest_*` harnesses.

> **UNAUDITED RESEARCH.** The witness generator is a *toy* BFV implementation for exercising the
> circuit, not a production encryptor. See [security.md](security.md).

## Prerequisites

| Tool | Version used | For |
|---|---|---|
| `nargo` | 1.0.0-beta.22 | compile + execute the circuit |
| `bb` | 5.0.0-nightly.20260522 | prove / verify / Solidity verifier |
| Rust + Cargo | stable | the witness generator |
| Foundry (`forge`, `anvil`) | 1.7.1 | on-chain verification |

```bash
cd witness-gen && cargo build --release && cd ..
```

## Step 1 — produce a witness (Rust)

`witness-gen` performs a toy public-key BFV encryption and emits a `Prover.toml` with all twelve
arrays the circuit needs (`pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1`), including the two
Schwartz-Zippel quotient pairs. It self-verifies the exact `Z[X]` identities and the bounds before
writing.

```bash
cd bench/pk_digest_1024
../../witness-gen/target/release/witness-gen \
    --scheme pk --n 1024 --seed 7 \
    --message "noir-rlwe vFHE" \
    --out Prover.toml
```

Flags: `--scheme sk|pk`, `--n <ring degree>`, `--seed`, `--message <string>` (encoded into `m`, else
random), `--tamper name:idx:value` (for negative tests). Signed coefficients are written as BN254
field representatives (`-v ↦ p - v`).

## Step 2 — solve the witness (Noir)

```bash
nargo execute
# [pk_enc_digest_1024] Circuit witness successfully solved
# [pk_enc_digest_1024] Circuit output: 0x0ae8…30e8     <- the returned digest
```

If the witness is malformed (a non-ternary `u`, an over-bound error, a wrong quotient, a tampered
ciphertext), `nargo execute` fails here — the circuit's `assert`s reject it. The `Circuit output` is
`digest = Poseidon2(pack(pk0)‖pack(pk1)‖pack(c0)‖pack(c1))`, the circuit's single public output.

## Step 3 — prove and verify natively (Barretenberg)

```bash
bb write_vk -b target/pk_enc_digest_1024.json -o po
bb prove    -b target/pk_enc_digest_1024.json -w target/pk_enc_digest_1024.gz -k po/vk -o po --verify
# Public inputs saved to "po/public_inputs"   (32 bytes = 1 field = the digest)
# Proof saved to "po/proof"

bb verify -p po/proof -k po/vk -i po/public_inputs
# Proof verified successfully
```

At `n=1024` this is ~0.9 s and ~184 MB on an M2 Air. `public_inputs` is exactly one field element —
the digest. The default `bb prove` produces a **ZK** proof (it hides the witness — message, randomness,
errors); **do not pass `--disable_zk`** (or a `*-no-zk` verifier target) if witness privacy matters. See
[security.md §7](security.md).

## Step 4 — verify on-chain (UltraHonk Solidity verifier)

Generate the EVM-flavored (keccak) proof and the auto-generated Solidity verifier:

```bash
bb write_vk -b target/pk_enc_digest_1024.json -o evm -t evm
bb prove    -b target/pk_enc_digest_1024.json -w target/pk_enc_digest_1024.gz -k evm/vk -t evm -o evm
bb write_solidity_verifier -k evm/vk -o evm/Verifier.sol
```

The included Foundry harness (`bench/pk_digest_1024/onchain/`) deploys `HonkVerifier` and calls
`verify(bytes proof, bytes32[] publicInputs)`:

```bash
cd onchain && forge test -vv
# [PASS] test_verify_valid_proof_onchain   verify_gas: 2,510,660   num_public_inputs: 1
# [PASS] test_reject_tampered_public_input   (flipping the digest is rejected)
```

To verify against a live node instead:

```bash
anvil &                                  # local EVM
forge script script/DeployVerify.s.sol --broadcast --rpc-url http://localhost:8545
```

`NUMBER_OF_PUBLIC_INPUTS = 9` in the verifier = 1 circuit public input (the digest) + 8 pairing-point
fields carried inside the proof.

## Binding the digest (the part the verifier app must do)

The `_digest` circuit makes `pk0,pk1,c0,c1` private and exposes only their hash. The proof is **sound on
its own** — it certifies "the public key and ciphertext behind this digest form a valid encryption of a
bounded message" (the digest now binds `(pk,c)` into the Fiat–Shamir challenge `γ`, so the prover cannot
forge a non-ciphertext — security.md §6). What the proof does *not* say is *which* `(pk,c)` — that the
relying party pins by recomputing the digest from the values it already trusts:

```
accept(proof, ciphertext) :=
    pi := H(registered_pk ‖ ciphertext)          // same Poseidon2 packing as the circuit
    return HonkVerifier.verify(proof, [pi])
```

Because the verifier only accepts when the proof's public input equals `H(registered_pk ‖
ciphertext)`, the proven `pk0,pk1,c0,c1` are forced to be exactly the registered key and the submitted
ciphertext. This is why the circuit range-checks `pk0,pk1,c0,c1` to 27 bits (so the packing is
injective). **Skipping this binding does not let a prover pass off a non-ciphertext (the proof is sound),
but it leaves you unable to tell whether the proof is about *your* ciphertext** — so it is still
required for relevance. See [security.md §6](security.md).

`registered_pk` must itself be a **well-formed** public key, established once at key registration by the
recipient or a DKG ceremony — the circuit proves validity *under* `pk`, not validity *of* `pk` (only the
secret-key holder could prove that). This is the trust boundary spelled out in
[security.md §6](security.md).

The ciphertext can then be published wherever is cheapest (calldata, or an EIP-4844 blob for data
availability) since it is no longer a SNARK public input.

## Using a real ciphertext

The toy `witness-gen` matches the circuit's parameters exactly (`q = 134215681`, etc.) so the whole
pipeline runs offline with zero dependencies. To prove a ciphertext from a production library
(OpenFHE/SEAL/fhe.rs), you must (a) match the ring/modulus to a preset, and (b) recover the witness
polynomials — the randomness `u`, errors `e0,e1`, message `m`, and the four quotients — from the
encryption, then format them as signed field representatives. The public-key path matches the default
encryption mode of those libraries, which makes this conversion the natural next integration step (a
tracked roadmap item; see the [README roadmap](../README.md#roadmap)).

## Negative tests

```bash
# Each tamper makes the witness invalid; `nargo execute` must fail.
for spec in u:0:2 e0:5:20 q0:5:99 c0:3:0 r1:7:9999999; do
  ../../witness-gen/target/release/witness-gen --scheme pk --n 1024 --seed 7 --tamper "$spec" --out Prover.toml
  nargo execute && echo "ACCEPTED (BUG)" || echo "rejected: $spec"
done
```

`u:0:2` (non-ternary), `e0:5:20` (`|e| > B`), `q0:5:99` (wrong `X^N+1` quotient — confirms the packed
challenge binds the quotient), `c0:3:0` (tampered private ciphertext), `r1:7:…` (out-of-range
mod-`q` quotient) all reject.
