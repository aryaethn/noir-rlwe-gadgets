# Benchmarks — noir-rlwe-gadgets

> **UNAUDITED RESEARCH.** Proof of correct BFV encryption — secret-key (Greco-style) and
> **public-key** (fhEVM-style input) — via the Schwartz-Zippel approach over
> R_q = Z_q[X]/(X^N+1), no in-circuit NTT.

**Machine:** MacBook Air M2, 8 GB RAM. **Toolchain:** nargo 1.0.0-beta.22,
bb 5.0.0-nightly.20260522 (UltraHonk), Foundry 1.7.1. **Date:** 2026-06-14.
**Preset:** q = 134215681 (27-bit NTT prime), t = 65537, B_err = 19.

## Provenance — what is measured vs cited

Every number below is a real measurement on the machine above, EXCEPT the Greco comparison
row (cited from ePrint 2024/594). Methodology:

- **Gates** = `bb gates` `circuit_size` (exact UltraHonk circuit size).
- **Compile** = `/usr/bin/time -p nargo compile`, real seconds (single run).
- **Prove** = `bb prove --write_vk` (native, includes inline VK generation), **median of 3 runs**
  (`/usr/bin/time` real). Earlier single-run figures were noisy (a cold run once showed 4.6 s at
  n=1024 vs a 2.29 s median) — hence median-of-3 here.
- **Prove RAM** = `/usr/bin/time -l` maximum resident set size.
- **Verify** = `bb verify` real seconds (near-instant; cold starts can show ~0.3 s).
- **On-chain gas** = the `verify(bytes,bytes32[])` call gas under `forge test` (Foundry EVM,
  cancun), cross-checked by deploying the verifier to a live **Anvil** node and calling it.
- Witnesses are real, produced by the Rust `witness-gen` (toy BFV) at each N.

## Main result — generalized single-digest circuit, by ring degree N

`verify_sk_encryption_digest::<N, LOG_N>` (generic over N; ciphertext is private witness, circuit
returns one public `digest`; uniform quotient bounds valid for N ≤ 4096).

| N | Gates | Compile (s) | Prove (s, med/3) | Prove RAM (MB) | Verify (s) | On-chain gas | Public inputs |
|---|---|---|---|---|---|---|---|
| 512  | 26,457  | 0.77 | 0.42 | 62  | 0.01 | 2,387,696 | 1 |
| 1024 | 48,195  | 0.90 | 0.65 | 108 | 0.01 | 2,449,156 | 1 |
| 2048 | 91,883  | 1.50 | 1.01 | 219 | 0.01 | 2,510,660 | 1 |
| 4096 | 179,263 | 3.03 | 2.77 | 338 | 0.01 | 2,572,208 | 1 |

- Gates scale ~linearly in N (FS + range checks + identity are O(N)). Even **n=4096 is 179,263
  gates (≈2¹⁷·⁵), under the 2¹⁹ design ceiling**, with 338 MB RAM — the 8 GB target is never close.
- **On-chain gas is nearly flat (~2.4–2.6M) across all N** because the digest gives every circuit
  a single public input; the small growth is sumcheck rounds (~log₂ circuit_size), not data.

## Public-key BFV encryption — `verify_pk_encryption_digest` (the fhEVM-style input statement)

The SK statement above can only be proved by the secret-key holder. The statement an actual
fhEVM-style input submitter needs is **public-key** encryption well-formedness — the encryptor holds
only the recipient's public key `pk = (pk0, pk1)`. `proofs/pk_encryption.nr` proves both PK relations
at one Fiat-Shamir γ (with `u(γ)` shared):

    pk0·u = c0 − e0 − Δ·m + q·r0 + (X^N+1)·q0
    pk1·u = c1 − e1        + q·r1 + (X^N+1)·q1     over Z[X]

Structurally two SK identities sharing `u`, reusing the same Schwartz-Zippel / packing / digest
gadgets. Because `pk0,pk1` are reduced-mod-q (|coeff| < q, exactly like `a` in SK), the quotient
bounds are **identical** to SK's (|r| ≤ N+2, |q| ≤ (N−1)q) — no new soundness derivation. Digest
variant: `pk0,pk1,c0,c1` are private, the circuit returns one public `digest = H(pk0||pk1||c0||c1)`.

| N | Gates | Prove (s, med/3) | Prove RAM (MB) | Verify | On-chain gas | Public inputs |
|---|---|---|---|---|---|---|
| 512  | 42,627 | 0.54 | 93  | PASS | 2,449,156 | 1 |
| 1024 | 80,185 | 0.89 | 184 | PASS | 2,510,660 | 1 |

- **~1.66× the SK digest gate count** (two products + 8 witness polys vs one + 5); still far under
  the 2¹⁹ ceiling and the 8 GB target. Prove ~1.3× SK, RAM ~1.7× SK.
- **On-chain gas matches SK digest** (`NUMBER_OF_PUBLIC_INPUTS = 9` either way; gas tracks the
  padded-circuit-size bucket, not PK-vs-SK). PK n=1024 (80,185 → pads to 2¹⁷) lands in the same
  bucket as SK n=2048, hence the identical 2,510,660; PK n=512 (→2¹⁶) matches SK n=1024's 2,449,156.
- **End-to-end verified:** real Rust PK witness (`witness-gen --scheme pk`) accepted by
  `nargo execute`; `bb prove`/`verify` PASS; Solidity verifier deployed under `forge`, tampered
  digest rejected.
- **Negative tests** (`nargo execute`) reject: `u` non-ternary, |e0| > B, wrong `q0` (the X^N+1
  quotient — confirms the packed γ binds the quotient), tampered private `c0`, out-of-range `r1`.

## Optimization progression at n=1024 (consistent median-of-3)

| Circuit | Gates | Prove (s) | Prove RAM (MB) | On-chain gas | Public inputs |
|---|---|---|---|---|---|
| unpacked (raw ciphertext PI) | 212,055 | 2.29 | 417 | 5,753,230 | 2048 |
| + packed Fiat-Shamir | 40,641 | 0.53 | 99 | ≈5.75M (PI-bound) | 2048 |
| + single-digest public input | 48,195 | 0.65 | 108 | **2,449,156** | **1** |

- **Packed FS (Part 1, ADR-011):** bit-packing the witness coefficients before the Poseidon2
  challenge hash cuts the circuit **5.2×** (212,055 → 40,641) and prove ~4× (2.29 → 0.53 s), with
  identical statement/soundness. (Poseidon2 measured at ~25.4 gates/absorbed element; FS was ~86%
  of the unpacked circuit.) Does not change on-chain gas — that is public-input-bound.
- **Single-digest public input (Part 2 prerequisite, ADR-012):** ciphertext becomes private, the
  circuit returns one public `digest = Poseidon2(hash(pack c0), hash(pack c1))` (c0,c1 range-checked
  to 27 bits for injective binding). Public inputs **2048 → 1**, on-chain gas **5.75M → 2.45M
  (2.35×)**, and the 64 KB ciphertext calldata is removed. The +7.5k gates over packed is the c0,c1
  range checks + digest hash. Enables posting the ciphertext in an EIP-4844 blob (Part 2).
- **Combined vs unpacked baseline:** 212,055 → 48,195 gates (**4.4×**), prove 2.29 → 0.65 s, RAM
  417 → 108 MB, gas 5.75M → 2.45M (**2.35×**), public inputs 2048 → 1.

Soundness preserved at every stage: valid Rust-generated witnesses accepted; tampered q_as, s, and
(private) c0 all rejected by `nargo execute`; tampered public input rejected on-chain.

## Comparison with Greco (Halo2)  *(Greco row cited, not measured here)*

| System | n=1024 prove | Verify | On-chain verifier | Prove RAM |
|---|---|---|---|---|
| Greco (Halo2), *cited* ePrint 2024/594 | ~685 ms | ~3–5 ms | custom Halo2 Solidity | not 8 GB-targeted |
| This library, UltraHonk (digest) | 0.65 s (med) | 0.01 s | bb-generated UltraHonk Solidity | 0.11 GB |

- After the FS optimization, prove (0.65 s) is now within ~1× of Greco's cited ~685 ms — the
  earlier gap was almost entirely the in-circuit Fiat-Shamir, now packed away.
- Differentiators stand: a standard auto-generated UltraHonk Solidity verifier (deployed + verified
  on Anvil), a single public input, and 0.11 GB prove RAM on an 8 GB machine.

## Reproduce

```bash
cd noir-rlwe && nargo test                    # 50 tests
cd ../witness-gen && cargo build --release

# Secret-key digest circuit
cd ../bench/circuit_digest_1024
../../witness-gen/target/release/witness-gen --out Prover.toml --n 1024 --seed 5 --message "noir-rlwe vFHE"
nargo execute witness
bb prove  -b target/sk_enc_digest_1024.json -w target/witness.gz -o evm -t evm --write_vk
bb write_solidity_verifier -k evm/vk -o ../circuit/onchain/src/HonkVerifier.sol -t evm
cd ../circuit/onchain && forge test -vv        # on-chain verify gas + tamper rejection

# Public-key digest circuit (the fhEVM-style input statement)
cd ../../bench/pk_digest_1024
../../witness-gen/target/release/witness-gen --scheme pk --n 1024 --seed 7 --out Prover.toml
nargo execute
bb write_vk -b target/pk_enc_digest_1024.json -o po
bb prove    -b target/pk_enc_digest_1024.json -w target/pk_enc_digest_1024.gz -k po/vk -o po --verify
cd onchain && forge test -vv                   # PK on-chain verify gas + tamper rejection
```
