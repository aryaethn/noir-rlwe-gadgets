# noir-rlwe-gadgets

**Verifiable Ring-LWE / BFV encryption in [Noir](https://noir-lang.org), proved with UltraHonk and verifiable on-chain.**

> ⚠️ **UNAUDITED RESEARCH.** This library is research-grade and has **not** been audited. It provides
> no security guarantees. Do not use it to protect anything of value. See [docs/security.md](docs/security.md).

---

A Noir library of gadgets for verifying [Ring-LWE](https://en.wikipedia.org/wiki/Ring_learning_with_errors)
operations — specifically, that a [BFV](https://eprint.iacr.org/2012/144) ciphertext is a *correct,
well-formed encryption* of a bounded message — inside a SNARK circuit on the Aztec / Barretenberg /
UltraHonk stack. It is a Noir port and extension of the [Greco](https://eprint.iacr.org/2024/594)
approach, and the first lattice-encryption gadget set in the Noir ecosystem.

The core technique is **Schwartz-Zippel random-evaluation** of polynomial identities over
`R_q = Z_q[X]/(X^N + 1)` — **not** in-circuit NTT. A degree-`N` polynomial product check collapses to
three Horner evaluations at one Fiat-Shamir challenge `γ`, turning an `O(N log N)` problem into an
`O(N)` circuit. See [docs/concepts.md](docs/concepts.md).

## Why

- **fhEVM-style input proofs.** A user submitting an encrypted input to an FHE coprocessor (Zama
  fhEVM, threshold-FHE rollups) must prove the ciphertext is a valid encryption of a bounded message
  *without revealing it*. That is exactly the public-key statement this library proves
  ([`pk_encryption`](noir-rlwe/src/proofs/pk_encryption.nr)).
- **The Noir gap.** Halo2 has Greco; Noir/Aztec had nothing for lattice encryption. This fills it,
  and ships a **standard auto-generated UltraHonk Solidity verifier** (no custom verifier contract).
- **A step toward verifiable FHE (vFHE).** The Schwartz-Zippel product gadget and coefficient range
  checks are the shared primitives for proving homomorphic operations (ct-ct add, relinearization,
  modulus switch). See the [Roadmap](#roadmap).

## What it proves

Two complete BFV encryption-correctness circuits over `R_q = Z_q[X]/(X^N + 1)`, each with a
single-digest variant that exposes **one** public input for cheap on-chain verification. Numbers below
are **measured** on an M2 Air (8 GB), n=1024, preset q≈2²⁷ — see [BENCHMARKS.md](BENCHMARKS.md).

| Circuit | Statement | Who can prove it | n=1024 (digest) |
|---|---|---|---|
| [`sk_encryption`](noir-rlwe/src/proofs/sk_encryption.nr) | `c0 = [-a·s + Δ·m + e]_q`, `c1 = a` | the secret-key holder | 48,270 gates · 0.65 s · 2.45M gas |
| [`pk_encryption`](noir-rlwe/src/proofs/pk_encryption.nr) | `c0 = [pk0·u + e0 + Δ·m]_q`, `c1 = [pk1·u + e1]_q` | **any input submitter** (holds only `pk`) | 80,262 gates · 0.89 s · 2.51M gas |

Both prove knowledge of a ternary key/randomness, a bounded error `‖e‖∞ ≤ B`, and a plaintext
`m ∈ [0, t)`, enforced by in-circuit range checks. All circuits ship with negative tests (tampering
detection) at both the witness and on-chain levels.

## Quick start

Requires [`nargo` 1.0.0-beta.22](https://noir-lang.org), [`bb` 5.0.0-nightly](https://github.com/AztecProtocol/aztec-packages),
Rust, and (for on-chain) [Foundry](https://getfoundry.sh).

```bash
git clone <repo-url> noir-rlwe-gadgets && cd noir-rlwe-gadgets

# 1. Library: type-check + 50 tests (incl. soundness negative tests)
cd noir-rlwe && nargo test && cd ..

# 2. Build the Rust witness generator (toy BFV, zero deps)
cd witness-gen && cargo build --release && cd ..

# 3. End-to-end public-key encryption proof at n=1024
cd bench/pk_digest_1024
../../witness-gen/target/release/witness-gen --scheme pk --n 1024 --seed 7 --out Prover.toml
nargo execute                                                       # solve the witness
bb write_vk -b target/pk_enc_digest_1024.json -o po
bb prove    -b target/pk_enc_digest_1024.json -w target/pk_enc_digest_1024.gz -k po/vk -o po --verify
cd onchain && forge test -vv                                        # Solidity verifier: gas + tamper test
```

Full walkthrough (including using a real ciphertext): [docs/end_to_end.md](docs/end_to_end.md).

## Using it as a dependency

```toml
# Nargo.toml
[dependencies]
noir_rlwe = { git = "https://github.com/<owner>/noir-rlwe-gadgets", directory = "noir-rlwe", tag = "v0.1.0" }
```

```noir
use noir_rlwe::proofs::pk_encryption::verify_pk_encryption_digest;

fn main(
    pk0: [Field; 1024], pk1: [Field; 1024], c0: [Field; 1024], c1: [Field; 1024],
    u: [Field; 1024], e0: [Field; 1024], e1: [Field; 1024], m: [Field; 1024],
    r0: [Field; 1024], r1: [Field; 1024], q0: [Field; 1024], q1: [Field; 1024],
) -> pub Field { // returns digest = H(pk0||pk1||c0||c1)
    verify_pk_encryption_digest::<1024, 10>(pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1)
}
```

Full API: [docs/api.md](docs/api.md).

## Repository layout

```
noir-rlwe/        the Noir library (gadgets + proof circuits)   <- the published package
witness-gen/      Rust toy-BFV witness generator (--scheme sk|pk)
bench/            per-circuit Nargo harnesses + Foundry on-chain verifiers
docs/             concepts, API, end-to-end, security, no-wraparound proof, benchmarks
tools/            Python oracles / proof checks (witness cross-check, no-wraparound bound)
BENCHMARKS.md     full measured benchmark tables + provenance
```

## Documentation

- [docs/concepts.md](docs/concepts.md) — the ring `R_q`, BFV SK/PK relations, the Schwartz-Zippel identity, why not NTT
- [docs/api.md](docs/api.md) — full module/gadget API reference
- [docs/end_to_end.md](docs/end_to_end.md) — encrypt in Rust → prove in Noir → verify on-chain
- [docs/security.md](docs/security.md) — soundness argument, knowledge-soundness status, the public-key binding requirement, proof obligations
- [docs/no_wraparound.md](docs/no_wraparound.md) — proof of the no-wraparound soundness lemma (`‖D‖∞ < p/2`)
- [docs/completeness.md](docs/completeness.md) — proof that genuine encryptions always pass the quotient range checks (`‖q‖∞ < 2³⁹`, `‖r‖∞ ≤ N+2`)
- [docs/parameter_security.md](docs/parameter_security.md) — lattice-estimator validation of the presets (`bfv_1024_27` ≈126-bit; `bfv_1024_55` insecure at n=1024)
- [docs/proof_system_composition.md](docs/proof_system_composition.md) — how the in-circuit Schwartz–Zippel argument composes with UltraHonk (Fiat–Shamir ROM reduction, knowledge soundness, ZK)
- [BENCHMARKS.md](BENCHMARKS.md) — measured gates / prove time / RAM / on-chain gas, with provenance
- [docs/benchmarks.md](docs/benchmarks.md) — pointer to the above

## Parameters

The MVP preset is `bfv_1024_27` (Greco's `sk_enc_1024_1x27_65537`): `n = 1024`, `q = 134215681`
(27-bit, NTT-friendly), `t = 65537`, ternary key, `B_err = 19` (6σ, σ=3.2). The circuits are generic
over the ring degree `N` (validated for `N ≤ 4096`). `bfv_1024_27` is **~126-bit secure** (lattice-estimator;
[docs/parameter_security.md](docs/parameter_security.md)) — use it for real encryption. A 56-bit preset
`bfv_1024_55` exists as a circuit-arithmetic test vector only: it is **~63-bit at `n=1024` and NOT secure
for encryption** (a larger `q` needs a larger `n`).

## Status & scope

MVP complete: SK + PK encryption circuits, packed Fiat-Shamir + single-digest optimizations, Rust
witness generator, on-chain UltraHonk Solidity verifier (deployed + verified on Anvil), measured
benchmarks. **Not yet done:** professional audit, a production-FHE-library cross-check, the q≈2⁵⁵
witness path, and the post-MVP homomorphic-operation circuits (see [Roadmap](#roadmap)).

## Security

> Research-grade and **UNAUDITED** — full analysis in [docs/security.md](docs/security.md). A professional
> audit is required before any production use.

The soundness of the Schwartz–Zippel approach is worked out, not assumed:

- **No-wraparound lemma (proven)** — the single-point check over `F_p` forces the exact integer relation: every coefficient of the difference polynomial satisfies `‖D‖∞ < 2⁴² < p/2` ([docs/no_wraparound.md](docs/no_wraparound.md)).
- **Quotient completeness (proven)** — every genuine encryption passes the range checks ([docs/completeness.md](docs/completeness.md)).
- **Fiat–Shamir in the ROM (proven)** — the in-circuit challenge is sound with grinding error `≤ Q·(2N−1)/p` ([docs/proof_system_composition.md](docs/proof_system_composition.md)).
- **Knowledge soundness & zero-knowledge (reduced)** — to UltraHonk's standard guarantees; the ZK flavor is verified on, so the witness (message, randomness, errors) is hidden under RLWE.
- **Parameters validated** — `bfv_1024_27` is ~126-bit (lattice-estimator); `bfv_1024_55` is insecure at n=1024 and is test-vector-only ([docs/parameter_security.md](docs/parameter_security.md)).
- **Trust boundary** — the digest binds `(pk,c)` into the Fiat–Shamir challenge, so the proof is sound on its own; the relying party still binds the returned digest to a *registered, well-formed* public key (the circuit proves validity **under** `pk`, not **of** `pk`).

An internal review pass hardened the digest/`γ` binding and surfaced these as explicit obligations; it is **not** an independent audit.

## Roadmap

Post-MVP directions, roughly in order of expected community value (the public-key circuit, originally
a roadmap item, is already shipped):

- **Production-FHE cross-check** — recover witnesses from an OpenFHE/SEAL/fhe.rs ciphertext and prove
  it, validating the toy parameters against a real library.
- **`q ≈ 2⁵⁵` witness path** — wire the `bfv_1024_55` preset end-to-end (quotient-bound constants +
  witness generator) for a higher soundness margin.
- **Multi-prime CRT modulus** (`Q = q₀·q₁·…`) — the prerequisite for BGV and for BFV at higher levels.
- **Homomorphic-operation circuits** — ct-ct addition (cheapest, the natural next demo), then
  relinearization and modulus switch (the verifiable-FHE prize; the public-key two-product pattern is
  their template).

These are research-gated and unscheduled; see [docs/security.md](docs/security.md) for the open proof
obligations that any production use would need closed first.

## Acknowledgements & related work

- [Greco](https://github.com/enricobottazzi/greco) (ePrint [2024/594](https://eprint.iacr.org/2024/594))
  — the Halo2 reference this library ports and extends.
- [hyper-greco](https://github.com/nulltea/hyper-greco) — the same statement via GKR/Libra.
- Built on [Noir](https://github.com/noir-lang/noir), [Barretenberg/UltraHonk](https://github.com/AztecProtocol/aztec-packages),
  and [noir-lang/poseidon](https://github.com/noir-lang/poseidon).

## License

Dual-licensed under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
