# noir-rlwe-gadgets

> **UNAUDITED RESEARCH.** No security guarantees until a professional audit. Do not use in production.

Noir gadgets for verifying Ring-LWE / BFV operations inside SNARK circuits, targeting
Aztec's Noir / Barretenberg / UltraHonk stack. The core technique is **Schwartz-Zippel
random-evaluation** of polynomial identities over `R_q = Z_q[X]/(X^N + 1)` — **not**
in-circuit NTT (which is O(N log N) gates and out of scope; see `docs/concepts.md`).

Built and validated on **nargo 1.0.0-beta.22 / bb 5.0.0-nightly.20260522**.

## What's here (Phase 1)

| Module | Gadget | Notes |
|---|---|---|
| `ring` | `RingElement<N, Q>`, `add/sub/neg/scalar_mul`, `reduce` | arithmetic is non-reducing (ADR-008) |
| `poly::horner` | `eval_at(coeffs, gamma)` | exactly N−1 mults (1,042 gates @ N=1024) |
| `poly::product_check` | `assert_poly_product(f, g, h, k, gamma)` | the core S-Z check; 5,146 gates @ N=1024 |
| `range::ternary` | `assert_ternary` | exact cubic, for the secret key |
| `range::bounded` | `assert_bounded`, `assert_lt` | infinity-norm error bound |
| `fiat_shamir` | `derive_challenge(polys)` | Poseidon2; binds to the witness (ADR-009) |
| `params` | `bfv_1024_27`, `bfv_1024_55` | validated presets |

## Quick example

```noir
use noir_rlwe::params::bfv_1024_27::{N, Q, LOG_N};
use noir_rlwe::{RingElement, derive_challenge};
use noir_rlwe::poly::product_check::assert_poly_product;

// Prove f * g == h in R_q, given the negacyclic quotient k.
fn check(f: [Field; N], g: [Field; N], h: [Field; N], k: [Field; N]) {
    let fr: RingElement<N, Q> = RingElement::new(f);
    let gr: RingElement<N, Q> = RingElement::new(g);
    let hr: RingElement<N, Q> = RingElement::new(h);
    let kr: RingElement<N, Q> = RingElement::new(k);
    let gamma = derive_challenge([fr, gr, hr, kr]); // hash ALL polys incl. witness
    assert_poly_product::<N, Q, LOG_N>(fr, gr, hr, kr, gamma);
}
```

The prover must supply `k` such that `f(X)·g(X) = h(X) + (X^N + 1)·k(X)` exactly over `Z[X]`
(the negacyclic quotient). The Rust `witness-gen` crate produces full witnesses for the circuits below.

## Proof circuits (`proofs/`)

Two complete BFV encryption-correctness statements, each in three variants (plain / packed-Fiat-Shamir
/ single-digest). The digest variant makes the ciphertext private and exposes **one** public input
(a Poseidon2 digest) for cheap on-chain verification. Measured on an M2 Air, 8 GB — see `BENCHMARKS.md`.

| Circuit | Statement | n=1024 digest | Who can prove it |
|---|---|---|---|
| `sk_encryption` | `c0 = [-a·s + Δ·m + e]_q`, `c1 = a` | 48,195 gates, 0.65 s, 2.45M gas | the secret-key holder |
| `pk_encryption` | `c0 = [pk0·u + e0 + Δ·m]_q`, `c1 = [pk1·u + e1]_q` | 80,185 gates, 0.89 s, 2.51M gas | **any input submitter** (holds only `pk`) |

`pk_encryption` is the **fhEVM-style input statement**: it proves a submitted ciphertext is a
well-formed public-key encryption of a bounded message, which is what a user (who does not hold the
FHE secret key) actually needs. It is two Schwartz-Zippel identities sharing the randomness `u`,
reusing the same gadgets and quotient bounds as `sk_encryption`.

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

```bash
# End-to-end: encrypt in Rust -> prove in Noir -> verify (native + on-chain)
cd ../witness-gen && cargo build --release
cd ../bench/pk_digest_1024
../../witness-gen/target/release/witness-gen --scheme pk --n 1024 --seed 7 --out Prover.toml
nargo execute
bb write_vk -b target/pk_enc_digest_1024.json -o po
bb prove    -b target/pk_enc_digest_1024.json -w target/pk_enc_digest_1024.gz -k po/vk -o po --verify
cd onchain && forge test -vv      # Solidity UltraHonk verifier: gas + tamper rejection
```

## Build & test

```bash
cd noir-rlwe
nargo check
nargo test          # 50 tests, including soundness negative tests

# Gate counts (true UltraHonk circuit size):
cd ../bench/product && nargo compile && bb gates -b ./target/bench_product.json
```

## Design notes

- **Field-valued generics** (`Q: Field`) must be passed via a `global` constant, not a
  literal (ADR-004). Presets in `params/` provide them.
- **Range checks** use `assert_max_bit_size`, never `as uN` casts (which truncate, ADR-007).
- **Soundness:** the S-Z check gives *random-evaluation* soundness ~2N/p; knowledge soundness
  additionally requires the proof system's polynomial commitments. The challenge binds to the
  witness (ADR-009). The product check alone does not prove a full BFV statement — that is the
  Phase 2 top-level circuit.

## License

MIT or Apache-2.0 (to be finalized before publication).
