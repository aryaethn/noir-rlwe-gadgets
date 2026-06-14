# API reference

Public API of the `noir_rlwe` package. Signatures use Noir generics: `<let N: u32, …>`. All gadgets
are `pub`. **UNAUDITED RESEARCH** — see [security.md](security.md) for soundness caveats.

Convenience re-exports at the crate root (`use noir_rlwe::…`): `RingElement`, `eval_at`,
`assert_poly_product`, `derive_challenge`.

---

## `proofs` — top-level circuits

The headline entry points. Each circuit comes in three variants with the **same statement and
soundness**; they differ only in how the Fiat-Shamir challenge is derived and which values are public.

### `proofs::sk_encryption`

```noir
// Public c0,c1; witnesses s,e,m,r,q_as. Plain: binds all polys via per-element Fiat-Shamir.
pub fn verify_sk_encryption<let N: u32, let LOG_N: u32>(
    c0, c1, s, e, m, r, q_as: [Field; N]
);
// Packed Fiat-Shamir (~5x fewer gates); c0,c1 still public inputs.
pub fn verify_sk_encryption_packed<let N: u32, let LOG_N: u32>(
    c0, c1, s, e, m, r, q_as: [Field; N]
);
// Single-digest: c0,c1 PRIVATE; returns digest = Poseidon2(pack(c0)||pack(c1)). One public input.
pub fn verify_sk_encryption_digest<let N: u32, let LOG_N: u32>(
    c0, c1, s, e, m, r, q_as: [Field; N]
) -> Field;
```

Proves `c0 = [-a·s + Δ·m + e]_q`, `c1 = a`, with `a = c1`. Witnesses: `s` ternary, `e` with
`‖e‖∞ ≤ B`, `m ∈ [0,t)`, and the quotient polynomials `r` (mod-`q`) and `q_as` (`X^N+1`).

### `proofs::pk_encryption`

```noir
pub fn verify_pk_encryption<let N: u32, let LOG_N: u32>(
    pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1: [Field; N]
);
pub fn verify_pk_encryption_packed<let N: u32, let LOG_N: u32>(
    pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1: [Field; N]
);
// Single-digest: pk0,pk1,c0,c1 PRIVATE; returns digest = Poseidon2(pack(pk0)||pack(pk1)||pack(c0)||pack(c1)).
pub fn verify_pk_encryption_digest<let N: u32, let LOG_N: u32>(
    pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1: [Field; N]
) -> Field;
```

Proves `c0 = [pk0·u + e0 + Δ·m]_q`, `c1 = [pk1·u + e1]_q`. Witnesses: `u` ternary, `e0,e1` with
`‖·‖∞ ≤ B`, `m ∈ [0,t)`, mod-`q` quotients `r0,r1`, and `X^N+1` quotients `q0,q1`.

> **Digest binding (required for soundness of `_digest`).** The returned digest only pins the values
> the relying party compares it against. The verifier MUST check `digest == H(registered_pk ‖
> submitted_ciphertext)` and reject on mismatch — otherwise a prover could encrypt under a public key
> they control. See [security.md](security.md) §"Public-key binding".

All circuits require `LOG_N == log2(N)`. Constants (`Q, Δ, t, B`, quotient bounds) come from the
`bfv_1024_27` preset; the circuits are generic over `N` and validated for `N ≤ 4096`.

---

## `ring` — elements of `R_q`

```noir
pub struct RingElement<let N: u32, let Q: Field> { pub coeffs: [Field; N] }

impl RingElement {
    pub fn new(coeffs: [Field; N]) -> Self;   // wraps; does NOT range-check
    pub fn zero() -> Self;
    pub fn constant(c: Field) -> Self;        // c in the X^0 slot
}
```

The `Q` generic tags the modulus at the type level so elements of different rings cannot be mixed.

### `ring::arithmetic` — non-reducing

```noir
pub fn add<N,Q>(a, b: RingElement<N,Q>) -> RingElement<N,Q>;
pub fn sub<N,Q>(a, b: RingElement<N,Q>) -> RingElement<N,Q>;
pub fn neg<N,Q>(a: RingElement<N,Q>) -> RingElement<N,Q>;
pub fn scalar_mul<N,Q>(s: Field, a: RingElement<N,Q>) -> RingElement<N,Q>;
```

These compute over the **full field** and do **not** reduce mod `Q` (ADR-008): the Schwartz-Zippel
check carries reduction via quotient polynomials, so `add`/`sub` are free and `scalar_mul` costs `N`
mults. Outputs may have coefficients outside `[0, Q)`.

### `ring::reduction` — canonical `[0,Q)` form

```noir
pub fn reduce<let VALBITS: u32, let QBITS: u32>(a: Field, q: Field) -> Field;
pub fn reduce_ring<N, Q, let VALBITS: u32, let QBITS: u32>(a: RingElement<N,Q>) -> RingElement<N,Q>;
```

Sound Euclidean reduction of a non-negative `a ∈ [0, 2^VALBITS)` to `[0,q)`, via an unconstrained
`(quotient, remainder)` hint pinned by `quotient*q + remainder == a`, `remainder < q`, and
`quotient < 2^VALBITS`. Use when a canonical representative is actually required (e.g. to publish a
reduced coefficient).

---

## `poly` — evaluation and the product check

```noir
// Horner: coeffs[0] + coeffs[1]*g + … + coeffs[N-1]*g^(N-1). Exactly N-1 mults.
pub fn poly::horner::eval_at<let N: u32>(coeffs: [Field; N], gamma: Field) -> Field;

// gamma^(2^LOG_N) by repeated squaring.
pub fn poly::product_check::pow_pow2<let LOG_N: u32>(gamma: Field) -> Field;

// Assert f*g == h in R_q given negacyclic quotient k, by evaluation at gamma:
//   f(g)*g(g) == h(g) + (g^N + 1)*k(g).   LOG_N must equal log2(N).
pub fn poly::product_check::assert_poly_product<N, Q, let LOG_N: u32>(
    f, g, h, k: RingElement<N,Q>, gamma: Field
);
```

`assert_poly_product` is the core Schwartz-Zippel gadget; the prover must supply `k` with
`f·g = h + (X^N+1)·k` exactly over `Z[X]`.

---

## `range` — sound coefficient bounds

All range checks build on `assert_max_bit_size`; never use `as uN` casts, which truncate rather than
constrain (ADR-007).

### `range::ternary` — unsigned `{0,1,Q-1}`

```noir
pub fn assert_ternary(c: Field, q: Field);              // exact cubic c(c-1)(c-(q-1))==0
pub fn assert_ternary_ring<N,Q>(a: RingElement<N,Q>);
```

### `range::signed` — signed/centered values

```noir
pub fn assert_ternary_signed(c: Field);                 // c in {-1,0,1} (field {p-1,0,1}); cubic
pub fn assert_abs_le<let BITS: u32>(c: Field, b: Field); // |c| <= b; needs 2b+1 <= 2^BITS
pub fn assert_signed_pow2<let BITS: u32>(x: Field, shift: Field); // x in [-shift, 2^BITS - shift)
pub fn assert_ternary_signed_ring<N,Q>(a: RingElement<N,Q>);
pub fn assert_abs_le_ring<N,Q, let BITS: u32>(a: RingElement<N,Q>, b: Field);
```

`assert_signed_pow2` with `shift = 2^(BITS-1)` gives the symmetric `|x| < 2^(BITS-1)`; it is used for
the quotient polynomials.

### `range::bounded` — unsigned centered band

```noir
pub fn assert_bounded<let BBITS: u32>(c: Field, q: Field, b: Field);  // |c| <= b in [0,b]∪[q-b,q-1]
pub fn assert_bounded_ring<N,Q, let BBITS: u32>(a: RingElement<N,Q>, b: Field);
pub use crate::util::assert_lt as assert_lt_field;
```

`assert_bounded` checks the centered magnitude of an **unsigned** `[0,q)` representative (low or high
band selected by a sound hint). Use `signed::assert_abs_le` for signed representatives.

### `util` — primitives

```noir
pub fn util::assert_max_bits<let BITS: u32>(x: Field);          // 0 <= x < 2^BITS
pub fn util::assert_lt<let BITS: u32>(x: Field, bound: Field);  // 0 <= x < bound (<= 2^BITS)
```

---

## `pack` — bit-packing for cheap Fiat-Shamir

```noir
// Pack N values (each < 2^BITS, caller-guaranteed), K per element, into ceil(N/K) field elements.
// Requires K*BITS <= 253 (injective, packed < p). Does NOT range-check.
pub fn pack_bits<let N: u32, let BITS: u32, let K: u32>(vals: [Field; N]) -> [Field; (N + K - 1) / K];

// Same, but range-checks each value to BITS bits first (sound standalone, pays the checks).
pub fn pack_bits_checked<let N: u32, let BITS: u32, let K: u32>(vals: [Field; N]) -> [Field; (N + K - 1) / K];
```

Poseidon2 costs ~25.4 gates per absorbed element regardless of bit-width, so packing the tiny RLWE
coefficients before hashing cuts the hash cost by the packing factor `K`. The output length is a
compile-time `ceil(N/K)`.

---

## `fiat_shamir::challenge` — challenge derivation

```noir
pub fn hash_ring<N,Q>(a: RingElement<N,Q>) -> Field;                 // Poseidon2 of one element's coeffs
pub fn hash_packed<let N: u32, let BITS: u32, let K: u32>(vals: [Field; N]) -> Field; // pack then hash
pub fn derive_challenge<N, Q, let M: u32>(polys: [RingElement<N,Q>; M]) -> Field;     // hash M polys -> gamma
```

`derive_challenge` hashes each polynomial to a digest and hashes the digests. Pass **every** polynomial
the product check depends on, public and witness (ADR-009); the challenge is a full-field element
(soundness ~`2N/p`, not `1/q`).

---

## `params` — validated presets

```noir
// bfv_1024_27 (MVP, Greco parity): N=1024, Q=134215681 (27-bit), T=65537, Δ=2047, B_KEY=1, B_ERR=19.
//   Plus quotient-bound constants: R_SHIFT, LOG_R_RANGE, QAS_SHIFT, LOG_QAS_RANGE, LOG_2BERR_P1.
use noir_rlwe::params::bfv_1024_27::{N, LOG_N, Q, T, DELTA, B_ERR /*, …*/};

// bfv_1024_55 (higher soundness margin): N=1024, Q=36028797018972161 (56-bit), T=65537. Base params
//   only (no quotient-bound constants yet — the 55-bit witness path is WIP).
use noir_rlwe::params::bfv_1024_55::{N, Q, DELTA /*, …*/};
```

Field-valued generics (`Q: Field`) must be passed via a `global` constant, not a literal (ADR-004) —
the presets provide them.
