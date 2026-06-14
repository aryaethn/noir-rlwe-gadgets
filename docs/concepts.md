# Concepts

How `noir-rlwe-gadgets` proves BFV encryption correctness in a SNARK, and why it uses
Schwartz-Zippel rather than an in-circuit NTT.

> **UNAUDITED RESEARCH.** Soundness claims here are random-evaluation arguments; full knowledge
> soundness additionally requires the proof system's polynomial commitments. See
> [security.md](security.md).

## 1. The ring `R_q`

All arithmetic lives in the negacyclic polynomial ring

```
R_q = Z_q[X] / (X^N + 1),     N a power of two.
```

An element is a polynomial of degree `< N`; we store it as its coefficient vector
`a = (a_0, …, a_{N-1})`. Multiplication is polynomial multiplication **reduced modulo `X^N + 1`**:
because `X^N ≡ -1`, any term `X^{N+j}` wraps to `-X^j` (hence *nega*cyclic). The MVP uses `N = 1024`
and a 27-bit prime `q = 134215681` chosen NTT-friendly (`q ≡ 1 mod 2N`), matching Greco's benchmark
preset.

Inside the circuit, coefficients are elements of the BN254 scalar field `F_p` (`p ≈ 2²⁵⁴`). Because
`q` and all intermediate magnitudes are far below `p`, integer arithmetic over `Z` is represented
faithfully by field arithmetic — there is no accidental wraparound. Signed values (a key in
`{-1,0,1}`, a centered error) are written as field representatives: `-v ↦ p - v`.

## 2. BFV encryption — the statements we prove

Let `Δ = ⌊q/t⌋` for plaintext modulus `t`. The library proves two encryption relations.

**Secret-key encryption** ([`sk_encryption`](../noir-rlwe/src/proofs/sk_encryption.nr)). With public
`(c0, c1) = (c0, a)` and secret witness `s` (ternary), `e` (`‖e‖∞ ≤ B`), `m ∈ [0,t)`:

```
c0 = [ -a·s + Δ·m + e ]_q ,      c1 = a .
```

Only the holder of `s` can produce this proof. It is the Greco statement, useful as a benchmark and
for key-holder settings.

**Public-key encryption** ([`pk_encryption`](../noir-rlwe/src/proofs/pk_encryption.nr)). With public
key `pk = (pk0, pk1) = (-a·s_key + e_key, a)` and ciphertext `(c0, c1)`, the encryptor holds only
`pk` and witnesses `u` (ternary), `e0, e1` (`‖e‖∞ ≤ B`), `m ∈ [0,t)`:

```
c0 = [ pk0·u + e0 + Δ·m ]_q ,    c1 = [ pk1·u + e1 ]_q .
```

This is the **fhEVM-style input statement**: a user proves their submitted ciphertext is a valid
encryption of a bounded message, without holding the FHE secret key (which belongs to the decrypting
authority). "Well-formed" matters because a malformed ciphertext could leak the secret key or corrupt
a homomorphic computation downstream.

## 3. The core gadget: Schwartz-Zippel negacyclic product check

The expensive part of either statement is the polynomial product (`a·s` or `pk·u`) modulo `X^N + 1`.
Computing it in-circuit naïvely is `O(N²)`; via NTT it is `O(N log N)` with a large constant
(§6). Instead we verify it.

To check `f · g = h` in `R_q`, the prover supplies the **quotient polynomial** `k` (degree `< N-1`)
witnessing the exact integer-polynomial identity

```
f(X) · g(X) = h(X) + (X^N + 1) · k(X)      over Z[X].
```

A verifier samples a random challenge `γ` and checks the identity **at that single point**:

```
f(γ) · g(γ) == h(γ) + (γ^N + 1) · k(γ).
```

Each evaluation is one [Horner](../noir-rlwe/src/poly/horner.nr) pass (`N-1` multiplications); the
whole check is `O(N)` gates instead of `O(N log N)`. This is
[`assert_poly_product`](../noir-rlwe/src/poly/product_check.nr).

**Why it's sound.** If the polynomial identity is *false*, the two sides differ by a nonzero
polynomial of degree `≤ 2N-2`, which has at most `2N-2` roots. For `γ` uniform over the field, the
check passes erroneously with probability `≤ (2N-2)/p ≈ 2⁻²⁴³` — negligible. (Schwartz-Zippel.)

## 4. From the product check to the full BFV identity

A complete encryption relation also folds in the `+Δ·m + e`, the `-c0`, and the modular reduction
`[·]_q`. The reduction mod `q` is itself carried by a second quotient polynomial `r` (one per ring
equation), so each equation becomes a *single* exact `Z[X]` identity checked at `γ`.

**SK identity** (two quotients, `q_as` for `X^N+1` and `r` for mod-`q`):

```
a(X)·s(X) = Δ·m + e - c0 - q·r + (X^N + 1)·q_as .
```

**PK identities** (two ring equations ⇒ two `X^N+1` quotients `q0,q1` and two mod-`q` quotients
`r0,r1`, sharing the randomness `u`):

```
pk0(X)·u(X) = c0 - e0 - Δ·m + q·r0 + (X^N + 1)·q0
pk1(X)·u(X) = c1 - e1        + q·r1 + (X^N + 1)·q1 .
```

All evaluated at one `γ`, with `u(γ)` computed once. (Derivations cross-checked coefficient-wise over
`Z` and at random `γ`, `n = 512…4096`, in `tools/`/the lab notebook.)

**Quotient bounds are soundness-critical.** Without a bound on `r`, a cheating prover could exploit
`q`'s invertibility mod `p` to satisfy a false identity. The circuit range-checks every quotient:
`|r| ≤ N+2 < 2¹³` and `|q_as|,|q0|,|q1| ≤ (N-1)q < 2⁴⁰` (uniform bounds valid for `N ≤ 4096`). Because
`pk0,pk1` are reduced-mod-`q` exactly like `a`, the PK bounds are identical to the SK ones — no new
derivation. See [security.md](security.md).

## 5. Range checks and Fiat-Shamir

The witnesses must additionally be *small*, or the statement is vacuous. The
[`range`](../noir-rlwe/src/range/) gadgets enforce, soundly (via `assert_max_bit_size`, never `as uN`
casts which merely truncate):

- ternary key/randomness `s, u ∈ {-1,0,1}` — an exact cubic `c(c-1)(c+1) = 0`;
- bounded error `‖e‖∞ ≤ B` — shift to `[0, 2B]` and bit-range-check;
- plaintext `m ∈ [0, t)` and the quotient bounds above.

The challenge `γ` is derived with **Fiat-Shamir** (Poseidon2 over BN254) from the polynomials, so the
prover cannot choose witnesses *after* seeing `γ`. Critically, `γ` binds the **witness** polynomials,
not just the public inputs (otherwise a prover knowing `γ` in advance could forge a witness satisfying
a false identity at that one point). See [`fiat_shamir`](../noir-rlwe/src/fiat_shamir/challenge.nr)
and ADR-009 in the lab notebook.

## 6. Why not in-circuit NTT

An in-circuit negacyclic NTT costs `~ (N/2)·log₂N` butterflies, each several constrained modular
multiplications: **~200k–500k gates at `N=4096`** (estimate from first principles). That blows past
the practical ceiling on an 8 GB machine and dwarfs the whole Schwartz-Zippel circuit. Three Horner
evaluations at `N=1024` cost ~3·1024 ≈ 3k multiply-gates — the entire product check is a few thousand
gates. NTT-in-circuit is therefore a deliberate **non-goal** for this library; Schwartz-Zippel is the
production path.

## 7. Two optimizations (measured)

The naïve circuit's cost is dominated by the Fiat-Shamir hash. Two transforms, applied in the
`_packed` and `_digest` circuit variants, cut it dramatically without changing the statement:

- **Coefficient packing** ([`pack`](../noir-rlwe/src/pack.nr), ADR-011). Witness coefficients are
  2–41 bits; several are packed into one 254-bit field element before hashing (an injective linear
  combination, near-free in PLONK). At `n=1024` this shrank the SK circuit **5.2×** (212k → 41k gates).
- **Single-digest public input** (ADR-012). The ciphertext (and, for PK, the public key) becomes a
  *private* witness; the circuit returns one public `digest = Poseidon2(pack(…))`. Public inputs drop
  from `2N`/`4N` to **1**, cutting on-chain gas ~2.35× and removing the ciphertext calldata. The
  relying party binds the digest to its known public key + the submitted ciphertext off-chain.

Full numbers and provenance: [BENCHMARKS.md](../BENCHMARKS.md).

## Notation

| symbol | meaning |
|---|---|
| `R_q = Z_q[X]/(X^N+1)` | the negacyclic ring, `N` a power of two |
| `Δ = ⌊q/t⌋` | scaling factor (plaintext modulus `t`) |
| `s, u` | ternary secret key / encryption randomness, `∈ {-1,0,1}` |
| `e, e0, e1` | error, `‖·‖∞ ≤ B` (`B = 19` at 6σ) |
| `m` | plaintext, `m_i ∈ [0, t)` |
| `r, r0, r1` | mod-`q` quotient polynomials |
| `q_as, q0, q1` | `X^N+1` (negacyclic) quotient polynomials |
| `γ` | Fiat-Shamir / Schwartz-Zippel challenge, uniform over `F_p` |
