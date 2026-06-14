# The no-wraparound lemma

A proof that the single-point Schwartz–Zippel check the circuits perform over the BN254 scalar field
`F_p` implies the intended polynomial identity over `Z`, with no false positive from modular
wraparound. This is the load-bearing soundness step (security.md §3, §8 obligation 1).

> **UNAUDITED RESEARCH.** This note proves the deterministic integer-bound step. The probabilistic
> step it composes with (a passing single-point check ⟹ coefficient-wise `≡ 0 (mod p)`) is the
> Schwartz–Zippel / Fiat–Shamir argument, treated separately (security.md §2, §4).

## 1. Setup and notation

Let `p` be the BN254 scalar-field prime,
```
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617,
2^253 < p < 2^254,   so   p/2 > 2^252.
```

The circuits operate in `F_p`. A signed integer `v` is represented by the field element `v mod p`
(so `-v ↦ p - v`). Each witness and public coefficient is constrained by a **range check** to a known
subset `S ⊂ F_p` whose preimage under `Z → F_p` contains a unique small integer:

> **Definition (canonical representative).** For a field element `a` whose range check confines it to a
> symmetric/positive integer window `W ⊂ Z` of width `|W| < p`, let `ι(a) ∈ W` be the unique integer
> with `ι(a) ≡ a (mod p)`. Uniqueness holds because two integers in a width-`< p` window cannot be
> congruent mod `p`.

This is the precise job of the range checks: they make `ι(·)` well-defined. The enforced windows are
(from `pk_encryption.nr` / `sk_encryption.nr`, the **digest** variants, uniform for `N ≤ 4096`):

| coefficient | range check | window `W` | `‖ι(·)‖∞` |
|---|---|---|---|
| `pk0,pk1,c0,c1` | `assert_max_bit_size::<27>` | `[0, 2²⁷)` | `< 2²⁷` |
| `u` (or `s`) | `assert_ternary_signed` | `{-1,0,1}` | `≤ 1` |
| `e0,e1` (or `e`) | `assert_abs_le::<6>(·,19)` | `[-19, 19]` | `≤ 19 < 2⁵` |
| `m` | `assert_lt::<17>(·, t)` | `[0, t)`, `t=65537` | `< 2¹⁷` |
| `r0,r1` (or `r`) | `assert_signed_pow2::<14>(·,2¹³)` | `[-2¹³, 2¹³)` | `≤ 2¹³` |
| `q0,q1` (or `q_as`) | `assert_signed_pow2::<41>(·,2⁴⁰)` | `[-2⁴⁰, 2⁴⁰)` | `≤ 2⁴⁰` |

with constants `q = 134215681 < 2²⁷`, `Δ = 2047 < 2¹¹`, and ring degree `N ≤ 4096 = 2¹²`.

## 2. The difference polynomial

Take the public-key relation 0 (the others are identical in shape). The circuit asserts, over `F_p` at
the challenge `γ` (`assert_pk_sz_identity`):
```
pk0(γ)·u(γ) = c0(γ) − e0(γ) − Δ·m(γ) + q·r0(γ) + (γ^N + 1)·q0(γ).
```
Define the **difference polynomial over `Z`**, using the canonical representatives for every
coefficient:
```
D(X) := pk0(X)·u(X) − c0(X) + e0(X) + Δ·m(X) − q·r0(X) − (X^N + 1)·q0(X)   ∈ Z[X].
```
Write `D(X) = Σ_i d_i X^i`, `d_i ∈ Z`. Because `ι` commutes with ring operations modulo `p`
(`Z → F_p` is a ring homomorphism and each `ι(coeff) ≡ coeff (mod p)`), the field value the circuit
computes equals `Σ_i (d_i mod p) γ^i`. Hence:

> The circuit assertion is exactly **`Σ_i d_i γ^i ≡ 0 (mod p)`**.

(The same construction gives `D` for SK encryption, `D = a·u_s … `, i.e. `a·s − Δm − e + c0 + q·r −
(X^N+1)·q_as`, and for the second PK relation. Each is a separate polynomial bounded identically.)

## 3. The lemma

> **Lemma (no wraparound).** Under the range checks of §1, every coefficient of the difference
> polynomial satisfies `|d_i| < 2⁴² < p/2`. Consequently, if `d_i ≡ 0 (mod p)` for all `i`, then
> `d_i = 0` in `Z` for all `i`, i.e. `D(X) = 0` over `Z[X]`.

**Proof.** Bound `‖D‖∞ = max_i |d_i|` by the triangle inequality over the six summands of `D`, using
the per-coefficient bounds of §1. For two polynomials of degree `< N`, each product coefficient is a
sum of at most `N` terms, so `‖f·g‖∞ ≤ N·‖f‖∞·‖g‖∞`.

| summand | bound on `‖·‖∞` | value (`N ≤ 4096`) |
|---|---|---|
| `pk0·u` | `N · ‖pk0‖∞ · ‖u‖∞ ≤ 2¹² · 2²⁷ · 1` | `≤ 2³⁹` |
| `c0` | `< 2²⁷` | `< 2²⁷` |
| `e0` | `≤ 19` | `< 2⁵` |
| `Δ·m` | `< 2¹¹ · 2¹⁷` | `< 2²⁸` |
| `q·r0` | `< 2²⁷ · 2¹³` | `< 2⁴⁰` |
| `(X^N+1)·q0` | `= ‖q0‖∞` (∗) | `≤ 2⁴⁰` |

(∗) `(X^N+1)·q0 = q0(X) + X^N·q0(X)`. The two shifted copies occupy disjoint degree ranges
(`0 … deg q0` and `N … N+deg q0`, which never overlap because `deg q0 < N`), so the sup-norm is just
`‖q0‖∞`, with no doubling. Summing,
```
‖D‖∞ < 2⁴⁰ + 2⁴⁰ + 2³⁹ + 2²⁸ + 2²⁷ + 2⁵ < 2⁴².
```
Since `2⁴² < 2²⁵² < p/2`, each `d_i` lies in `(−p/2, p/2)`. The only integer in that interval divisible
by `p` is `0`; hence `d_i ≡ 0 (mod p)` forces `d_i = 0`. ∎

The bound is loose by design (the two dominant terms `q·r0` and `(X^N+1)·q0` are each just under `2⁴⁰`;
the exact worst case over `N ≤ 4096` is `‖D‖∞ ≤ 2⁴¹·³²`). The margin to `p/2` exceeds **2²¹⁰** — there
is no realistic parameter regime in which wraparound occurs. Machine-checked, including a sign-aligned
adversarial worst case, in [`tools/no_wraparound_check.py`](../tools/no_wraparound_check.py).

## 4. Soundness chain (where the lemma sits)

For a complete picture, the lemma is step (iii) of:

1. **(i)** The circuit asserts `Σ_i d_i γ^i ≡ 0 (mod p)` at the Fiat–Shamir challenge `γ` (§2).
2. **(ii)** *Schwartz–Zippel / Fiat–Shamir* (security.md §2, §4; soundness error `≤ (2N−1)/p` per
   challenge, in the ROM): except with negligible probability, this forces the **polynomial** identity
   `D̄ ≡ 0` over `F_p[X]`, i.e. `d_i ≡ 0 (mod p)` for every `i`.
3. **(iii)** *No-wraparound lemma (this note):* `|d_i| < p/2` then upgrades `d_i ≡ 0 (mod p)` to
   `d_i = 0` over `Z`, so `D(X) = 0` in `Z[X]`.
4. **(iv)** `D = 0` over `Z[X]` is the exact integer identity `pk0·u = c0 − e0 − Δm + q·r0 +
   (X^N+1)·q0`. Reducing mod `(X^N+1)` then mod `q` yields `c0 = [pk0·u + e0 + Δm]_q`; together with the
   range checks (`u` ternary, `‖e0‖∞ ≤ B`, `m ∈ [0,t)`) this is precisely well-formed PK-BFV
   encryption. (Symmetrically for relation 1 and for SK encryption.)

**Remark (high quotient coefficient).** The witness array `q0` has length `N`, so a prover may set the
top coefficient `q0_{N-1}` that the honest quotient leaves zero. This does not affect the lemma (the
disjoint-support argument and the bound are unchanged), and step (iv) forces it to zero anyway: the
degree-`(2N-1)` coefficient of `D` equals `−q0_{N-1}`, so `D = 0` requires `q0_{N-1} = 0`.

## 5. Scope: unconditional vs. conditional

- **Digest variants (`verify_*_encryption_digest`): unconditional.** `pk0,pk1,c0,c1` are *private*
  witnesses and are range-checked to 27 bits in-circuit, so the table of §1 binds **every** prover.
  The lemma holds for all adversaries. (This is exactly why the digest circuits range-check the
  ciphertext/key — the checks are load-bearing for soundness, not only for injective digest packing.)
- **Plain / packed variants: conditional on honest public inputs.** There `pk0,pk1,c0,c1` are public
  inputs and are *not* range-checked in-circuit. The lemma still holds **provided the verifier supplies
  ciphertext/key coefficients in `[0, q)`** (which an honest verifier does — it is verifying its own,
  reduced ciphertext). With the tighter per-`N` quotient bounds those circuits use
  (`|r| < 2¹¹`, `|q_as| < 2³⁸`), the same computation gives an even smaller `‖D‖∞ < 2⁴⁰`. A prover
  cannot violate the bound because it does not control the public inputs; but a careless verifier that
  passed an out-of-range public ciphertext would void the guarantee — another reason to prefer the
  digest variant, where the bound is enforced for everyone.

## 6. What this does and does not establish

This note discharges security.md §8 **obligation 1** (the no-wraparound bound) and supplies step (iv)
(exact-relation soundness). It does **not** by itself establish: the probabilistic step (ii) as a
formal Fiat–Shamir reduction (obligation 3), knowledge soundness / witness extraction (obligation 2),
zero-knowledge (obligation 4), or public-key well-formedness (obligation 5). Those remain open.
