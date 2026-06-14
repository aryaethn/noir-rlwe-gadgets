# Quotient-bound completeness lemma

A proof that the circuits **accept every genuine BFV encryption**: the quotient polynomials computed by
honest encryption always satisfy the range checks the circuit enforces. This is the completeness
companion to the [no-wraparound lemma](no_wraparound.md) (which proved *soundness* — that any witness
passing the checks forces the true relation). Together they show the enforced quotient windows are
neither too tight (completeness) nor too loose (soundness). Discharges security.md §8 obligation 6.

> **UNAUDITED RESEARCH.** The bounds below are worst-case over all inputs in the declared coefficient
> ranges, so they hold for any genuine encryption — not just statistically-typical ones.

## 1. Setup

An **honest witness** is the output of exact BFV encryption from inputs in the declared ranges, exactly
as the Rust/Python witness generators compute it. Using the unsigned reduced representation the
generators use — `pk0, pk1, a ∈ [0, q)`, `u, s ∈ {-1,0,1}`, `‖e‖∞ ≤ B`, `m ∈ [0, t)` — each ring
relation produces its quotients as follows (public-key relation 0; the others are identical in shape):

```
P        := pk0 · u            over Z[X],  deg ≤ 2N-2
(X^N+1)·q0 + ⟨P⟩ := P          negacyclic division:  q0 = quotient,  ⟨P⟩ = P mod (X^N+1),  deg ⟨P⟩ < N
raw      := ⟨P⟩ + Δ·m + e0     (the pre-reduction value)
c0       := raw mod q          ∈ [0, q)
r0       := (raw − c0) / q  =  ⌊raw / q⌋    (the mod-q quotient)
```

The circuit range-checks the prover-supplied `q0` and `r0` to the uniform windows (`N ≤ 4096`):
`|r0| < 2¹³` and `|q0| < 2⁴⁰`. Completeness requires the honest `q0, r0` to land inside them. (The
sampled witnesses `u, s, e, m` satisfy their own checks by construction — ternary, `‖e‖∞ ≤ B`,
`m ∈ [0,t)`; only the *derived* quotients need an argument.)

Constants: `q = 134215681 < 2²⁷`, `t = 65537`, `Δ = ⌊q/t⌋ = 2047`, `B = 19`, and `Δ(t−1) =
134152192 < q`.

## 2. The lemma

> **Lemma (quotient completeness).** For any `pk0 ∈ [0,q)^N`, `u ∈ {-1,0,1}^N`, `m ∈ [0,t)^N`,
> `‖e0‖∞ ≤ B`, the honest quotients satisfy, for all `N ≤ 4096`,
> ```
> ‖q0‖∞ ≤ (N−1)(q−1) < 2³⁹ ≤ 2⁴⁰      and      ‖r0‖∞ ≤ N + 2 ≤ 4098 < 2¹³.
> ```
> Hence every genuine encryption passes the circuit's quotient range checks. The same bounds hold for
> the second PK relation and for SK encryption.

**Proof.**

*Bounding the negacyclic quotient `q0`.* By the negacyclic-division formula, the quotient coefficients
are the high coefficients of the product: `q0[j] = P[N+j]` for `j = 0 … N−2` (and `q0[N−1] = 0`). Now
`P[N+j] = Σ_{i+k=N+j, 0≤i,k≤N−1} pk0[i]·u[k]` is a sum of exactly `N−1−j` products, each of magnitude
`|pk0[i]·u[k]| ≤ (q−1)·1`. Therefore
```
‖q0‖∞ = max_j |P[N+j]| ≤ (N−1)(q−1).
```
For `N ≤ 4096`: `(N−1)(q−1) ≤ 4095·134215680 = 549613209600 < 2³⁹ < 2⁴⁰`. ✔ inside the window.

*Bounding the mod-q quotient `r0`.* The negacyclic remainder is `⟨P⟩[j] = P[j] − P[N+j]`, with
`|P[j]| ≤ (j+1)(q−1)` and `|P[N+j]| ≤ (N−1−j)(q−1)`. Since `(j+1) + (N−1−j) = N`,
```
‖⟨P⟩‖∞ ≤ N(q−1).
```
Then `|raw[j]| ≤ ‖⟨P⟩‖∞ + Δ(t−1) + B ≤ N(q−1) + Δ(t−1) + B`, and since `r0[j] = ⌊raw[j]/q⌋` we have
`|r0[j]| ≤ |raw[j]|/q + 1`. Dividing termwise:
```
|r0[j]| ≤ N(q−1)/q + Δ(t−1)/q + B/q + 1  <  N + 1 + 0 + 1  =  N + 2,
```
using `(q−1)/q < 1`, `Δ(t−1) < q` (so that term is `< 1`), and `B < q`. For `N ≤ 4096`:
`‖r0‖∞ ≤ N+2 ≤ 4098 < 2¹³`. ✔ inside the window.

*Other relations.* PK relation 1 has `raw1 = ⟨pk1·u⟩ + e1` (no `Δm` term), giving the same `q1` bound
and an even smaller `‖r1‖∞ < N+1`. SK encryption uses `raw = ⟨−a·s⟩ + Δm + e` with `a ∈ [0,q)`,
`s` ternary; `|⟨−a·s⟩| = |⟨a·s⟩|`, so the identical bounds apply to `q_as` and `r`. ∎

Both bounds are **tight**: taking `pk0 ≡ q−1`, `u ≡ +1` gives `q0[0] = (N−1)(q−1)` exactly, and pushing
`m ≡ t−1`, `e ≡ B` drives `|r0|` up to `≈ N`. Machine-checked — analytic bounds for `N ≤ 4096` plus
random and sign-aligned-extreme witnesses — in [`tools/completeness_check.py`](../tools/completeness_check.py).

## 3. Why the windows are well-chosen (completeness ∧ soundness)

The two lemmas pin the enforced windows from both sides:

| quantity | honest worst case (completeness) | enforced window | soundness ceiling (no-wraparound) |
|---|---|---|---|
| `‖q‖∞` | `< 2³⁹` | `2⁴⁰` | keeps `‖D‖∞ < p/2`, i.e. up to `≈ 2²⁵²` |
| `‖r‖∞` | `≤ N+2 (< 2¹³)` | `2¹³` | same |

The window sits a factor `≈ 2` above the honest worst case (so completeness holds with margin) and
`> 2²¹⁰` below the soundness ceiling (so [no_wraparound.md](no_wraparound.md) holds with enormous
margin). Both lemmas are therefore simultaneously satisfied; the power-of-two windows `2⁴⁰` / `2¹³` are
the smallest that clear the honest worst case while staying trivially within the soundness bound.

> Validity is `N ≤ 4096`-bounded by the `r` window: `N + 2 < 2¹³` needs `N < 8190`. Larger `N` requires
> widening `R_SHIFT`/`LOG_R_RANGE` (and re-checking the no-wraparound margin, which has room to spare).

## 4. What this establishes

This discharges security.md §8 **obligation 6** (honest-witness completeness of the quotient bounds),
now as an analytic worst-case lemma for the unsigned `pk0 ∈ [0,q)` representation the generators use,
replacing the earlier empirical sweep. Combined with [no_wraparound.md](no_wraparound.md), the quotient
range checks are proven correct in both directions: **complete** (every genuine encryption is accepted)
and **sound** (every accepted witness forces the exact relation). It does not bear on the remaining
obligations (Fiat–Shamir reduction, knowledge soundness, zero-knowledge, public-key well-formedness,
parameter security) — see security.md §8.
