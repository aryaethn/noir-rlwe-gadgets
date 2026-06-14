# Parameter security (RLWE / IND-CPA)

The circuits prove *correctness* of a BFV encryption; they assume the underlying RLWE parameters are
hard. This note validates that assumption for the shipped presets with the
[lattice-estimator](https://github.com/malb/lattice-estimator), discharging security.md §8
obligation 7. **It surfaced a real problem with one preset — read §3.**

> **UNAUDITED RESEARCH.** These are concrete-hardness *estimates* from the standard tool; they are not
> a security proof, and estimator models evolve. Re-run before relying on any preset.

## 1. Method

- **Tool:** `malb/lattice-estimator` (commit `27a581b`, 2026-06-06), run under SageMath 10.7.
- **Instance:** each preset as an LWE problem with secret dimension `n`, modulus `q`, ternary secret
  `Xs = U{-1,0,1}`, and discrete-Gaussian error `Xe = DG(σ=3.2)` — matching the circuits' key/error
  distributions (`B_key = 1`, `σ = 3.2`, `B_err = 19 = 6σ`).
- **Security level** = `log₂(min rop)` over all attacks the estimator runs (usvp, bdd, dual,
  dual_hybrid, bkw, …); `rop` is the estimated classical cost of the best attack.
- **Reference:** the [Homomorphic Encryption Standard](https://homomorphicencryption.org/standard/)
  tables (themselves calibrated against this estimator) give, for ternary secret and 128-bit classical
  security, a maximum `log q` per `n`: `n=1024 → 27`, `n=2048 → 54`, `n=4096 → 109`.

## 2. Results

| preset | `n` | `log₂ q` | best attack | **security** | verdict |
|---|---|---|---|---|---|
| `bfv_1024_27` (MVP) | 1024 | 27 | dual_hybrid `2¹²⁶·²` | **≈ 126 bits** | OK — at the 128-bit boundary |
| `bfv_1024_55` | 1024 | 56 | bdd `2⁶²·⁷` | **≈ 63 bits** | **INSECURE — do not use for encryption** |

Per-attack costs (classical `rop`, `log₂`):

```
bfv_1024_27:  usvp 128.8 | bdd 127.0 | dual 131.9 | dual_hybrid 126.2 | bkw 234.3   -> min 126.2
bfv_1024_55:  usvp  63.4 | bdd  62.7 | dual  64.6 | dual_hybrid  64.0 | bkw 186.2   -> min  62.7
```

`bfv_1024_27`'s 126.2 bits matches the HE-standard `n=1024 / log q ≤ 27` entry (the ~2-bit shortfall is
within estimator/standard rounding) and reproduces Greco's 128-bit claim for the same parameter set.

## 3. Finding: `bfv_1024_55` is not secure at `n = 1024`

For a **fixed** dimension `n`, RLWE hardness *decreases* as `q` grows (the noise rate `α = σ/q`
shrinks, making the lattice easier). Raising `log q` from 27 to 56 at `n = 1024` halves the effective
hardness, dropping security from ~126 bits to **~63 bits** — comfortably breakable. The HE standard says
as much: `n = 1024` supports only `log q ≤ 27` for 128-bit security.

The preset was introduced for a "higher soundness margin," but **that rationale is obsolete**: the
Schwartz–Zippel challenge `γ` is drawn over the full BN254 field `F_p` (soundness `≈ 2N/p ≈ 2⁻²⁴³`,
[no_wraparound.md](no_wraparound.md), security.md §2), so the in-circuit soundness does **not** depend on
`q` at all. A larger `q` therefore buys the *proof* nothing while destroying the *encryption*'s security.

**Consequences / guidance:**

- **Use `bfv_1024_27` as the production preset.** It is ~128-bit and the default everywhere in the code.
- **Do not encrypt real data under `bfv_1024_55` at `n = 1024`.** A larger modulus only makes sense at a
  larger dimension — e.g. `n = 2048, log q ≤ 54` or `n = 4096, log q ≤ 109` return to ~128-bit (per the
  HE standard). The circuits are already generic over `N`, so the path is to pair a bigger `q` with a
  bigger `n`, not to bolt a 56-bit modulus onto `n = 1024`.
- The `bfv_1024_55` source now carries an explicit security warning. It remains useful only as a
  *circuit-arithmetic* test vector (exercising 56-bit-coefficient witnesses), never as a real
  encryption parameter set.

## 4. Caveats

- `rop` is the **classical** cost. Quantum cost (sieve square-root speedup) is lower; for the
  conservative core-SVP quantum model subtract roughly 10–25 bits. The 128-bit comparison above is
  classical, matching the HE standard.
- Estimates assume the standard distributions; a sparser/heavier secret would shift them. Re-run if you
  change `Xs`, `σ`, `n`, or `q`.
- This validates *parameter hardness only*. It says nothing about the proof system's soundness/ZK
  (security.md §2–§8) — those are separate obligations.

## 5. Reproduce

```bash
git clone https://github.com/malb/lattice-estimator /tmp/le && cd /tmp/le
sage -c '
from estimator import *
for n,q in [(1024,134215681),(1024,36028797018972161)]:
    p = LWE.Parameters(n=n, q=q, Xs=ND.Uniform(-1,1), Xe=ND.DiscreteGaussian(3.2))
    print(n, q, LWE.estimate(p))'
```
