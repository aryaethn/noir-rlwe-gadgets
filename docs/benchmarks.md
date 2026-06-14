# Benchmarks

The full, measured benchmark tables — gates, prove time (median-of-3), prove RAM, on-chain gas, plus
a provenance note on exactly how each number was obtained — live in **[../BENCHMARKS.md](../BENCHMARKS.md)**.

Summary (M2 Air 8 GB; nargo 1.0.0-beta.22 / bb 5.0.0-nightly.20260522; preset `bfv_1024_27`,
single-digest variant):

| Circuit | N | Gates | Prove (s) | Prove RAM | On-chain gas | Public inputs |
|---|---|---|---|---|---|---|
| SK encryption | 1024 | 48,270 | 0.65 | 108 MB | 2,449,156 | 1 |
| SK encryption | 4096 | 179,338 | 2.77 | 338 MB | 2,572,208 | 1 |
| **PK encryption** | 512 | 42,704 | 0.54 | 93 MB | 2,449,156 | 1 |
| **PK encryption** | 1024 | 80,262 | 0.89 | 184 MB | 2,510,660 | 1 |

Every circuit stays far under the 2¹⁹-gate design ceiling and the 8 GB target; on-chain gas is nearly
flat across `N` because the digest variant exposes a single public input. See
[../BENCHMARKS.md](../BENCHMARKS.md) for the optimization progression (5.2× from packed Fiat-Shamir,
2.35× gas from the single digest) and the Greco comparison.
