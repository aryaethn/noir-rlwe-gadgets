# Security

> ⚠️ **UNAUDITED RESEARCH.** This library has not undergone any professional security audit. It is
> published to support research and review, **not** production use. No security guarantees are made
> until an audit is completed. Do not use it to protect anything of value.

This document states precisely what the circuits prove, the soundness argument and its parameters, the
gap between soundness and knowledge soundness, and the operational requirements a deploying application
must satisfy. Claims are labelled **Fact** (provable / cited), **Estimate**, or **Open question** per
the project's precision convention.

## 1. What is proven

The circuits prove **well-formedness of a BFV ciphertext**: knowledge of witnesses
`(s/u, e, m, quotients)` such that the public ciphertext is a correct encryption of a message
`m ∈ [0,t)` under a ternary key/randomness and a bounded error `‖e‖∞ ≤ B`, over `R_q = Z_q[X]/(X^N+1)`.
This is the Greco statement ([ePrint 2024/594](https://eprint.iacr.org/2024/594)) for `sk_encryption`,
and its public-key analogue for `pk_encryption`.

**Not** in scope (these are separate concerns, not provided here):

- **IND-CPA security of BFV** itself — that is a property of the *scheme and parameters*, established
  by lattice cryptanalysis. The library proves *correctness of an encryption*, not the hardness of
  RLWE. The shipped presets are validated separately in
  [parameter_security.md](parameter_security.md): **`bfv_1024_27` is ~126-bit (OK); `bfv_1024_55` is
  only ~63-bit at `n=1024` and must NOT be used for real encryption.**
- A secure **encryptor**. The Rust `witness-gen` is a *toy*: it uses a non-cryptographic PRNG
  (splitmix64), is not constant-time, and targets the circuit's toy parameters. It must not be used to
  encrypt real secrets.
- **Decryptability / noise budget.** The circuit proves the encryption *relation* (well-formedness),
  not that the ciphertext decrypts. An independent reference-decryption check
  (`tools/decrypt_validation.py`) confirms **SK** ciphertexts at the q27 preset decrypt correctly
  (20/20, noise `|e|≤19 ≪ Δ/2=1023`) — a faithful BFV — but **PK** ciphertexts at the same preset do
  **not** reliably decrypt (0/20): the fresh public-key noise `⟨e_key·u⟩+e0+⟨e1·s_key⟩` is a ring
  convolution reaching `≈ Δ/2`, exceeding the budget because `t=65537` makes `Δ=⌊q/t⌋=2047` small. The
  proof is unaffected (decryptability is out of scope), but a *usable* PK-FHE deployment needs more
  noise budget (smaller `t` / larger `Δ`, or larger `n,q`). The demo PK parameters are a
  well-formedness benchmark, not a decryptable scheme.

## 2. Random-evaluation soundness (the Schwartz-Zippel core)

**Fact.** The product check verifies `f·g = h + (X^N+1)·k` over `Z[X]` by evaluating both sides at one
challenge `γ`. If the polynomial identity is false, the two sides differ by a nonzero polynomial of
degree `≤ 2N-2`, which has at most `2N-2` roots in the field. For `γ` uniform over the BN254 scalar
field `F_p` (`p ≈ 2²⁵⁴`), the check passes erroneously with probability `≤ (2N-2)/p`.

**Estimate (parameter).** At `N = 1024`, `(2N-2)/p ≈ 2¹¹/2²⁵⁴ ≈ 2⁻²⁴³` — negligible, and far inside a
128-bit margin even after Fiat-Shamir. (Contrast a mod-`q` challenge, which would give only `~1/q ≈
2⁻²⁷`; the library deliberately draws `γ` over the **full field**, not mod `q`.)

## 3. Quotient bounds prevent field wraparound (soundness-critical)

**Fact.** The mod-`q` reduction is carried by a quotient polynomial `r` (and `r0,r1` for PK). Field
arithmetic is mod `p`, and `q` is invertible mod `p`; without a bound on `r`, a malicious prover could
choose an enormous `r` to satisfy a false identity that "wraps around" mod `p`. The circuit therefore
range-checks every quotient coefficient:

- `|r|, |r0|, |r1| ≤ N+2 < 2¹³`  (uniform bound, valid for `N ≤ 4096`);
- `|q_as|, |q0|, |q1| ≤ (N-1)·q < 2⁴⁰`.

**Proven (completeness).** The bounds are satisfied by *every* genuine encryption, not just typical
ones: [completeness.md](completeness.md) proves the analytic worst case `‖q‖∞ ≤ (N−1)(q−1) < 2³⁹` and
`‖r‖∞ ≤ N+2 < 2¹³` for all `N ≤ 4096` and any inputs in the declared ranges (both bounds tight). So the
circuit accepts every honest witness. For the PK circuit the bounds are *identical* to the SK circuit
because `pk0,pk1` are reduced-mod-`q` (`|coeff| < q`) exactly like `a`.

**Proven.** That these bounds actually *prevent* wraparound — i.e. the single-point `F_p` check forces
the exact identity over `Z` — is established in [no_wraparound.md](no_wraparound.md): under the range
checks, every coefficient of the difference polynomial satisfies `‖D‖∞ < 2⁴² < p/2` (margin > 2²¹⁰),
so `D ≡ 0 (mod p)` ⟹ `D = 0` over `Z`. Machine-checked in `tools/no_wraparound_check.py`.

> Increasing `N` beyond 4096 requires revisiting the shifts/pack-widths: `|r| ≤ N+2 < 2¹³` needs
> `N < 8190`.

## 4. Fiat-Shamir and witness binding

**Fact / design (ADR-009).** The challenge `γ` is derived by Poseidon2 (over BN254) from the circuit's
polynomials, including the **witness** polynomials — not only the public inputs. If `γ` depended only
on public data, a prover who learns `γ` in advance could craft a witness satisfying a false identity at
that single point. Binding the witnesses makes `γ = H(witness)`, so altering the witness changes `γ`;
forging then requires a Poseidon2 collision/fixpoint.

**Proven.** [proof_system_composition.md](proof_system_composition.md) §3 makes this rigorous: in the
ROM, a prover making `Q` queries forges a satisfying-but-false witness with probability `≤ Q·(2N−1)/p`.
The challenge binding the *whole* witness is what reduces the attack to grinding. Subject to the
in-circuit-vs-protocol hash domain-separation condition (that note §6).

## 5. Knowledge soundness — status and boundary

**The boundary.** The *circuit* enforces the encryption relation soundly (§2–§4): any satisfying
assignment is a genuine well-formed ciphertext + witness, except with the negligible random-evaluation
error. Turning "a satisfying assignment exists" into "the prover *knows* the witness" — knowledge
soundness / extractability — is provided by the **proof system**, UltraHonk, whose knowledge soundness
rests on its polynomial commitment scheme over BN254 (in the AGM / ROM). The composition is written out
in [proof_system_composition.md](proof_system_composition.md) §4: extraction yields a circuit-satisfying
assignment, which §3 (the ROM argument) certifies is the lattice witness of a genuine encryption, with
total error `≤ ε_UH + Q·(2N−1)/p`. This library does not re-prove UltraHonk's extractability; it cites
and composes with it.

**Open question.** The general lattice-SNARK literature flags that knowledge soundness for some
constructions is only attainable in relaxed/idealized models (rewinding, AROM/osROM/EAGM). That caveat
concerns *lattice-based* argument systems (LaBRADOR, LatticeFold, …) that a future vFHE composition
might use; it does **not** apply to the UltraHonk path used here, whose extractor is standard. It is
documented because the project's research axis (verifiable FHE via lattice SNARKs) will eventually
touch it. The composition itself is a proof obligation — see §8.

## 6. Trust boundary: public-key binding and well-formedness

The PK circuit proves the ciphertext is a valid encryption **under whatever `pk` it is given**; it does
not prove `pk` is itself a well-formed public key. The deployment closes this with two requirements —
one cryptographic (T2, enforced by the relying party) and one a trust assumption (T1, established at key
registration). This is **obligation 5 (§8), resolved by scoping** (the chosen path; an alternative is a
companion well-formedness proof — see "When the assumption is not acceptable" below).

**T2 — digest binding (cryptographic, the relying party's job).** The single-digest variants make
`pk0,pk1,c0,c1` *private* and expose only `digest = H(pack(pk0)‖pack(pk1)‖pack(c0)‖pack(c1))` (PK) or
`H(pack(c0)‖pack(c1))` (SK). The proof asserts only that *some* values with that digest form a valid
encryption, so the consuming application **must** bind the digest to the values it trusts:

```
accept(proof, ciphertext) := HonkVerifier.verify(proof, [ H(registered_pk ‖ ciphertext) ])
```

If this off-circuit check is skipped, a prover could present a proof for a public key **they** control.
The circuit range-checks `pk0,pk1,c0,c1` to 27 bits before hashing so the binding is injective (else a
distinct colliding ciphertext could be substituted). See [end_to_end.md](end_to_end.md) §"Binding the
digest".

**T1 — public-key well-formedness (trust assumption, established at registration).** Security further
requires `registered_pk` to be a *well-formed* public key — `pk = (-a·s_key + e_key, a)` for a properly
sampled ternary `s_key` and bounded `e_key` — established **out-of-band, once, at key registration**, by
the recipient (single-key) or a distributed key-generation ceremony (threshold). It is **not** proven
per encryption, and indeed **cannot** be: only the secret-key holder can prove well-formedness of `pk`
(it needs `s_key`), and the input submitter does not hold `s_key`.

*Why this is the right model, not a cop-out.* The public key belongs to the **decrypting** party, who is
precisely the party that *wants* correct decryption; a malformed key only harms them. The "malicious
`pk`" case is a threat the key-owner would pose to *themselves*, which is not a meaningful adversary for
input validity. This matches every production FHE-coprocessor deployment (Zama fhEVM, threshold-FHE
rollups): the FHE key is a published system parameter from a one-time trusted/threshold ceremony, and
no per-input key-well-formedness proof exists. For threshold keys, well-formedness is an output of the
DKG protocol itself — so the trust-assumption framing is the *only* applicable one there.

*The honest boundary — what T1 does not cover.* If a single adversary controls **both** key
registration **and** encryption against a third party relying on the proof, it can register a malformed
`pk` and prove "valid encryption under it"; the guarantee is then only as strong as the pk-registration
trust. T1 also does not certify the *secrecy* of `s_key` (operational security of the key-holder), only
the structural well-formedness the relation needs.

*When the assumption is not acceptable.* For a single-holder key in an adversarial-registrar setting,
the assumption can be **removed** with a companion proof: the key-holder proves once, at registration,
that `pk` is a valid RLWE sample (ternary `s_key`, bounded `e_key`) — structurally the SK relation
applied to the key, reusing the same Schwartz–Zippel gadgets. (Not implemented; it is the
[Roadmap](../README.md#roadmap) upgrade path. It does not apply to threshold/DKG keys.)

*Optional hardening (defense-in-depth, not a substitute for T1).* The circuit could cheaply reject the
most degenerate malformations (`pk0 = 0`, `pk1 = 0`) in-circuit per input. This rules out trivial
footguns only; it does not establish well-formedness.

**Open question.** Posting the ciphertext in an EIP-4844 blob for data availability and binding the
blob *on-chain* (rather than off-chain) requires a point-evaluation precompile and a cross-field
argument (BLS12-381 blob commitment vs BN254 SNARK) — unresolved research (see §8).

## 7. Zero-knowledge

**Fact (the ZK flavor is on — verified empirically).** Every proving path used here is the ZK UltraHonk
variant, *not* only the EVM verifier. In bb 5.0, ZK is selected by `--verifier_target`: the on-chain
path uses `-t evm` (= "keccak, ZK"), and the **default native `bb prove`** (the one the benchmarks
measure) is also ZK. Confirmed: the native proof is **randomized across runs** (necessary for ZK) and is
**14,656 bytes**, vs **13,120 bytes** with `--disable_zk` — the 1,536-byte difference is the ZK masking.
So the proof contains the blinding that makes it simulatable; **do not pass `--disable_zk`** (or a
`*-no-zk` target) if witness privacy matters.

**Argued (the privacy reduction).** Given the ZK property of UltraHonk (delegated to the proof system,
like knowledge soundness — §5, §8 obligation 2), a proof reveals nothing about the witness *beyond the
public input/output*. The only public value is the ciphertext/key digest (digest variant) or the
ciphertext/key themselves (plain/packed variant). Hence privacy of the message/randomness reduces to:

> *the public output reveals at most the ciphertext, and the ciphertext computationally hides
> `(m, u, e0, e1)` — i.e. IND-CPA of BFV.*

IND-CPA holds under RLWE for the secure preset (`bfv_1024_27`, ~126-bit — §1,
[parameter_security.md](parameter_security.md)); it does **not** for `bfv_1024_55`. The digest itself is
a deterministic Poseidon2 hash (not a hiding commitment), but it is a hash of a high-entropy ciphertext
and the relying party is given that ciphertext by construction, so it leaks nothing beyond it. **Net:
witness privacy is sound for `bfv_1024_27` under RLWE, contingent on the ZK flavor (verified on) and the
delegated UltraHonk ZK property (obligation 2's sibling).**

## 8. Proof obligations — what is NOT yet proven

The properties below are *argued* (sketched, empirically checked, or delegated to the proof system)
but are **not** yet backed by a written, reviewed proof. Each is a concrete obligation a security
review or production deployment must close. They are listed in rough order of how load-bearing they
are. Nothing here is known to be false; the point is that the absence of a proof is itself a risk.

1. **No-wraparound soundness lemma (load-bearing). — DISCHARGED.** Proven in
   [no_wraparound.md](no_wraparound.md): under the enforced range checks, every coefficient of the
   difference polynomial `D(X) = LHS(X) − RHS(X)` satisfies `‖D‖∞ < 2⁴² < p/2` (margin > 2²¹⁰), so
   `D ≡ 0 (mod p)` coefficient-wise implies `D = 0` over `Z`, hence the exact integer relation. The
   note also supplies step (iv) of the chain (exact relation ⟹ well-formed encryption). For the digest
   circuits the bound is unconditional (the ciphertext/key are range-checked in-circuit); for the
   plain/packed circuits it is conditional on the verifier supplying public inputs in `[0,q)`.
   Machine-checked, incl. a sign-aligned adversarial worst case, in `tools/no_wraparound_check.py`.

2. **Knowledge soundness / extraction. — REDUCED to UltraHonk.** [proof_system_composition.md](proof_system_composition.md)
   §4 proves the composition: UltraHonk's knowledge-soundness extractor yields a circuit-satisfying
   assignment, which (by §3/obligation 1) *is* the lattice witness `(u, e, m)` of a genuine encryption,
   with total error `≤ ε_UH + Q·(2N−1)/p`. **Residual:** UltraHonk's own knowledge soundness (cited
   under KZG/BN254 in the AGM+ROM), which no SNARK-based application re-proves.

3. **Fiat–Shamir / Schwartz–Zippel in the ROM. — DISCHARGED.** [proof_system_composition.md](proof_system_composition.md)
   §3 proves that the in-circuit `γ = Poseidon2(witness)` is a sound challenge: a prover making `Q` RO
   queries forges a satisfying-but-false witness with probability `≤ Q·(2N−1)/p` (`≈ Q·2⁻²⁴³` at
   `N=1024`). This is the step that amplifies the single-point check to a polynomial identity — *not*
   covered by UltraHonk KS. Subject to the domain-separation condition of §6 there (free on the EVM
   path; a verification item on the native poseidon2 path).

4. **Zero-knowledge. — VERIFIED + REDUCED.** (a) *Verified:* the ZK flavor is on for both the native
   and EVM proving paths (default `bb prove` is randomized + carries 1,536 bytes of masking vs
   `--disable_zk`; `-t evm` is "keccak, ZK") — §7; the worry that native proofs might be non-ZK is
   **disproved**. (b) *Reduced:* [proof_system_composition.md](proof_system_composition.md) §5 shows
   witness confidentiality follows from UltraHonk ZK (only public value is the digest; `γ` and the
   ciphertext/key are internal wires) plus IND-CPA of BFV (holds for `bfv_1024_27`, fails for
   `bfv_1024_55`). **Residual:** UltraHonk's ZK property, cited like #2. Operational requirement: never
   use `--disable_zk`.

5. **Public-key well-formedness. — RESOLVED (by scoping; §6).** The PK circuit cannot prove `pk` is a
   real public key (that needs `s_key`, which the input submitter does not hold). The trust boundary is
   now stated precisely in §6: T2 (the relying party cryptographically binds the digest to the
   registered `pk` — enforced) plus T1 (the registered `pk` is well-formed, established once at key
   registration by the recipient or a DKG ceremony — a trust assumption that matches every production
   FHE-coprocessor deployment, and the *only* applicable model for threshold keys). The honest limit
   (collusion of registrar + encryptor against a third party) and the single-key upgrade path (a
   companion well-formedness proof) are documented there.

6. **Honest-witness completeness of the quotient bounds. — DISCHARGED.** Proven in
   [completeness.md](completeness.md): for the unsigned `pk0 ∈ [0,q)` representation the generators use,
   `‖q‖∞ ≤ (N−1)(q−1) < 2³⁹` and `‖r‖∞ ≤ N+2 < 2¹³` for all `N ≤ 4096` and any inputs in the declared
   ranges (both tight), so the circuit accepts every genuine encryption. Together with obligation 1 the
   quotient windows are proven correct in both directions. Machine-checked in
   `tools/completeness_check.py`.

7. **Parameter (IND-CPA) security. — VALIDATED (with a finding).** [parameter_security.md](parameter_security.md)
   runs the lattice-estimator on both presets: **`bfv_1024_27` ≈ 126-bit** (at the 128-bit boundary,
   matches the HE standard) — OK; **`bfv_1024_55` ≈ 63-bit at `n=1024`** — insecure, now carrying a
   source-level warning and flagged as a circuit-arithmetic test vector only. (Validation, not a proof,
   but the missing security measure is now in place — and it caught a genuinely unsafe preset.)

8. **Digest binding/collision-resistance details (minor).** The injective-packing claim
   (`K·BITS ≤ 252 < 253`) and the fixed-order concatenation of the four sub-digests are argued; a
   complete binding proof would also state domain separation and rule out cross-grouping collisions.

Items 1, 3, and 6 are now **discharged** ([no_wraparound.md](no_wraparound.md),
[completeness.md](completeness.md), [proof_system_composition.md](proof_system_composition.md) §3) —
the quotient range checks are proven correct both directions, and the in-circuit Fiat–Shamir is given a
ROM reduction. Item 7 is **validated** ([parameter_security.md](parameter_security.md)) and caught an
insecure preset. Items 2 and 4 are **reduced** to UltraHonk's standard knowledge-soundness / ZK
guarantees via proven compositions (proof_system_composition.md §4–§5). Item 5 is **resolved by scoping**
— the public-key trust boundary is now stated precisely (§6). What remains: trusting UltraHonk itself
(items 2, 4 — which no SNARK-based application avoids), the one concrete §6 native-path hash
domain-separation **verification item** (free on the EVM/keccak path), and item 8 (a minor binding detail,
provable from material in hand). No load-bearing soundness gap remains unaddressed.

## 9. Reporting issues

This is research code. If you find a soundness bug or a problem with the analysis above, please open an
issue. Do not rely on this library for production security until it has been independently audited.
