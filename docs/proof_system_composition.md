# Proof-system composition

How the library's in-circuit Schwartz–Zippel argument composes with the UltraHonk proof system to give
a deployed **non-interactive zero-knowledge argument of knowledge** of a valid BFV encryption witness.
This note collapses three security.md §8 obligations that are really one question:

- **#3 (Fiat–Shamir in the ROM)** — proven here in full;
- **#2 (knowledge soundness / extraction)** — reduced here to UltraHonk's knowledge soundness;
- **#4 residual (zero-knowledge)** — reduced here to UltraHonk's ZK property.

> **UNAUDITED RESEARCH.** This note proves the *circuit-level* facts and the *composition*. It does
> **not** re-prove UltraHonk itself; that is cited as a standard primitive under stated idealized models.

## 1. The two layers (and why they don't conflate)

There are two distinct Fiat–Shamir hashes, and the whole analysis turns on keeping them apart.

**Layer 1 — the in-circuit challenge `γ`.** `γ = Poseidon2(packed witness)` is computed *inside* the
circuit ([`pk_witness_subdigests`](../noir-rlwe/src/proofs/pk_encryption.nr) + a final hash; in the
digest variant `γ` also folds in the public `(pk,c)` sub-digests, audit ZK-01) and used in the
Schwartz–Zippel identity assertions. It is **part of the relation the circuit defines** — a deterministic function of
the witness wires, not a protocol message. It is an internal wire: never a public input or output.

**Layer 2 — the UltraHonk transcript.** UltraHonk is a SNARK for satisfiability of that circuit. It has
its *own* Fiat–Shamir transcript (commit to witness polynomials, then squeeze challenges for the
permutation/lookup/sumcheck arguments and the PCS openings). This is the protocol's randomness and is
unrelated to `γ`.

Define two relations. Public input `x` is the returned digest (digest variant); witness
`w = (pk0,pk1,c0,c1,u,e0,e1,m,r0,r1,q0,q1)`.

- **`R_circuit(x; w)`** — what the circuit actually checks: (i) all range checks of
  [no_wraparound.md](no_wraparound.md) §1; (ii) `γ = Poseidon2(pack(w_witness))`; (iii) the two
  Schwartz–Zippel identities `D₀(γ)=0`, `D₁(γ)=0`; (iv) `x = Poseidon2(pack(pk0)‖…‖pack(c1))`.
- **`R_BFV(x; w)`** — the real statement: `(pk0,pk1,c0,c1)` is a well-formed public-key BFV encryption
  of `m∈[0,t)` under ternary `u` and bounded `e0,e1`, and `x` is its digest.

The circuit only checks the identities at the *single* point `γ`, so `R_circuit` is weaker than
`R_BFV`. Layer 1 (this note, §3) bridges the gap; Layer 2 (§4) turns "exists" into "knows".

## 2. Model and assumptions

We work in the **algebraic group model (AGM) + random-oracle model (ROM)**, the standard setting for
KZG-based SNARKs. We assume, citing Barretenberg:

- **(UH-KS)** UltraHonk is knowledge-sound: an efficient extractor `E` outputs a satisfying assignment
  to `R_circuit` from any prover producing accepting proofs with non-negligible probability, with
  soundness error `ε_UH` (negligible under KZG/BN254 in the AGM+ROM).
- **(UH-ZK)** the ZK flavor (verified on — security.md §7) is zero-knowledge: a simulator produces
  proofs indistinguishable from real ones given only the public I/O.
- **(RO)** the in-circuit Poseidon2 and UltraHonk's transcript hash are modelled as random oracles, and
  are **independent** (domain-separated or distinct functions) — see §6.

`p` is the BN254 scalar prime (`2²⁵³ < p < 2²⁵⁴`); `N` the ring degree.

## 3. Lemma (Layer 1 soundness — discharges obligation #3)

> **Lemma.** Model the in-circuit Poseidon2 as a random oracle `H`. For any prover making at most `Q`
> queries to `H`, the probability that it outputs `(x, w)` with `R_circuit(x; w)` satisfied but
> `R_BFV(x; w)` false is at most `Q·(2N−1)/p`.

**Proof.** Fix `w`. Let `Dᵢ` be the difference polynomial of identity `i` built from `w` (the integer
polynomial of [no_wraparound.md](no_wraparound.md) §2). Suppose `R_BFV` is false. Then by the
no-wraparound lemma (no_wraparound.md §3) at least one `Dᵢ ≠ 0` over `F_p[X]`: if both `D₀ ≡ D₁ ≡ 0`
over `F_p[X]`, the bound `‖Dᵢ‖∞ < p/2` would force `Dᵢ = 0` over `Z`, i.e. the exact BFV relation —
contradicting falsity. Take such a nonzero `Dᵢ`, of degree `≤ 2N−1`, hence with at most `2N−1` roots
in `F_p`.

The circuit accepts only if `Dᵢ(γ) = 0` with `γ = H(w)`. For each distinct `w` the prover tries, `H(w)`
is a fresh uniform point, so `Pr_H[Dᵢ(H(w)) = 0] ≤ (2N−1)/p`. (Crucially, `γ` binds the *entire*
witness — ADR-009 — so a prover cannot fix `γ` and then choose `w`; changing `w` to chase a root
re-randomizes `γ` through `H`. The only attack is to grind `w`.) Union-bounding over `≤ Q` queries
gives `Q·(2N−1)/p`. ∎

For `N = 1024`, `(2N−1)/p ≈ 2⁻²⁴³`; even `Q = 2¹²⁸` gives `≤ 2⁻¹¹⁵`. This is the step that amplifies a
single-point check into a polynomial identity — it is **not** subsumed by UH-KS, which only certifies
that the one-point circuit is satisfied.

## 4. Theorem (knowledge soundness — discharges obligation #2 modulo UH-KS)

> **Theorem.** Under (UH-KS) and the ROM, the deployed proof is an argument of knowledge of a witness
> `w` with `R_BFV(x; w)`, with soundness error `≤ ε_UH + Q·(2N−1)/p`.

**Proof.** Run the UH-KS extractor `E` on a successful prover to obtain, except with probability
`ε_UH`, an assignment `w*` satisfying `R_circuit(x; w*)`. By the Lemma (§3), except with probability
`Q·(2N−1)/p` over the in-circuit RO, any such `w*` satisfies `R_BFV(x; w*)`. Union bound. ∎

So extraction yields exactly the lattice witness `(u, e0, e1, m)` (and the quotients) of a genuine
encryption. The composition is clean because `γ` is part of the extracted assignment, and §3's
argument is over the *relation* (the RO), independent of the extraction. The remaining gap is **(UH-KS)
itself**, which this library cites rather than re-proves — the same status as any application built on
a SNARK.

## 5. Theorem (zero-knowledge — discharges obligation #4 residual modulo UH-ZK)

> **Theorem.** Under (UH-ZK), the proof reveals nothing about `w` beyond the public output `x`. With
> the digest variant, `x` is the only public value, and witness confidentiality reduces to IND-CPA of
> BFV.

**Proof sketch.** By (UH-ZK) the simulator reproduces the proof from `x` alone, so the proof leaks
nothing beyond `x`. In the digest circuit the only public value is `x = digest`; in particular `γ` and
all of `(pk,c,u,e,m,r,q)` are internal wires covered by ZK. `x = Poseidon2(pack(pk)‖pack(c))` is a
deterministic hash of `(pk, c)` — it is not a hiding commitment, but it is a hash of a high-entropy
ciphertext that the relying party already holds (security.md §6), so it reveals nothing beyond `(pk,c)`.
Finally `(pk,c)` computationally hides `(m,u,e)` iff BFV is IND-CPA, which holds under RLWE for
`bfv_1024_27` (~126-bit, [parameter_security.md](parameter_security.md)) and **fails** for
`bfv_1024_55`. ∎

(The plain/packed variants expose `(pk,c)` directly as public inputs rather than via the digest; the
same reduction applies, with `(pk,c)` as the public value.)

## 6. The domain-separation condition (a real prerequisite)

§3 and the SNARK both model Poseidon2 as a random oracle. For the analysis to be sound these uses must
be **independent**:

- **EVM path (`-t evm`): satisfied for free.** UltraHonk's transcript uses **keccak** there, a
  different function from the in-circuit **Poseidon2** — trivially independent.
- **Native path (`-t` default, poseidon2 transcript): a condition to verify.** Both the in-circuit `γ`
  and the protocol transcript use Poseidon2. Independence then requires **domain separation** (distinct
  capacity/domain tags or input framing) between the two uses. This is standard in bb's transcript, but
  the library has not audited it. **Open verification item:** confirm bb's transcript Poseidon2 is
  domain-separated from a raw `Poseidon2::hash` over field elements, or use the EVM/keccak path (or a
  distinct in-circuit hash) when this matters.

There is no circularity in timing: `γ` is a function of the *committed* witness, fixed before the
protocol squeezes any transcript challenge, so the protocol challenges cannot influence `γ`.

## 7. What is proven here vs. delegated

| obligation | status after this note |
|---|---|
| #3 Fiat–Shamir / Schwartz–Zippel in the ROM | **Proven** (§3), error `Q·(2N−1)/p`, subject to §6 |
| #2 knowledge soundness | **Reduced** to (UH-KS): composition proven (§4); UltraHonk cited, not re-proved |
| #4 residual zero-knowledge | **Reduced** to (UH-ZK) + IND-CPA: composition argued (§5); UltraHonk cited |

Net: the deployed artifact is a **zk-SNARK of knowledge of a well-formed BFV encryption**, with
soundness error `≤ ε_UH + Q·(2N−1)/p` and witness confidentiality under RLWE (`bfv_1024_27`), in the
AGM+ROM, **assuming** UltraHonk's standard guarantees and the §6 domain-separation condition. The only
items this note leaves genuinely open are (a) the §6 native-path domain-separation check (a concrete,
answerable engineering question) and (b) trusting UltraHonk's KS/ZK — which no application built on a
SNARK avoids. The remaining standalone obligation is #5 (public-key well-formedness), a trust-boundary
scoping decision treated in security.md §6.
