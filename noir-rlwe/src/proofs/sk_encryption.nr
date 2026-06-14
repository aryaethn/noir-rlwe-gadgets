//! Proof of correct SK-BFV encryption (Greco-style), preset `bfv_1024_27`.
//!
//! Public:  c0, c1 (= a) in R_q.   Witness: s (ternary), e (|e|<=B), m (in [0,t)),
//! and the two Schwartz-Zippel quotient polynomials r, q_as.
//!
//! Proves knowledge of (s, e, m) with `c0 = [-a*s + Delta*m + e]_q` in R_q = Z_q[X]/(X^N+1),
//! via the exact integer-polynomial identity (derived & verified in Phase 2,
//! /tmp/bfv_identity.py; lab notebook 10.3):
//!
//!     a(X) s(X) = Delta*m(X) + e(X) - c0(X) - q*r(X) + (X^N + 1) * q_as(X)     over Z[X]
//!
//! checked at a single Fiat-Shamir challenge `gamma`. Soundness: random-evaluation error
//! ~ 2N/p; the quotient range checks prevent field wraparound (without them the prover could
//! exploit q's invertibility mod p). Knowledge soundness additionally needs the proof
//! system's witness commitments. UNAUDITED RESEARCH.

use crate::fiat_shamir::challenge::{derive_challenge, hash_packed};
use crate::params::bfv_1024_27::{
    B_ERR, DELTA, LOG_2BERR_P1, LOG_QAS_RANGE, LOG_R_RANGE, LOG_T, Q, QAS_SHIFT, R_SHIFT, T,
};
use crate::poly::horner::eval_at;
use crate::poly::product_check::pow_pow2;
use crate::range::signed::{assert_abs_le, assert_signed_pow2, assert_ternary_signed};
use crate::ring::RingElement;
use crate::util::assert_lt;
use poseidon::poseidon2::Poseidon2;

/// Generic over the ring degree N (and LOG_N = log2(N)); all other constants are shared by the
/// bfv_*_27 presets (same prime q27, same bounds -- the n=512 quotient bounds are looser, so the
/// n=1024 R_SHIFT/QAS_SHIFT are still valid). Instantiate as `verify_sk_encryption::<1024, 10>`
/// or `verify_sk_encryption::<512, 9>`.
pub fn verify_sk_encryption<let N: u32, let LOG_N: u32>(
    c0: [Field; N], // public
    c1: [Field; N], // public (= a)
    s: [Field; N], // witness: ternary secret key (signed)
    e: [Field; N], // witness: error, |e_i| <= B (signed)
    m: [Field; N], // witness: plaintext, m_i in [0, t)
    r: [Field; N], // witness: mod-q quotient (signed)
    q_as: [Field; N], // witness: (X^N+1) product quotient (signed)
) {
    // 1. Well-formedness range checks on the witness + quotient bounds.
    for i in 0..N {
        assert_ternary_signed(s[i]);
        assert_abs_le::<LOG_2BERR_P1>(e[i], B_ERR);
        assert_lt::<LOG_T>(m[i], T);
        assert_signed_pow2::<LOG_R_RANGE>(r[i], R_SHIFT);
        assert_signed_pow2::<LOG_QAS_RANGE>(q_as[i], QAS_SHIFT);
    }

    // 2. Fiat-Shamir challenge binding ALL polynomials, public and witness (ADR-009).
    let c0r: RingElement<N, Q> = RingElement::new(c0);
    let c1r: RingElement<N, Q> = RingElement::new(c1);
    let sr: RingElement<N, Q> = RingElement::new(s);
    let er: RingElement<N, Q> = RingElement::new(e);
    let mr: RingElement<N, Q> = RingElement::new(m);
    let rr: RingElement<N, Q> = RingElement::new(r);
    let qr: RingElement<N, Q> = RingElement::new(q_as);
    let gamma = derive_challenge([c0r, c1r, sr, er, mr, rr, qr]);

    // 3. Evaluate every polynomial at gamma and check the identity.
    let ag = eval_at(c1, gamma);
    let sg = eval_at(s, gamma);
    let mg = eval_at(m, gamma);
    let eg = eval_at(e, gamma);
    let c0g = eval_at(c0, gamma);
    let rg = eval_at(r, gamma);
    let qg = eval_at(q_as, gamma);
    let gn = pow_pow2::<LOG_N>(gamma);

    assert(ag * sg == DELTA * mg + eg - c0g - Q * rg + (gn + 1) * qg);
}

// --- packed Fiat-Shamir, GENERIC over N (optimization plan Part 1; ADR-011/012) ----------------
//
// Uniform quotient bounds valid for any N <= 4096: |r| <= N+2 < 2^13 and |q_as| <= (N-1)*q < 2^40.
// These are looser than the tight per-N bounds (e.g. n=1024 has |r| < 2^11) -- a few hundred gates
// of slack -- but they let one circuit serve every standard ring degree. Packing bit-widths follow:
// s:2, e:6, m:17, r:14, q_as:41, c0/c1:27, each with K*BITS <= 252 < 253 (injective, packed < p).

global R_SHIFT_U: Field = 8192; // 2^13  (|r| < 2^13 for N <= 4096)
global QAS_SHIFT_U: Field = 1099511627776; // 2^40  (|q_as| < 2^40 for N <= 4096)

/// Range-check the 5 witness polynomials and return their 5 bit-packed sub-digests. The caller folds
/// these (and, in the digest variant, the public sub-digests too) into gamma. Generic over N.
fn sk_witness_subdigests<let N: u32>(
    s: [Field; N],
    e: [Field; N],
    m: [Field; N],
    r: [Field; N],
    q_as: [Field; N],
) -> [Field; 5] {
    let mut s1 = [0; N];
    let mut e1 = [0; N];
    let mut r1 = [0; N];
    let mut q1 = [0; N];
    for i in 0..N {
        assert_ternary_signed(s[i]);
        assert_abs_le::<6>(e[i], B_ERR); // |e| <= 19, 2*19+1 = 39 < 2^6
        assert_lt::<17>(m[i], T); // m < t < 2^17
        assert_signed_pow2::<14>(r[i], R_SHIFT_U); // r + 2^13 < 2^14
        assert_signed_pow2::<41>(q_as[i], QAS_SHIFT_U); // q_as + 2^40 < 2^41
        // shift to nonnegative representatives (free); bounds hold by the checks above
        s1[i] = s[i] + 1;
        e1[i] = e[i] + B_ERR;
        r1[i] = r[i] + R_SHIFT_U;
        q1[i] = q_as[i] + QAS_SHIFT_U;
    }
    let h_s = hash_packed::<N, 2, 126>(s1);
    let h_e = hash_packed::<N, 6, 42>(e1);
    let h_m = hash_packed::<N, 17, 14>(m);
    let h_r = hash_packed::<N, 14, 18>(r1);
    let h_q = hash_packed::<N, 41, 6>(q1);
    [h_s, h_e, h_m, h_r, h_q]
}

/// The exact SK-BFV Schwartz-Zippel identity at `gamma`. Generic over N and LOG_N = log2(N).
fn assert_sz_identity<let N: u32, let LOG_N: u32>(
    c0: [Field; N],
    c1: [Field; N],
    s: [Field; N],
    e: [Field; N],
    m: [Field; N],
    r: [Field; N],
    q_as: [Field; N],
    gamma: Field,
) {
    let ag = eval_at(c1, gamma);
    let sg = eval_at(s, gamma);
    let mg = eval_at(m, gamma);
    let eg = eval_at(e, gamma);
    let c0g = eval_at(c0, gamma);
    let rg = eval_at(r, gamma);
    let qg = eval_at(q_as, gamma);
    let gn = pow_pow2::<LOG_N>(gamma);
    assert(ag * sg == DELTA * mg + eg - c0g - Q * rg + (gn + 1) * qg);
}

/// Packed-Fiat-Shamir variant of `verify_sk_encryption`, generic over N (optimization plan Part 1).
/// Same statement, range checks, and identity; only the gamma derivation is packed (~5x smaller
/// circuit, measured). c0,c1 remain public inputs here. Instantiate `::<N, LOG_N>`.
pub fn verify_sk_encryption_packed<let N: u32, let LOG_N: u32>(
    c0: [Field; N],
    c1: [Field; N],
    s: [Field; N],
    e: [Field; N],
    m: [Field; N],
    r: [Field; N],
    q_as: [Field; N],
) {
    // c0,c1 are PUBLIC inputs here, bound directly by the SNARK, so gamma need not bind them (Lever B).
    let gamma = Poseidon2::hash(sk_witness_subdigests(s, e, m, r, q_as), 5);
    assert_sz_identity::<N, LOG_N>(c0, c1, s, e, m, r, q_as, gamma);
}

/// Single-digest variant (optimization plan Part 2 prerequisite), generic over N: c0,c1 are PRIVATE
/// witness, and the circuit RETURNS `digest = Poseidon2(hash(pack c0), hash(pack c1))` as its single
/// public output. This collapses the public inputs from 2N (the raw ciphertext) to 1, cutting on-chain
/// gas; the ciphertext can then be posted in an EIP-4844 blob (DA) and bound by recomputing the digest.
///
/// SOUNDNESS (hardened, audit ZK-01): c0 is PRIVATE (prover-chosen), so gamma binds the public
/// sub-digests (h0,h1) as well as the 5 witnesses -- otherwise a prover could fix the witnesses (fixing
/// gamma) and solve c0(gamma) to satisfy the identity at one point (a vacuous proof). The relying party
/// MUST still bind the returned digest to its ciphertext (T2, docs/security.md §6); the hardening only
/// removes the "accepts garbage" failure if that check is imperfect. c0,c1 are range-checked to 27 bits
/// for injective digest packing.
pub fn verify_sk_encryption_digest<let N: u32, let LOG_N: u32>(
    c0: [Field; N],
    c1: [Field; N],
    s: [Field; N],
    e: [Field; N],
    m: [Field; N],
    r: [Field; N],
    q_as: [Field; N],
) -> Field {
    for i in 0..N {
        c0[i].assert_max_bit_size::<27>(); // q < 2^27 -> injective digest packing
        c1[i].assert_max_bit_size::<27>();
    }
    // Public sub-digests, reused to BIND c0,c1 into gamma and to form the returned digest.
    let h0 = hash_packed::<N, 27, 9>(c0);
    let h1 = hash_packed::<N, 27, 9>(c1);

    // gamma binds the 5 witnesses AND the 2 public polynomials (a private c0 must not be solvable for
    // after gamma is fixed -- audit ZK-01).
    let w = sk_witness_subdigests(s, e, m, r, q_as);
    let gamma = Poseidon2::hash([w[0], w[1], w[2], w[3], w[4], h0, h1], 7);
    assert_sz_identity::<N, LOG_N>(c0, c1, s, e, m, r, q_as, gamma);

    Poseidon2::hash([h0, h1], 2)
}
