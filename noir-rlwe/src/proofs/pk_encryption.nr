//! Proof of correct PUBLIC-KEY BFV encryption (Greco-style), preset `bfv_1024_27`.
//! UNAUDITED RESEARCH.
//!
//! This is the statement an actual fhEVM-style input submitter needs: the encryptor holds only
//! the recipient's public key `pk = (pk0, pk1)` (NOT the secret key) and proves a submitted
//! ciphertext is a well-formed encryption of a bounded message. Cf. `sk_encryption.nr`, which
//! proves the secret-key relation (only the key holder can run it).
//!
//! Public key / ciphertext:  pk0, pk1, c0, c1 in R_q.
//! Witness: u (ternary encryption randomness), e0, e1 (|e|<=B), m (in [0,t)),
//!          and the FOUR Schwartz-Zippel quotient polynomials r0, r1 (mod-q) and q0, q1 (X^N+1).
//!
//! PK encryption:  c0 = [pk0*u + e0 + Delta*m]_q,   c1 = [pk1*u + e1]_q.
//! Two exact integer-polynomial identities (derived & verified in /tmp/pk_identity.py over
//! n=512..4096, 40 seeds each, coefficient-wise AND at a random gamma):
//!
//!     pk0(X) u(X) = c0 - e0 - Delta*m + q*r0 + (X^N + 1) * q0     over Z[X]
//!     pk1(X) u(X) = c1 - e1          + q*r1 + (X^N + 1) * q1     over Z[X]
//!
//! checked at a single Fiat-Shamir challenge `gamma` (u(gamma) is shared). Soundness: the two
//! degree-(2N-2) differences each vanish at a uniform full-field gamma with prob <= (2N-2)/p;
//! the quotient range checks prevent field wraparound. Knowledge soundness additionally needs the
//! proof system's witness commitments (ADR-009). Structurally this is two copies of the SK identity
//! sharing u, with pk0/pk1 playing the role a=c1 played there -- so the quotient bounds are
//! IDENTICAL to SK's (|r| <= N+2, |q| <= (N-1)q): pk0,pk1 are reduced-mod-q (|coeff|<q) just like a.

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

// Uniform quotient bounds valid for any N <= 4096 (same as sk_encryption.nr): |r| <= N+2 < 2^13
// and |q| <= (N-1)q < 2^40. Used by the packed / digest variants. The tight per-N bounds from the
// params module (R_SHIFT=2^11, QAS_SHIFT=2^38) are used by the plain reference variant below.
global R_SHIFT_U: Field = 8192; // 2^13
global QAS_SHIFT_U: Field = 1099511627776; // 2^40

/// The two PK-BFV Schwartz-Zippel identities at `gamma`. Generic over N and LOG_N = log2(N).
/// `u(gamma)` is evaluated once and reused across both relations.
fn assert_pk_sz_identity<let N: u32, let LOG_N: u32>(
    pk0: [Field; N],
    pk1: [Field; N],
    c0: [Field; N],
    c1: [Field; N],
    u: [Field; N],
    e0: [Field; N],
    e1: [Field; N],
    m: [Field; N],
    r0: [Field; N],
    r1: [Field; N],
    q0: [Field; N],
    q1: [Field; N],
    gamma: Field,
) {
    let p0g = eval_at(pk0, gamma);
    let p1g = eval_at(pk1, gamma);
    let ug = eval_at(u, gamma);
    let c0g = eval_at(c0, gamma);
    let c1g = eval_at(c1, gamma);
    let e0g = eval_at(e0, gamma);
    let e1g = eval_at(e1, gamma);
    let mg = eval_at(m, gamma);
    let r0g = eval_at(r0, gamma);
    let r1g = eval_at(r1, gamma);
    let q0g = eval_at(q0, gamma);
    let q1g = eval_at(q1, gamma);
    let gn = pow_pow2::<LOG_N>(gamma);

    // pk0*u = c0 - e0 - Delta*m + q*r0 + (X^N+1)*q0
    assert(p0g * ug == c0g - e0g - DELTA * mg + Q * r0g + (gn + 1) * q0g);
    // pk1*u = c1 - e1 + q*r1 + (X^N+1)*q1
    assert(p1g * ug == c1g - e1g + Q * r1g + (gn + 1) * q1g);
}

/// Range-check the 8 witness polynomials (uniform N<=4096 bounds) and derive `gamma` by hashing
/// each one bit-packed, then hashing the 8 sub-digests. pk0,pk1,c0,c1 are excluded from gamma
/// (ADR-009 Lever B: they are pinned -- as public inputs in the packed variant, or by the returned
/// digest in the digest variant). Generic over N. Packing widths reuse the SK schedule, doubled for
/// the two error / two r / two q polynomials.
fn packed_gamma_pk<let N: u32>(
    u: [Field; N],
    e0: [Field; N],
    e1: [Field; N],
    m: [Field; N],
    r0: [Field; N],
    r1: [Field; N],
    q0: [Field; N],
    q1: [Field; N],
) -> Field {
    let mut u1 = [0; N];
    let mut e01 = [0; N];
    let mut e11 = [0; N];
    let mut r01 = [0; N];
    let mut r11 = [0; N];
    let mut q01 = [0; N];
    let mut q11 = [0; N];
    for i in 0..N {
        assert_ternary_signed(u[i]);
        assert_abs_le::<6>(e0[i], B_ERR); // |e| <= 19, 2*19+1 = 39 < 2^6
        assert_abs_le::<6>(e1[i], B_ERR);
        assert_lt::<17>(m[i], T); // m < t < 2^17
        assert_signed_pow2::<14>(r0[i], R_SHIFT_U); // r + 2^13 < 2^14
        assert_signed_pow2::<14>(r1[i], R_SHIFT_U);
        assert_signed_pow2::<41>(q0[i], QAS_SHIFT_U); // q + 2^40 < 2^41
        assert_signed_pow2::<41>(q1[i], QAS_SHIFT_U);
        // shift to nonnegative representatives (free); bounds hold by the checks above
        u1[i] = u[i] + 1;
        e01[i] = e0[i] + B_ERR;
        e11[i] = e1[i] + B_ERR;
        r01[i] = r0[i] + R_SHIFT_U;
        r11[i] = r1[i] + R_SHIFT_U;
        q01[i] = q0[i] + QAS_SHIFT_U;
        q11[i] = q1[i] + QAS_SHIFT_U;
    }
    let h_u = hash_packed::<N, 2, 126>(u1);
    let h_e0 = hash_packed::<N, 6, 42>(e01);
    let h_e1 = hash_packed::<N, 6, 42>(e11);
    let h_m = hash_packed::<N, 17, 14>(m);
    let h_r0 = hash_packed::<N, 14, 18>(r01);
    let h_r1 = hash_packed::<N, 14, 18>(r11);
    let h_q0 = hash_packed::<N, 41, 6>(q01);
    let h_q1 = hash_packed::<N, 41, 6>(q11);
    Poseidon2::hash([h_u, h_e0, h_e1, h_m, h_r0, h_r1, h_q0, h_q1], 8)
}

/// Plain reference variant: binds every polynomial (public AND witness) into `gamma` via the
/// per-element `derive_challenge`, and uses the tight per-N param bounds. Simplest to audit but the
/// most gates (unpacked Fiat-Shamir). Prefer `verify_pk_encryption_digest` for production. `::<N,LOG_N>`.
pub fn verify_pk_encryption<let N: u32, let LOG_N: u32>(
    pk0: [Field; N], // public
    pk1: [Field; N], // public
    c0: [Field; N], // public
    c1: [Field; N], // public
    u: [Field; N], // witness: ternary encryption randomness (signed)
    e0: [Field; N], // witness: error, |e0_i| <= B (signed)
    e1: [Field; N], // witness: error, |e1_i| <= B (signed)
    m: [Field; N], // witness: plaintext, m_i in [0, t)
    r0: [Field; N], // witness: mod-q quotient for relation 0 (signed)
    r1: [Field; N], // witness: mod-q quotient for relation 1 (signed)
    q0: [Field; N], // witness: (X^N+1) product quotient for pk0*u (signed)
    q1: [Field; N], // witness: (X^N+1) product quotient for pk1*u (signed)
) {
    for i in 0..N {
        assert_ternary_signed(u[i]);
        assert_abs_le::<LOG_2BERR_P1>(e0[i], B_ERR);
        assert_abs_le::<LOG_2BERR_P1>(e1[i], B_ERR);
        assert_lt::<LOG_T>(m[i], T);
        assert_signed_pow2::<LOG_R_RANGE>(r0[i], R_SHIFT);
        assert_signed_pow2::<LOG_R_RANGE>(r1[i], R_SHIFT);
        assert_signed_pow2::<LOG_QAS_RANGE>(q0[i], QAS_SHIFT);
        assert_signed_pow2::<LOG_QAS_RANGE>(q1[i], QAS_SHIFT);
    }

    let pk0r: RingElement<N, Q> = RingElement::new(pk0);
    let pk1r: RingElement<N, Q> = RingElement::new(pk1);
    let c0r: RingElement<N, Q> = RingElement::new(c0);
    let c1r: RingElement<N, Q> = RingElement::new(c1);
    let ur: RingElement<N, Q> = RingElement::new(u);
    let e0r: RingElement<N, Q> = RingElement::new(e0);
    let e1r: RingElement<N, Q> = RingElement::new(e1);
    let mr: RingElement<N, Q> = RingElement::new(m);
    let r0r: RingElement<N, Q> = RingElement::new(r0);
    let r1r: RingElement<N, Q> = RingElement::new(r1);
    let q0r: RingElement<N, Q> = RingElement::new(q0);
    let q1r: RingElement<N, Q> = RingElement::new(q1);
    let gamma =
        derive_challenge([pk0r, pk1r, c0r, c1r, ur, e0r, e1r, mr, r0r, r1r, q0r, q1r]);

    assert_pk_sz_identity::<N, LOG_N>(pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1, gamma);
}

/// Packed-Fiat-Shamir variant, generic over N (optimization plan Part 1). Same statement; gamma is
/// derived from the bit-packed witnesses (~5x smaller FS, measured for SK). pk0,pk1,c0,c1 remain
/// public inputs. `::<N, LOG_N>`.
pub fn verify_pk_encryption_packed<let N: u32, let LOG_N: u32>(
    pk0: [Field; N],
    pk1: [Field; N],
    c0: [Field; N],
    c1: [Field; N],
    u: [Field; N],
    e0: [Field; N],
    e1: [Field; N],
    m: [Field; N],
    r0: [Field; N],
    r1: [Field; N],
    q0: [Field; N],
    q1: [Field; N],
) {
    let gamma = packed_gamma_pk(u, e0, e1, m, r0, r1, q0, q1);
    assert_pk_sz_identity::<N, LOG_N>(pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1, gamma);
}

/// Single-digest variant (optimization plan Part 2), generic over N: pk0,pk1,c0,c1 are PRIVATE
/// witness, and the circuit RETURNS `digest = Poseidon2(pack(pk0)||pack(pk1)||pack(c0)||pack(c1))`
/// as its single public output. This collapses the public inputs from 4N to 1, cutting on-chain gas;
/// the relying party accepts only if the returned digest equals H(the recipient's registered public
/// key || the submitted ciphertext), which pins all four public polynomials to those exact values
/// (so gamma need not bind them).
///
/// pk0,pk1,c0,c1 are range-checked to 27 bits: this makes the digest packing INJECTIVE (otherwise a
/// prover could substitute a colliding ciphertext) AND bounds the products pk*u so the quotient
/// bounds |q| <= (N-1)q remain valid for adversarial inputs. `::<N, LOG_N>`.
pub fn verify_pk_encryption_digest<let N: u32, let LOG_N: u32>(
    pk0: [Field; N],
    pk1: [Field; N],
    c0: [Field; N],
    c1: [Field; N],
    u: [Field; N],
    e0: [Field; N],
    e1: [Field; N],
    m: [Field; N],
    r0: [Field; N],
    r1: [Field; N],
    q0: [Field; N],
    q1: [Field; N],
) -> Field {
    for i in 0..N {
        pk0[i].assert_max_bit_size::<27>();
        pk1[i].assert_max_bit_size::<27>();
        c0[i].assert_max_bit_size::<27>();
        c1[i].assert_max_bit_size::<27>();
    }
    let gamma = packed_gamma_pk(u, e0, e1, m, r0, r1, q0, q1);
    assert_pk_sz_identity::<N, LOG_N>(pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1, gamma);

    let hp0 = hash_packed::<N, 27, 9>(pk0);
    let hp1 = hash_packed::<N, 27, 9>(pk1);
    let h0 = hash_packed::<N, 27, 9>(c0);
    let h1 = hash_packed::<N, 27, 9>(c1);
    Poseidon2::hash([hp0, hp1, h0, h1], 4)
}

mod tests {
    use super::assert_pk_sz_identity;

    // N=4 valid PK witness (preset q27), generated & cross-checked in /tmp/pk_identity.py at
    // gamma=7. Signed coefficients are given as their BN254 field representatives (p - |v|), exactly
    // as emitted by the oracle. The two identities hold coefficient-wise over Z and at this gamma.
    global PK0: [Field; 4] = [132850816, 24133702, 55917763, 98339357];
    global PK1: [Field; 4] = [55917772, 98339353, 1364882, 110081987];
    global C0: [Field; 4] = [21923306, 93910831, 35151814, 55394956];
    global C1: [Field; 4] = [114174223, 34511460, 22768819, 80051484];
    // u = [-1, 0, 0, 1]
    global U: [Field; 4] =
        [21888242871839275222246405745257275088548364400416034343698204186575808495616, 0, 0, 1];
    // e0 = [-8, 16, -8, 3]
    global E0: [Field; 4] = [
        21888242871839275222246405745257275088548364400416034343698204186575808495609,
        16,
        21888242871839275222246405745257275088548364400416034343698204186575808495609,
        3,
    ];
    // e1 = [-14, 14, 7, 18]
    global E1: [Field; 4] = [
        21888242871839275222246405745257275088548364400416034343698204186575808495603,
        14,
        7,
        18,
    ];
    global M: [Field; 4] = [21833, 19417, 26963, 10202];
    // r0 = [-1, -1, -1, 0]
    global R0: [Field; 4] = [
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
        0,
    ];
    // r1 = [-2, -1, -1, -1]
    global R1: [Field; 4] = [
        21888242871839275222246405745257275088548364400416034343698204186575808495615,
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
        21888242871839275222246405745257275088548364400416034343698204186575808495616,
    ];
    global Q0: [Field; 4] = [24133702, 55917763, 98339357, 0];
    global Q1: [Field; 4] = [98339353, 1364882, 110081987, 0];

    #[test]
    fn accepts_correct_pk_product() {
        assert_pk_sz_identity::<4, 2>(PK0, PK1, C0, C1, U, E0, E1, M, R0, R1, Q0, Q1, 7);
    }

    #[test(should_fail)]
    fn rejects_tampered_c0() {
        let mut c0_bad = C0;
        c0_bad[0] = c0_bad[0] + 1; // breaks relation 0 at gamma=7
        assert_pk_sz_identity::<4, 2>(PK0, PK1, c0_bad, C1, U, E0, E1, M, R0, R1, Q0, Q1, 7);
    }

    #[test(should_fail)]
    fn rejects_tampered_q1() {
        let mut q1_bad = Q1;
        q1_bad[1] = q1_bad[1] + 1; // breaks relation 1 (the X^N+1 quotient) at gamma=7
        assert_pk_sz_identity::<4, 2>(PK0, PK1, C0, C1, U, E0, E1, M, R0, R1, Q0, q1_bad, 7);
    }
}
