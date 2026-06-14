//! Schwartz-Zippel negacyclic product check -- the core gadget.
//!
//! To verify f(X)*g(X) == h(X) in R_q = Z_q[X]/(X^N + 1), the prover supplies the
//! quotient polynomial k(X) (degree < N-1) such that the EXACT integer-polynomial identity
//!
//!     f(X) * g(X) = h(X) + (X^N + 1) * k(X)
//!
//! holds over Z[X]. This is checked by evaluating both sides at a single challenge `gamma`
//! over the full field:
//!
//!     f(gamma) * g(gamma) == h(gamma) + (gamma^N + 1) * k(gamma).
//!
//! Soundness: if the polynomial identity is false, the degree-(2N-2) difference vanishes at
//! `gamma` with probability <= (2N-2)/p ~ 2^-243 for a uniform full-field `gamma` (p ~ 2^254).
//! This is the *random-evaluation* soundness; for knowledge soundness the polynomials must be
//! committed and `gamma` derived from those commitments (see `fiat_shamir`, ADR-009). No field
//! wraparound occurs because |coeffs| < N*Q^2 << p.

use crate::poly::horner::eval_at;
use crate::ring::RingElement;

/// Compute gamma^(2^LOG_N) by LOG_N repeated squarings (N = 2^LOG_N).
pub fn pow_pow2<let LOG_N: u32>(gamma: Field) -> Field {
    let mut g = gamma;
    for _ in 0..LOG_N {
        g = g * g;
    }
    g
}

/// Assert f * g == h in R_q given the quotient polynomial k, via evaluation at `gamma`.
/// `LOG_N` must equal log2(N).
pub fn assert_poly_product<let N: u32, let Q: Field, let LOG_N: u32>(
    f: RingElement<N, Q>,
    g: RingElement<N, Q>,
    h: RingElement<N, Q>,
    k: RingElement<N, Q>,
    gamma: Field,
) {
    let lhs = eval_at(f.coeffs, gamma) * eval_at(g.coeffs, gamma);
    let gamma_n = pow_pow2::<LOG_N>(gamma);
    let rhs = eval_at(h.coeffs, gamma) + (gamma_n + 1) * eval_at(k.coeffs, gamma);
    assert(lhs == rhs);
}

mod tests {
    use super::{assert_poly_product, pow_pow2};
    use crate::ring::RingElement;

    global Q: Field = 134215681;

    // Vectors generated and verified over Z in /tmp/sz_vectors.py (N=8, gamma=5):
    //   f*g == h + (X^8 + 1)*k. Negative coeffs of h are given as BN254 representatives.
    global F: [Field; 8] = [3, 1, 4, 1, 5, 9, 2, 6];
    global G: [Field; 8] = [2, 7, 1, 8, 2, 8, 1, 8];
    global H: [Field; 8] = [
        21888242871839275222246405745257275088548364400416034343698204186575808495477,
        21888242871839275222246405745257275088548364400416034343698204186575808495527,
        21888242871839275222246405745257275088548364400416034343698204186575808495498,
        21888242871839275222246405745257275088548364400416034343698204186575808495595,
        21888242871839275222246405745257275088548364400416034343698204186575808495530,
        90, 51, 134,
    ];
    global K: [Field; 8] = [146, 113, 137, 77, 122, 22, 48, 0];

    #[test]
    fn pow_pow2_matches() {
        // gamma^8 at gamma=5 == 390625
        assert(pow_pow2::<3>(5) == 390625);
    }

    #[test]
    fn accepts_correct_product() {
        let f: RingElement<8, Q> = RingElement::new(F);
        let g: RingElement<8, Q> = RingElement::new(G);
        let h: RingElement<8, Q> = RingElement::new(H);
        let k: RingElement<8, Q> = RingElement::new(K);
        assert_poly_product::<8, Q, 3>(f, g, h, k, 5);
    }

    #[test(should_fail)]
    fn rejects_tampered_h() {
        // h[0] incremented by 1 -> identity fails at gamma=5.
        let mut h_bad = H;
        h_bad[0] = h_bad[0] + 1;
        let f: RingElement<8, Q> = RingElement::new(F);
        let g: RingElement<8, Q> = RingElement::new(G);
        let h: RingElement<8, Q> = RingElement::new(h_bad);
        let k: RingElement<8, Q> = RingElement::new(K);
        assert_poly_product::<8, Q, 3>(f, g, h, k, 5);
    }

    #[test(should_fail)]
    fn rejects_tampered_k() {
        let mut k_bad = K;
        k_bad[1] = k_bad[1] + 1;
        let f: RingElement<8, Q> = RingElement::new(F);
        let g: RingElement<8, Q> = RingElement::new(G);
        let h: RingElement<8, Q> = RingElement::new(H);
        let k: RingElement<8, Q> = RingElement::new(k_bad);
        assert_poly_product::<8, Q, 3>(f, g, h, k, 5);
    }
}
