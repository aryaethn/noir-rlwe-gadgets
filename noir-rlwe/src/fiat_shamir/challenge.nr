//! Derive the Schwartz-Zippel challenge `gamma` with Poseidon2.
//!
//! ADR-009 (Phase 1, soundness): `gamma` must bind to ALL polynomials the product check
//! ranges over -- including the witness polynomials (s, e, m, k), not just the public
//! (c0, c1). If `gamma` depended only on public inputs, a malicious prover (who then knows
//! `gamma` in advance) could craft witnesses satisfying a false identity at that single
//! point. Hashing the witness coefficients makes `gamma = H(witness)`, so altering the
//! witness changes `gamma`; grinding then requires a Poseidon2 fixpoint/collision.
//! The challenge is a full-field element (no mod-q reduction): soundness ~ 2N/p, not 1/q.
//!
//! Poseidon2 is an external dependency (ADR-006: it is no longer in the Noir stdlib).

use crate::pack::pack_bits;
use crate::ring::RingElement;
use poseidon::poseidon2::Poseidon2;

/// Poseidon2 hash of a single ring element's coefficients.
pub fn hash_ring<let N: u32, let Q: Field>(a: RingElement<N, Q>) -> Field {
    Poseidon2::hash(a.coeffs, N)
}

/// Bit-pack `vals` (each `< 2^BITS`, K per element) and Poseidon2-hash the result. Binds every
/// coefficient (injective packing) at ~1/K the absorbed-element cost. See `pack` / ADR-011.
pub fn hash_packed<let N: u32, let BITS: u32, let K: u32>(vals: [Field; N]) -> Field {
    let packed = pack_bits::<N, BITS, K>(vals);
    Poseidon2::hash(packed, packed.len())
}

/// Derive `gamma` by hashing M ring elements: hash each to a digest, then hash the
/// M digests. Pass every polynomial the product check depends on (public AND witness).
pub fn derive_challenge<let N: u32, let Q: Field, let M: u32>(
    polys: [RingElement<N, Q>; M],
) -> Field {
    let mut digests = [0; M];
    for i in 0..M {
        digests[i] = Poseidon2::hash(polys[i].coeffs, N);
    }
    Poseidon2::hash(digests, M)
}

mod tests {
    use super::{derive_challenge, hash_ring};
    use crate::ring::RingElement;

    global Q: Field = 134215681;

    #[test]
    fn deterministic() {
        let a: RingElement<4, Q> = RingElement::new([1, 2, 3, 4]);
        let b: RingElement<4, Q> = RingElement::new([5, 6, 7, 8]);
        let g1 = derive_challenge([a, b]);
        let g2 = derive_challenge([a, b]);
        assert(g1 == g2);
    }

    #[test]
    fn sensitive_to_witness() {
        // Changing one witness coefficient must change gamma (binding property).
        let a: RingElement<4, Q> = RingElement::new([1, 2, 3, 4]);
        let b: RingElement<4, Q> = RingElement::new([5, 6, 7, 8]);
        let b2: RingElement<4, Q> = RingElement::new([5, 6, 7, 9]);
        assert(derive_challenge([a, b]) != derive_challenge([a, b2]));
    }

    #[test]
    fn hash_ring_deterministic() {
        let a: RingElement<4, Q> = RingElement::new([1, 2, 3, 4]);
        assert(hash_ring(a) == hash_ring(a));
    }
}
