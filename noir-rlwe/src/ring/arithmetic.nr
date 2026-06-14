//! Ring arithmetic over R_q. These gadgets are NON-REDUCING: they compute coefficient
//! arithmetic over the full BN254 field, so outputs may have coefficients outside [0, Q).
//!
//! Rationale (ADR-008, Phase 1): the Schwartz-Zippel circuit checks polynomial identities
//! by evaluation at a random challenge over the full field; the mod-q reduction is carried
//! by an explicit quotient polynomial, not by reducing every intermediate coefficient.
//! Non-reducing add/sub are then free (PLONK linearity) and scalar_mul costs N mults.
//! When a canonical [0, Q) form is needed, follow with `reduction::reduce_ring`.

use crate::ring::RingElement;

/// Coefficient-wise sum (non-reducing).
pub fn add<let N: u32, let Q: Field>(
    a: RingElement<N, Q>,
    b: RingElement<N, Q>,
) -> RingElement<N, Q> {
    let mut out = [0; N];
    for i in 0..N {
        out[i] = a.coeffs[i] + b.coeffs[i];
    }
    RingElement::new(out)
}

/// Coefficient-wise difference (non-reducing; may produce field-negative coefficients).
pub fn sub<let N: u32, let Q: Field>(
    a: RingElement<N, Q>,
    b: RingElement<N, Q>,
) -> RingElement<N, Q> {
    let mut out = [0; N];
    for i in 0..N {
        out[i] = a.coeffs[i] - b.coeffs[i];
    }
    RingElement::new(out)
}

/// Coefficient-wise negation (non-reducing).
pub fn neg<let N: u32, let Q: Field>(a: RingElement<N, Q>) -> RingElement<N, Q> {
    let mut out = [0; N];
    for i in 0..N {
        out[i] = 0 - a.coeffs[i];
    }
    RingElement::new(out)
}

/// Multiply every coefficient by a field scalar (non-reducing).
pub fn scalar_mul<let N: u32, let Q: Field>(
    s: Field,
    a: RingElement<N, Q>,
) -> RingElement<N, Q> {
    let mut out = [0; N];
    for i in 0..N {
        out[i] = s * a.coeffs[i];
    }
    RingElement::new(out)
}

mod tests {
    use super::{add, neg, scalar_mul, sub};
    use crate::ring::RingElement;

    global Q: Field = 134215681;

    #[test]
    fn add_sub_roundtrip() {
        let a: RingElement<4, Q> = RingElement::new([10, 20, 30, 40]);
        let b: RingElement<4, Q> = RingElement::new([1, 2, 3, 4]);
        let c = sub(add(a, b), b);
        for i in 0..4 {
            assert(c.coeffs[i] == a.coeffs[i]);
        }
    }

    #[test]
    fn neg_is_additive_inverse() {
        let a: RingElement<4, Q> = RingElement::new([10, 20, 30, 40]);
        let s = add(a, neg(a));
        for i in 0..4 {
            assert(s.coeffs[i] == 0);
        }
    }

    #[test]
    fn scalar_mul_basic() {
        let a: RingElement<4, Q> = RingElement::new([1, 2, 3, 4]);
        let z = scalar_mul(0, a);
        let o = scalar_mul(1, a);
        let three = scalar_mul(3, a);
        for i in 0..4 {
            assert(z.coeffs[i] == 0);
            assert(o.coeffs[i] == a.coeffs[i]);
            assert(three.coeffs[i] == 3 * a.coeffs[i]);
        }
    }
}
