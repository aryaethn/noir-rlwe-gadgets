//! The ring-element type for R_q = Z_q[X]/(X^N + 1) and its arithmetic.

pub mod reduction;
pub mod arithmetic;

/// An element of R_q = Z_q[X]/(X^N + 1), stored as N coefficients (degree < N).
///
/// Representation: coefficients are field elements. The *canonical* representation is
/// unsigned in [0, Q), but the arithmetic gadgets in `arithmetic.nr` are NON-reducing
/// (they operate over the full field), so intermediate `RingElement`s may hold values
/// outside [0, Q). Use `reduction::reduce_ring` to canonicalize, or the `range` gadgets
/// to constrain coefficients. The Q generic tags the modulus at the type level so
/// elements of different rings cannot be mixed.
pub struct RingElement<let N: u32, let Q: Field> {
    pub coeffs: [Field; N],
}

impl<let N: u32, let Q: Field> RingElement<N, Q> {
    /// Wrap a coefficient array. Does NOT range-check (range checks are explicit gadgets).
    pub fn new(coeffs: [Field; N]) -> Self {
        Self { coeffs }
    }

    /// The zero polynomial.
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// The constant polynomial `c` (c in the X^0 slot, rest zero).
    pub fn constant(c: Field) -> Self {
        let mut coeffs = [0; N];
        coeffs[0] = c;
        Self { coeffs }
    }
}

mod tests {
    use super::RingElement;

    global Q: Field = 134215681;

    #[test]
    fn construct_and_index() {
        let a: RingElement<4, Q> = RingElement::new([1, 2, 3, 4]);
        assert(a.coeffs[2] == 3);
    }

    #[test]
    fn zero_and_constant() {
        let z: RingElement<4, Q> = RingElement::zero();
        assert(z.coeffs[0] == 0);
        assert(z.coeffs[3] == 0);
        let c: RingElement<4, Q> = RingElement::constant(7);
        assert(c.coeffs[0] == 7);
        assert(c.coeffs[1] == 0);
    }
}
