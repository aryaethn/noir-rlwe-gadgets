//! Ternary range check for the BFV secret key: each coefficient is in {-1, 0, 1},
//! represented unsigned as {Q-1, 0, 1}.

use crate::ring::RingElement;

/// Assert `c` is in {0, 1, Q-1}. Exact algebraic constraint (the cubic has exactly those
/// three roots in the field), so it is SOUND with no range decomposition; ~2 mults.
pub fn assert_ternary(c: Field, q: Field) {
    assert(c * (c - 1) * (c - (q - 1)) == 0);
}

/// Assert every coefficient of `a` is ternary.
pub fn assert_ternary_ring<let N: u32, let Q: Field>(a: RingElement<N, Q>) {
    for i in 0..N {
        assert_ternary(a.coeffs[i], Q);
    }
}

mod tests {
    use super::{assert_ternary, assert_ternary_ring};
    use crate::ring::RingElement;

    global Q: Field = 134215681;

    #[test]
    fn accepts_ternary_values() {
        assert_ternary(0, Q);
        assert_ternary(1, Q);
        assert_ternary(Q - 1, Q);
    }

    #[test]
    fn accepts_ternary_ring() {
        let a: RingElement<4, Q> = RingElement::new([0, 1, Q - 1, 0]);
        assert_ternary_ring(a);
    }

    #[test(should_fail)]
    fn rejects_two() {
        assert_ternary(2, Q);
    }

    #[test(should_fail)]
    fn rejects_q_minus_2() {
        assert_ternary(Q - 2, Q);
    }
}
