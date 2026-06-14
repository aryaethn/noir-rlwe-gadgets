//! Bounded (infinity-norm) range check for the BFV error term: each coefficient has
//! centered magnitude <= B, i.e. c is in [0, B] U [Q-B, Q-1] in the unsigned [0,Q) rep.
//! Also re-exports the generic `assert_lt` for plaintext-style bounds (m < T).

use crate::ring::RingElement;
use crate::util::assert_lt;

pub use crate::util::assert_lt as assert_lt_field;

/// Hint: is `c` in the high (negative) band [q-b, q-1]? Unconstrained, so the u128
/// comparison is harmless (correctness is enforced by `assert_lt` on `small`).
unconstrained fn in_high_band(c: Field, q: Field, b: Field) -> bool {
    (c as u128) > ((q - 1 - b) as u128)
}

/// Assert the centered magnitude of `c` is <= B (c in [0,B] U [Q-B, Q-1]).
/// `BBITS` must satisfy `B + 1 <= 2^BBITS`. SOUND: `small = c` (low band) or `q-c`
/// (high band) is selected by a hint and range-checked into [0, B]; an out-of-range `c`
/// makes `small` exceed B for either selection, so both fail.
pub fn assert_bounded<let BBITS: u32>(c: Field, q: Field, b: Field) {
    // Safety: the only constraint is that the selected `small` is <= B; either selection
    // forces c into [0,B] (hi=0) or [q-B, q] (hi=1), so a valid hi exists iff c is in range.
    let hi = unsafe { in_high_band(c, q, b) };
    let small = if hi { q - c } else { c };
    assert_lt::<BBITS>(small, b + 1);
}

/// Assert every coefficient of `a` has centered magnitude <= B.
pub fn assert_bounded_ring<let N: u32, let Q: Field, let BBITS: u32>(
    a: RingElement<N, Q>,
    b: Field,
) {
    for i in 0..N {
        assert_bounded::<BBITS>(a.coeffs[i], Q, b);
    }
}

mod tests {
    use super::{assert_bounded, assert_bounded_ring};
    use crate::ring::RingElement;

    global Q: Field = 134215681;
    global B: Field = 19;

    #[test]
    fn accepts_low_band() {
        assert_bounded::<5>(0, Q, B);
        assert_bounded::<5>(19, Q, B);
    }

    #[test]
    fn accepts_high_band() {
        assert_bounded::<5>(Q - 1, Q, B); // -1
        assert_bounded::<5>(Q - 19, Q, B); // -19
    }

    #[test]
    fn accepts_bounded_ring() {
        let a: RingElement<4, Q> = RingElement::new([0, 19, Q - 19, Q - 1]);
        assert_bounded_ring::<4, Q, 5>(a, B);
    }

    #[test(should_fail)]
    fn rejects_just_above_low() {
        assert_bounded::<5>(20, Q, B);
    }

    #[test(should_fail)]
    fn rejects_just_below_high() {
        assert_bounded::<5>(Q - 20, Q, B);
    }

    #[test(should_fail)]
    fn rejects_midrange() {
        assert_bounded::<5>(1000, Q, B);
    }
}
