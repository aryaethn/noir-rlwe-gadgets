//! Range checks for SIGNED (centered) coefficients, used by the BFV witness polynomials
//! in the Schwartz-Zippel identity. The identity holds over Z with the *signed* integer
//! values (s in {-1,0,1}, e in [-B,B], quotients r/q_as signed), so these are checked on
//! their field representatives (a negative integer -v is the field element p - v).

use crate::ring::RingElement;
use crate::util::assert_lt;

/// Assert `c` is a signed ternary value in {-1, 0, 1} (field {p-1, 0, 1}).
/// Exact cubic `c*(c-1)*(c+1) == 0`; SOUND, no range decomposition.
pub fn assert_ternary_signed(c: Field) {
    assert(c * (c - 1) * (c + 1) == 0);
}

/// Assert `|c| <= B` for a signed `c` (c in [-B, B]). `BITS` must satisfy `2B+1 <= 2^BITS`.
/// SOUND: shifts to `c + B in [0, 2B]` and range-checks with `assert_lt`.
pub fn assert_abs_le<let BITS: u32>(c: Field, b: Field) {
    assert_lt::<BITS>(c + b, 2 * b + 1);
}

/// Assert a signed `x` lies in `[-shift, 2^BITS - shift)`; with `shift = 2^(BITS-1)` this is
/// the symmetric bound `|x| < 2^(BITS-1)`. SOUND: single `assert_max_bit_size` on `x + shift`.
/// Used for the quotient polynomials r, q_as where a (loose) power-of-two bound suffices to
/// prevent field wraparound -- the identity itself pins their exact values.
pub fn assert_signed_pow2<let BITS: u32>(x: Field, shift: Field) {
    (x + shift).assert_max_bit_size::<BITS>();
}

/// Apply `assert_ternary_signed` to every coefficient.
pub fn assert_ternary_signed_ring<let N: u32, let Q: Field>(a: RingElement<N, Q>) {
    for i in 0..N {
        assert_ternary_signed(a.coeffs[i]);
    }
}

/// Apply `assert_abs_le::<BITS>` to every coefficient.
pub fn assert_abs_le_ring<let N: u32, let Q: Field, let BITS: u32>(
    a: RingElement<N, Q>,
    b: Field,
) {
    for i in 0..N {
        assert_abs_le::<BITS>(a.coeffs[i], b);
    }
}

mod tests {
    use super::{assert_abs_le, assert_signed_pow2, assert_ternary_signed};

    #[test]
    fn ternary_signed_accepts() {
        assert_ternary_signed(0);
        assert_ternary_signed(1);
        assert_ternary_signed(0 - 1); // -1
    }

    #[test(should_fail)]
    fn ternary_signed_rejects_two() {
        assert_ternary_signed(2);
    }

    #[test(should_fail)]
    fn ternary_signed_rejects_neg_two() {
        assert_ternary_signed(0 - 2);
    }

    #[test]
    fn abs_le_accepts() {
        assert_abs_le::<6>(0, 19);
        assert_abs_le::<6>(19, 19);
        assert_abs_le::<6>(0 - 19, 19); // -19
    }

    #[test(should_fail)]
    fn abs_le_rejects_above() {
        assert_abs_le::<6>(20, 19);
    }

    #[test(should_fail)]
    fn abs_le_rejects_below() {
        assert_abs_le::<6>(0 - 20, 19); // -20
    }

    #[test]
    fn signed_pow2_accepts() {
        // |x| < 2^11, shift 2^11, BITS=12.
        assert_signed_pow2::<12>(1026, 2048);
        assert_signed_pow2::<12>(0 - 1026, 2048);
        assert_signed_pow2::<12>(0, 2048);
    }

    #[test(should_fail)]
    fn signed_pow2_rejects_outside() {
        // x = 2^11 -> x + shift = 2^12, fails 12-bit check.
        assert_signed_pow2::<12>(2048, 2048);
    }
}
