//! Sound range-check primitives.
//!
//! ADR-007 (Phase 1): `x as uN` in Noir TRUNCATES modulo 2^N; it does NOT constrain
//! `x < 2^N`. Empirically verified (Phase 0 cast probe). Therefore a cast-then-compare
//! is NOT a sound bound. Only `Field::assert_max_bit_size` constrains the value. Every
//! range check in this library is built on it.

/// Assert `0 <= x < 2^BITS`.
pub fn assert_max_bits<let BITS: u32>(x: Field) {
    x.assert_max_bit_size::<BITS>();
}

/// Assert `0 <= x < bound`, where the caller guarantees `bound <= 2^BITS`.
///
/// Sound: `x < 2^BITS` and `bound-1-x < 2^BITS`. If `x >= bound` (but `< 2^BITS`),
/// then `bound-1-x` is negative and wraps to a ~254-bit field element, failing the
/// second check. Costs two BITS-bit range checks.
pub fn assert_lt<let BITS: u32>(x: Field, bound: Field) {
    x.assert_max_bit_size::<BITS>();
    (bound - 1 - x).assert_max_bit_size::<BITS>();
}

mod tests {
    use super::assert_lt;

    #[test]
    fn lt_accepts_in_range() {
        assert_lt::<8>(0, 200);
        assert_lt::<8>(199, 200);
        assert_lt::<27>(134215680, 134215681);
    }

    #[test(should_fail)]
    fn lt_rejects_equal() {
        assert_lt::<8>(200, 200);
    }

    #[test(should_fail)]
    fn lt_rejects_above() {
        assert_lt::<8>(201, 200);
    }

    #[test(should_fail)]
    fn lt_rejects_wrapped_negative() {
        // 0 - 1 wraps to p-1, a ~254-bit value: must fail the BITS-bit check.
        assert_lt::<27>(0 - 1, 134215681);
    }
}
