//! Canonical modular reduction via an unconstrained (quotient, remainder) hint pinned
//! by an in-circuit identity and SOUND range checks (see util::assert_lt).
//!
//! The arithmetic gadgets are non-reducing; use these when a canonical [0, Q)
//! representative is actually required (e.g. to publish a reduced coefficient).

use crate::ring::RingElement;
use crate::util::assert_lt;

/// Hint: integer (quotient, remainder) of `a / q`. Requires the *true* value `a` to fit
/// in u128 (a < 2^128) — true for sums/products of [0,Q) values with Q <= 2^55 (a < 2^110).
/// Untrusted: correctness is enforced by the caller's constraints.
unconstrained fn divmod_hint(a: Field, q: Field) -> (Field, Field) {
    let ai = a as u128;
    let qi = q as u128;
    ((ai / qi) as Field, (ai % qi) as Field)
}

/// Reduce a NON-NEGATIVE value `a` known to lie in [0, 2^VALBITS) to its canonical
/// residue in [0, q). `QBITS` is the bit length of q (q <= 2^QBITS). SOUND:
/// `quotient*q + remainder == a`, `remainder < q`, `quotient < 2^VALBITS`, with no field
/// wraparound as long as VALBITS, QBITS are well below the field size (~254 bits).
pub fn reduce<let VALBITS: u32, let QBITS: u32>(a: Field, q: Field) -> Field {
    // Safety: (quotient, remainder) are pinned by the identity and range checks below
    // to the unique Euclidean division of `a` by `q`.
    let (quotient, remainder) = unsafe { divmod_hint(a, q) };
    assert(quotient * q + remainder == a);
    assert_lt::<QBITS>(remainder, q);
    quotient.assert_max_bit_size::<VALBITS>();
    remainder
}

/// Reduce every coefficient of a ring element into [0, Q).
pub fn reduce_ring<let N: u32, let Q: Field, let VALBITS: u32, let QBITS: u32>(
    a: RingElement<N, Q>,
) -> RingElement<N, Q> {
    let mut out = [0; N];
    for i in 0..N {
        out[i] = reduce::<VALBITS, QBITS>(a.coeffs[i], Q);
    }
    RingElement::new(out)
}

mod tests {
    use super::reduce;

    global Q: Field = 134215681; // 27-bit

    #[test]
    fn reduce_known_values() {
        // a in [0, 2^54): use VALBITS=54, QBITS=27.
        assert(reduce::<54, 27>(0, Q) == 0);
        assert(reduce::<54, 27>(Q - 1, Q) == Q - 1);
        assert(reduce::<54, 27>(Q, Q) == 0);
        assert(reduce::<54, 27>(Q + 5, Q) == 5);
        assert(reduce::<54, 27>(2 * Q + 9, Q) == 9);
    }

    #[test]
    fn reduce_product() {
        // (Q-1)^2 mod Q == 1. (Q-1)^2 < 2^54.
        let a = (Q - 1) * (Q - 1);
        assert(reduce::<54, 27>(a, Q) == 1);
    }

    #[test(should_fail)]
    fn reduce_rejects_out_of_valbits() {
        // a >= 2^VALBITS makes the quotient exceed its VALBITS bound: must fail.
        // Here a = Q * 2^54 (quotient ~2^54) with VALBITS=27 -> quotient range check fails.
        let big = Q * 134217728 * 134217728; // ~ Q * 2^54
        let _ = reduce::<27, 27>(big, Q);
    }
}
