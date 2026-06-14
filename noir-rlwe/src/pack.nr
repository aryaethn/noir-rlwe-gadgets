//! Bit-packing for cheap Fiat-Shamir (optimization plan Part 1, Q1.6; ADR-011).
//!
//! Poseidon2 costs ~25.4 gates per absorbed field element (measured), independent of how many
//! bits the element actually uses. The RLWE/BFV witness coefficients are tiny (2-41 bits), so we
//! pack several per 254-bit field element before hashing, cutting the absorbed-element count (and
//! thus the hash cost) by the packing factor. Packing is a constant-coefficient linear combination
//! `packed = sum_t v_t * 2^(BITS*t)`, which is (near-)free in PLONKish.
//!
//! SOUNDNESS: the packing is an injective encoding -- hence binds every coefficient exactly as
//! hashing them individually would -- PROVIDED (a) each input value is < 2^BITS (the caller's range
//! checks already guarantee this for the shifted-nonnegative witness representatives), and
//! (b) K*BITS <= 253, so packed < 2^253 < p (no field wraparound, no slot overlap).
//!
//! The output length is computed at compile time as M = ceil(N/K), so the gadget is generic over N.

/// 2^e as a Field (e is comptime).
fn pow2(e: u32) -> Field {
    let mut r: Field = 1;
    for _ in 0..e {
        r *= 2;
    }
    r
}

/// Pack N values, each `< 2^BITS` (caller-guaranteed), into ceil(N/K) field elements,
/// little-endian base 2^BITS. Requires K*BITS <= 253. Does NOT range-check (see `pack_bits_checked`).
pub fn pack_bits<let N: u32, let BITS: u32, let K: u32>(vals: [Field; N]) -> [Field; (N + K - 1) / K] {
    let base = pow2(BITS);
    let m = (N + K - 1) / K;
    let mut out: [Field; (N + K - 1) / K] = [0; (N + K - 1) / K];
    for j in 0..m {
        let mut acc: Field = 0;
        let mut mult: Field = 1;
        for t in 0..K {
            let idx = j * K + t;
            if idx < N {
                acc += vals[idx] * mult;
            }
            mult *= base;
        }
        out[j] = acc;
    }
    out
}

/// Self-contained variant: range-checks each value to BITS bits, then packs. Sound on its own, but
/// pays the range checks; prefer `pack_bits` when the inputs are already bounded by other checks.
pub fn pack_bits_checked<let N: u32, let BITS: u32, let K: u32>(
    vals: [Field; N],
) -> [Field; (N + K - 1) / K] {
    for i in 0..N {
        vals[i].assert_max_bit_size::<BITS>();
    }
    pack_bits::<N, BITS, K>(vals)
}

mod tests {
    use super::{pack_bits, pack_bits_checked};

    #[test]
    fn packs_little_endian() {
        // [1,2,3,4], 8-bit slots, 2 per element -> [1 + 2*256, 3 + 4*256].
        let out = pack_bits::<4, 8, 2>([1, 2, 3, 4]);
        assert(out.len() == 2);
        assert(out[0] == 1 + 2 * 256);
        assert(out[1] == 3 + 4 * 256);
    }

    #[test]
    fn zero_pads_last_block() {
        // 3 values, 2 per element -> ceil(3/2)=2; last slot of element 1 is zero-padded.
        let out = pack_bits::<3, 8, 2>([5, 6, 7]);
        assert(out.len() == 2);
        assert(out[0] == 5 + 6 * 256);
        assert(out[1] == 7);
    }

    #[test]
    fn output_length_is_ceil() {
        // 1024 values, 9 per element -> ceil(1024/9) = 114.
        let out = pack_bits::<1024, 27, 9>([0; 1024]);
        assert(out.len() == 114);
    }

    #[test]
    fn injective_max_values() {
        // Max 2-bit values {3,3,3} -> 3 + 3*4 + 3*16 = 63.
        let out = pack_bits::<3, 2, 3>([3, 3, 3]);
        assert(out[0] == 3 + 3 * 4 + 3 * 16);
    }

    #[test]
    fn checked_accepts_in_range() {
        let _ = pack_bits_checked::<3, 6, 3>([0, 38, 63]); // all < 2^6
    }

    #[test(should_fail)]
    fn checked_rejects_out_of_range() {
        // 64 >= 2^6 -> the range check must fail (otherwise packing would not be injective).
        let _ = pack_bits_checked::<3, 6, 3>([0, 64, 1]);
    }
}
