// Top-level proof-of-SK-BFV-encryption circuit (preset bfv_1024_27).
use noir_rlwe::proofs::sk_encryption::verify_sk_encryption;

fn main(
    c0: pub [Field; 1024],
    c1: pub [Field; 1024],
    s: [Field; 1024],
    e: [Field; 1024],
    m: [Field; 1024],
    r: [Field; 1024],
    q_as: [Field; 1024],
) {
    verify_sk_encryption::<1024, 10>(c0, c1, s, e, m, r, q_as);
}
