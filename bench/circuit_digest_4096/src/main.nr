use noir_rlwe::proofs::sk_encryption::verify_sk_encryption_digest;
fn main(
    c0: [Field; 4096], c1: [Field; 4096],
    s: [Field; 4096], e: [Field; 4096], m: [Field; 4096], r: [Field; 4096], q_as: [Field; 4096],
) -> pub Field {
    verify_sk_encryption_digest::<4096, 12>(c0, c1, s, e, m, r, q_as)
}
