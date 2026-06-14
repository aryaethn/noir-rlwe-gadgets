use noir_rlwe::proofs::sk_encryption::verify_sk_encryption_digest;
fn main(
    c0: [Field; 2048], c1: [Field; 2048],
    s: [Field; 2048], e: [Field; 2048], m: [Field; 2048], r: [Field; 2048], q_as: [Field; 2048],
) -> pub Field {
    verify_sk_encryption_digest::<2048, 11>(c0, c1, s, e, m, r, q_as)
}
