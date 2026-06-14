use noir_rlwe::proofs::sk_encryption::verify_sk_encryption_digest;
fn main(
    c0: [Field; 512], c1: [Field; 512],
    s: [Field; 512], e: [Field; 512], m: [Field; 512], r: [Field; 512], q_as: [Field; 512],
) -> pub Field {
    verify_sk_encryption_digest::<512, 9>(c0, c1, s, e, m, r, q_as)
}
