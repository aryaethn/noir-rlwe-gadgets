// Single-digest SK-BFV circuit: ciphertext is PRIVATE; circuit returns one public digest.
use noir_rlwe::proofs::sk_encryption::verify_sk_encryption_digest;

fn main(
    c0: [Field; 1024],
    c1: [Field; 1024],
    s: [Field; 1024],
    e: [Field; 1024],
    m: [Field; 1024],
    r: [Field; 1024],
    q_as: [Field; 1024],
) -> pub Field {
    verify_sk_encryption_digest(c0, c1, s, e, m, r, q_as)
}
