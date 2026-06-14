use noir_rlwe::proofs::pk_encryption::verify_pk_encryption_digest;

// Public-key BFV encryption, single-digest variant (n=512, q27).
fn main(
    pk0: [Field; 512], pk1: [Field; 512], c0: [Field; 512], c1: [Field; 512],
    u: [Field; 512], e0: [Field; 512], e1: [Field; 512], m: [Field; 512],
    r0: [Field; 512], r1: [Field; 512], q0: [Field; 512], q1: [Field; 512],
) -> pub Field {
    verify_pk_encryption_digest::<512, 9>(pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1)
}
