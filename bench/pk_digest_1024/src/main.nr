use noir_rlwe::proofs::pk_encryption::verify_pk_encryption_digest;

// Public-key BFV encryption, single-digest variant (n=1024, q27). pk0,pk1,c0,c1 are PRIVATE;
// the lone public output is digest = H(pk0||pk1||c0||c1), which the relying party binds to the
// recipient's registered public key and the submitted ciphertext.
fn main(
    pk0: [Field; 1024],
    pk1: [Field; 1024],
    c0: [Field; 1024],
    c1: [Field; 1024],
    u: [Field; 1024],
    e0: [Field; 1024],
    e1: [Field; 1024],
    m: [Field; 1024],
    r0: [Field; 1024],
    r1: [Field; 1024],
    q0: [Field; 1024],
    q1: [Field; 1024],
) -> pub Field {
    verify_pk_encryption_digest::<1024, 10>(pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1)
}
