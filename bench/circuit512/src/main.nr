// Top-level SK-BFV encryption circuit at n=512 (shares q27 preset constants).
use noir_rlwe::proofs::sk_encryption::verify_sk_encryption;

fn main(
    c0: pub [Field; 512],
    c1: pub [Field; 512],
    s: [Field; 512],
    e: [Field; 512],
    m: [Field; 512],
    r: [Field; 512],
    q_as: [Field; 512],
) {
    verify_sk_encryption::<512, 9>(c0, c1, s, e, m, r, q_as);
}
