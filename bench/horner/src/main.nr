// Phase 1 exit measurement: Horner evaluation gate count at N=1024.
use noir_rlwe::eval_at;

fn main(coeffs: [Field; 1024], gamma: pub Field) -> pub Field {
    eval_at(coeffs, gamma)
}
