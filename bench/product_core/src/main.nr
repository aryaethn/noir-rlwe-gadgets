// S-Z product check at N=1024 WITHOUT Fiat-Shamir (gamma supplied) -- isolates the
// evaluation core from the Poseidon2 challenge-derivation cost.
use noir_rlwe::params::bfv_1024_27::{LOG_N, N, Q};
use noir_rlwe::poly::product_check::assert_poly_product;
use noir_rlwe::RingElement;

fn main(f: [Field; N], g: [Field; N], h: pub [Field; N], k: [Field; N], gamma: pub Field) {
    let fr: RingElement<N, Q> = RingElement::new(f);
    let gr: RingElement<N, Q> = RingElement::new(g);
    let hr: RingElement<N, Q> = RingElement::new(h);
    let kr: RingElement<N, Q> = RingElement::new(k);
    assert_poly_product::<N, Q, LOG_N>(fr, gr, hr, kr, gamma);
}
