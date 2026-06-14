// Phase 1 exit measurement: full Schwartz-Zippel negacyclic product check at N=1024.
// Includes Fiat-Shamir challenge derivation over (f, g, h, k) and the product assertion.
use noir_rlwe::params::bfv_1024_27::{LOG_N, N, Q};
use noir_rlwe::poly::product_check::assert_poly_product;
use noir_rlwe::derive_challenge;
use noir_rlwe::RingElement;

fn main(
    f: [Field; N],
    g: [Field; N],
    h: pub [Field; N],
    k: [Field; N],
) {
    let fr: RingElement<N, Q> = RingElement::new(f);
    let gr: RingElement<N, Q> = RingElement::new(g);
    let hr: RingElement<N, Q> = RingElement::new(h);
    let kr: RingElement<N, Q> = RingElement::new(k);
    let gamma = derive_challenge([fr, gr, hr, kr]);
    assert_poly_product::<N, Q, LOG_N>(fr, gr, hr, kr, gamma);
}
