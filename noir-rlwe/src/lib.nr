//! # noir-rlwe-gadgets
//!
//! UNAUDITED RESEARCH. Gadgets for verifying Ring-LWE / BFV operations inside Noir
//! (Aztec / Barretenberg / UltraHonk) circuits. Primary technique: Schwartz-Zippel
//! polynomial-product checking over R_q = Z_q[X]/(X^N + 1) via random evaluation,
//! NOT in-circuit NTT. See `docs/concepts.md` for the design.
//!
//! No security guarantees are provided until a professional audit is completed.

pub mod util;
pub mod pack;
pub mod params;
pub mod ring;
pub mod range;
pub mod poly;
pub mod fiat_shamir;
pub mod proofs;

// Convenience re-exports for the public API.
pub use ring::RingElement;
pub use poly::horner::eval_at;
pub use poly::product_check::assert_poly_product;
pub use fiat_shamir::challenge::derive_challenge;
