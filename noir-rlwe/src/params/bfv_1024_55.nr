//! Single ~55-bit NTT-friendly prime preset. q = 36028797018972161 is prime, q = 1 (mod 2048),
//! and 2^55 < q < 2^56 (so LOG_Q = 56).
//!
//! !!! SECURITY WARNING !!! At n=1024 this modulus gives only ~63-bit RLWE security (lattice-estimator;
//! see docs/parameter_security.md) -- it is NOT cryptographically secure for real encryption. For a
//! fixed n, a larger q is LESS secure; the HE standard caps n=1024 at log q <= 27 for 128 bits. There
//! is no in-circuit soundness benefit either (the Schwartz-Zippel gamma is full-field, independent of q).
//! USE bfv_1024_27 FOR REAL ENCRYPTION. This preset is a circuit-arithmetic test vector only (it
//! exercises 56-bit-coefficient witnesses); to use a 55-bit modulus securely, pair it with n>=2048.

pub global N: u32 = 1024;
pub global LOG_N: u32 = 10;
pub global Q: Field = 36028797018972161; // 2^55 < q < 2^56
pub global LOG_Q: u32 = 56; // Q < 2^LOG_Q (q needs 56 bits)
pub global T: Field = 65537;
pub global LOG_T: u32 = 17;
pub global DELTA: Field = 549747425408; // floor(Q / T)
pub global B_KEY: Field = 1;
pub global B_ERR: Field = 19;
pub global LOG_B_ERR_P1: u32 = 5;
