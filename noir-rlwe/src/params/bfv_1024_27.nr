//! Greco benchmark preset `sk_enc_1024_1x27_65537` (MVP target).
//! q = 134215681 is the largest prime < 2^27 with q = 1 (mod 2048) -> NTT-friendly
//! for n=1024. Validated in Phase 0 (Go decision, 142,789-gate full circuit).

pub global N: u32 = 1024;
pub global LOG_N: u32 = 10; // log2(N)
pub global Q: Field = 134215681; // ciphertext modulus, < 2^27
pub global LOG_Q: u32 = 27; // Q < 2^LOG_Q
pub global T: Field = 65537; // plaintext modulus, < 2^17
pub global LOG_T: u32 = 17; // T < 2^LOG_T
pub global DELTA: Field = 2047; // floor(Q / T)
pub global B_KEY: Field = 1; // ternary key bound
pub global B_ERR: Field = 19; // 6-sigma error bound (sigma = 3.2)
pub global LOG_2BERR_P1: u32 = 6; // ceil(log2(2*B_ERR + 1)) = ceil(log2(39)) = 6

// Schwartz-Zippel quotient-polynomial bounds (derived Phase 2; see lab notebook 10.3).
// r = mod-q quotient: |r_i| <= N+2 = 1026 < 2^11. Symmetric check shifts by R_SHIFT.
pub global R_SHIFT: Field = 2048; // 2^11
pub global LOG_R_RANGE: u32 = 12; // r + R_SHIFT < 2^12
// q_as = (X^N+1) product quotient: |q_as_i| <= (N-1)*Q ~= 2^37 < 2^38. Shift by QAS_SHIFT.
pub global QAS_SHIFT: Field = 274877906944; // 2^38
pub global LOG_QAS_RANGE: u32 = 39; // q_as + QAS_SHIFT < 2^39
