//! Horner evaluation of a degree-(N-1) polynomial at a field point. Evaluation is over
//! the full BN254 field (NON-reducing): the Schwartz-Zippel check accounts for the ring
//! structure via quotient polynomials, so no per-step mod-q reduction is needed.
//!
//! Cost (measured, Phase 0 Exp B): exactly N-1 multiply opcodes; additions are free.

/// Evaluate `coeffs[0] + coeffs[1]*gamma + ... + coeffs[N-1]*gamma^(N-1)` at `gamma`.
pub fn eval_at<let N: u32>(coeffs: [Field; N], gamma: Field) -> Field {
    let mut acc = coeffs[N - 1];
    for i in 1..N {
        acc = acc * gamma + coeffs[N - 1 - i];
    }
    acc
}

mod tests {
    use super::eval_at;

    #[test]
    fn eval_constant() {
        let mut c = [0; 8];
        c[0] = 5;
        assert(eval_at(c, 12345) == 5);
    }

    #[test]
    fn eval_linear() {
        // 2 + 3X at 7 = 23
        let mut c = [0; 8];
        c[0] = 2;
        c[1] = 3;
        assert(eval_at(c, 7) == 23);
    }

    #[test]
    fn eval_cubic() {
        // 5 + 2X + X^3 at 3 = 5 + 6 + 27 = 38
        let mut c = [0; 8];
        c[0] = 5;
        c[1] = 2;
        c[3] = 1;
        assert(eval_at(c, 3) == 38);
    }

    #[test]
    fn eval_monomial() {
        // X^5 at 2 = 32
        let mut c = [0; 8];
        c[5] = 1;
        assert(eval_at(c, 2) == 32);
    }
}
