//! Toy BFV witness generator for the noir-rlwe encryption circuits (preset bfv_1024_27).
//! UNAUDITED RESEARCH. Two schemes via `--scheme`:
//!
//! `sk` (default): secret-key encryption, matching `proofs/sk_encryption.nr`:
//!     a(X) s(X) = Delta*m(X) + e(X) - c0(X) - q*r(X) + (X^N + 1) * q_as(X)     over Z[X]
//!   Witnesses: s (ternary), e (|e|<=B), m (in [0,t)), r (mod-q quotient), q_as ((X^N+1) quotient).
//!
//! `pk`: public-key encryption, matching `proofs/pk_encryption.nr` (the fhEVM-style input statement):
//!     pk0*u = c0 - e0 - Delta*m + q*r0 + (X^N+1)*q0
//!     pk1*u = c1 - e1          + q*r1 + (X^N+1)*q1                            over Z[X]
//!   Witnesses: u (ternary), e0,e1 (|e|<=B), m (in [0,t)), r0,r1 (mod-q), q0,q1 ((X^N+1) quotients).
//!
//! Emits a `Prover.toml` (+ `Verifier.toml`). Signed coefficients are written as their BN254 field
//! representatives (a negative integer -v -> P - v).

const P_DEC: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Clone)]
struct Params {
    n: usize,
    q: i128,
    t: i128,
    b: i128, // error bound B
    delta: i128,
}

impl Params {
    /// The validated MVP preset (bfv_1024_27): n=1024, q=134215681 (27-bit NTT prime),
    /// t=65537, B=19, Delta=floor(q/t)=2047.
    fn preset() -> Self {
        Self::preset_n(1024)
    }

    /// Same q27 preset at a chosen ring degree (n=512 or 1024 for the benchmark table).
    fn preset_n(n: usize) -> Self {
        let q = 134215681i128;
        let t = 65537i128;
        Params { n, q, t, b: 19, delta: q / t }
    }
}

struct Witness {
    c0: Vec<i128>,
    c1: Vec<i128>, // = a (public)
    s: Vec<i128>,
    e: Vec<i128>,
    m: Vec<i128>,
    r: Vec<i128>,
    q_as: Vec<i128>,
}

// --- deterministic PRNG (splitmix64) ---------------------------------------

struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// --- polynomial arithmetic over Z (negacyclic ring R = Z[X]/(X^N+1)) -------

fn poly_mul(a: &[i128], b: &[i128]) -> Vec<i128> {
    let mut r = vec![0i128; a.len() + b.len() - 1];
    for (i, &ai) in a.iter().enumerate() {
        if ai != 0 {
            for (j, &bj) in b.iter().enumerate() {
                r[i + j] += ai * bj;
            }
        }
    }
    r
}

/// Divide `full` by (X^n + 1): returns (quotient, remainder) with deg(remainder) < n,
/// so `full = (X^n + 1) * quotient + remainder`. Quotient padded to length n.
fn divide_by_xn_plus_1(full: &[i128], n: usize) -> (Vec<i128>, Vec<i128>) {
    let mut f = full.to_vec();
    let mut quo = vec![0i128; n];
    for d in (n..f.len()).rev() {
        let c = f[d];
        if c != 0 {
            quo[d - n] += c;
            f[d] -= c; // cancel c*X^d (the X^n term of the divisor)
            f[d - n] -= c; // the +1 term: c*X^{d-n}
        }
    }
    (quo, f[..n].to_vec())
}

// --- witness generation ----------------------------------------------------

fn encode_message(msg: &str, n: usize, t: i128) -> Vec<i128> {
    let bytes = msg.as_bytes();
    let mut m = vec![0i128; n];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        if i >= n {
            panic!("message too long: needs <= {} bytes for n={}", 2 * n, n);
        }
        let lo = chunk[0] as i128;
        let hi = if chunk.len() > 1 { chunk[1] as i128 } else { 0 };
        let v = lo + (hi << 8); // < 65536 < t
        assert!(v < t);
        m[i] = v;
    }
    m
}

fn gen(p: &Params, seed: u64, message: Option<&str>) -> Witness {
    let mut rng = Prng(seed.wrapping_add(0x1234));
    let n = p.n;
    let a: Vec<i128> = (0..n).map(|_| rng.below(p.q as u64) as i128).collect();
    let s: Vec<i128> = (0..n).map(|_| rng.below(3) as i128 - 1).collect(); // {-1,0,1}
    let e: Vec<i128> = (0..n)
        .map(|_| rng.below((2 * p.b + 1) as u64) as i128 - p.b)
        .collect(); // [-B, B]
    let m: Vec<i128> = match message {
        Some(msg) => encode_message(msg, n, p.t),
        None => (0..n).map(|_| rng.below(p.t as u64) as i128).collect(),
    };

    let as_full = poly_mul(&a, &s);
    let (q_as, as_r) = divide_by_xn_plus_1(&as_full, n);
    let raw: Vec<i128> = (0..n).map(|i| -as_r[i] + p.delta * m[i] + e[i]).collect();
    let c0: Vec<i128> = raw.iter().map(|&x| x.rem_euclid(p.q)).collect();
    let r: Vec<i128> = (0..n).map(|i| (raw[i] - c0[i]) / p.q).collect();

    Witness { c0, c1: a, s, e, m, r, q_as }
}

/// Coefficient-wise check of the exact Z[X] identity, plus the quotient bounds. Stronger than a
/// single-point check; all intermediate magnitudes are < 2^38, well within i128.
fn verify(w: &Witness, p: &Params) {
    let n = p.n;
    let as_full = poly_mul(&w.c1, &w.s);
    let mut rhs = vec![0i128; 2 * n - 1];
    for i in 0..n {
        rhs[i] += p.delta * w.m[i] + w.e[i] - w.c0[i] - p.q * w.r[i] + w.q_as[i];
    }
    for i in 0..n {
        if i + n < 2 * n - 1 {
            rhs[i + n] += w.q_as[i]; // X^n * q_as
        } else {
            assert_eq!(w.q_as[i], 0, "q_as degree too high");
        }
    }
    assert_eq!(as_full, rhs, "Z[X] identity mismatch");
    // Uniform bounds matching the generic circuit (valid for N <= 4096): |r| < 2^13, |q_as| < 2^40.
    assert!(w.r.iter().all(|&x| x.abs() < (1i128 << 13)), "r bound (|r| < 2^13) violated");
    assert!(
        w.q_as.iter().all(|&x| x.abs() < (1i128 << 40)),
        "q_as bound (|q_as| < 2^40) violated"
    );
    assert!(w.s.iter().all(|&x| x.abs() <= 1), "s not ternary");
    assert!(w.e.iter().all(|&x| x.abs() <= p.b), "e out of bound");
    assert!(w.m.iter().all(|&x| x >= 0 && x < p.t), "m out of [0,t)");
}

// --- PUBLIC-KEY BFV witness (scheme `pk`) ----------------------------------
//
// PK encryption: c0 = [pk0*u + e0 + Delta*m]_q, c1 = [pk1*u + e1]_q, where the encryptor holds
// only pk = (pk0, pk1) = (-a*s_key + e_key, a). Two Schwartz-Zippel identities (verified in
// /tmp/pk_identity.py, matching proofs/pk_encryption.nr):
//   pk0*u = c0 - e0 - Delta*m + q*r0 + (X^N+1)*q0
//   pk1*u = c1 - e1          + q*r1 + (X^N+1)*q1

struct WitnessPk {
    pk0: Vec<i128>,
    pk1: Vec<i128>, // = a (public key second component)
    c0: Vec<i128>,
    c1: Vec<i128>,
    u: Vec<i128>,
    e0: Vec<i128>,
    e1: Vec<i128>,
    m: Vec<i128>,
    r0: Vec<i128>,
    r1: Vec<i128>,
    q0: Vec<i128>,
    q1: Vec<i128>,
}

fn gen_pk(p: &Params, seed: u64, message: Option<&str>) -> WitnessPk {
    let mut rng = Prng(seed.wrapping_add(0x1234));
    let n = p.n;
    let sample_e = |rng: &mut Prng| rng.below((2 * p.b + 1) as u64) as i128 - p.b;

    // Well-formed public key pk = (-a*s_key + e_key, a), so pk0 has coeffs in [0,q) just like a.
    let a: Vec<i128> = (0..n).map(|_| rng.below(p.q as u64) as i128).collect();
    let s_key: Vec<i128> = (0..n).map(|_| rng.below(3) as i128 - 1).collect();
    let e_key: Vec<i128> = (0..n).map(|_| sample_e(&mut rng)).collect();
    let (_, as_key_r) = divide_by_xn_plus_1(&poly_mul(&a, &s_key), n);
    let pk0: Vec<i128> = (0..n).map(|i| (-as_key_r[i] + e_key[i]).rem_euclid(p.q)).collect();
    let pk1 = a;

    // Encryption randomness.
    let u: Vec<i128> = (0..n).map(|_| rng.below(3) as i128 - 1).collect();
    let e0: Vec<i128> = (0..n).map(|_| sample_e(&mut rng)).collect();
    let e1: Vec<i128> = (0..n).map(|_| sample_e(&mut rng)).collect();
    let m: Vec<i128> = match message {
        Some(msg) => encode_message(msg, n, p.t),
        None => (0..n).map(|_| rng.below(p.t as u64) as i128).collect(),
    };

    // Relation 0: pk0*u.
    let (q0, p0u_r) = divide_by_xn_plus_1(&poly_mul(&pk0, &u), n);
    let raw0: Vec<i128> = (0..n).map(|i| p0u_r[i] + p.delta * m[i] + e0[i]).collect();
    let c0: Vec<i128> = raw0.iter().map(|&x| x.rem_euclid(p.q)).collect();
    let r0: Vec<i128> = (0..n).map(|i| (raw0[i] - c0[i]) / p.q).collect();

    // Relation 1: pk1*u.
    let (q1, p1u_r) = divide_by_xn_plus_1(&poly_mul(&pk1, &u), n);
    let raw1: Vec<i128> = (0..n).map(|i| p1u_r[i] + e1[i]).collect();
    let c1: Vec<i128> = raw1.iter().map(|&x| x.rem_euclid(p.q)).collect();
    let r1: Vec<i128> = (0..n).map(|i| (raw1[i] - c1[i]) / p.q).collect();

    WitnessPk { pk0, pk1, c0, c1, u, e0, e1, m, r0, r1, q0, q1 }
}

/// Coefficient-wise check of BOTH exact Z[X] identities + the bounds (uniform N<=4096 bounds, the
/// same the generic circuit enforces). Stronger than the single-point in-circuit check.
fn verify_pk(w: &WitnessPk, p: &Params) {
    let n = p.n;
    let check_rel = |lhs_poly: &[i128], rhs_lo: Vec<i128>, quo: &[i128], tag: &str| {
        let lhs = poly_mul(lhs_poly, &w.u);
        let mut rhs = vec![0i128; 2 * n - 1];
        for i in 0..n {
            rhs[i] += rhs_lo[i];
            if i + n < 2 * n - 1 {
                rhs[i + n] += quo[i]; // X^n * quo
            } else {
                assert_eq!(quo[i], 0, "{}: quotient degree too high", tag);
            }
        }
        assert_eq!(lhs, rhs, "{} Z[X] identity mismatch", tag);
    };
    // pk0*u == c0 - e0 - delta*m + q*r0 + (X^N+1)*q0
    let rhs0: Vec<i128> =
        (0..n).map(|i| w.c0[i] - w.e0[i] - p.delta * w.m[i] + p.q * w.r0[i] + w.q0[i]).collect();
    check_rel(&w.pk0, rhs0, &w.q0, "relation 0");
    // pk1*u == c1 - e1 + q*r1 + (X^N+1)*q1
    let rhs1: Vec<i128> =
        (0..n).map(|i| w.c1[i] - w.e1[i] + p.q * w.r1[i] + w.q1[i]).collect();
    check_rel(&w.pk1, rhs1, &w.q1, "relation 1");

    // Uniform bounds matching the generic circuit (valid for N <= 4096): |r| < 2^13, |q| < 2^40.
    let r_ok = |v: &[i128]| v.iter().all(|&x| x.abs() < (1i128 << 13));
    let q_ok = |v: &[i128]| v.iter().all(|&x| x.abs() < (1i128 << 40));
    assert!(r_ok(&w.r0) && r_ok(&w.r1), "r bound (|r| < 2^13) violated");
    assert!(q_ok(&w.q0) && q_ok(&w.q1), "q bound (|q| < 2^40) violated");
    assert!(w.u.iter().all(|&x| x.abs() <= 1), "u not ternary");
    assert!(
        w.e0.iter().all(|&x| x.abs() <= p.b) && w.e1.iter().all(|&x| x.abs() <= p.b),
        "e out of bound"
    );
    assert!(w.m.iter().all(|&x| x >= 0 && x < p.t), "m out of [0,t)");
    for v in [&w.pk0, &w.pk1, &w.c0, &w.c1] {
        assert!(v.iter().all(|&x| x >= 0 && x < p.q), "pk/ct coeff not in [0,q)");
    }
}

fn write_prover_toml_pk(w: &WitnessPk) -> String {
    let mut out = String::new();
    for (name, vals) in [
        ("pk0", &w.pk0),
        ("pk1", &w.pk1),
        ("c0", &w.c0),
        ("c1", &w.c1),
        ("u", &w.u),
        ("e0", &w.e0),
        ("e1", &w.e1),
        ("m", &w.m),
        ("r0", &w.r0),
        ("r1", &w.r1),
        ("q0", &w.q0),
        ("q1", &w.q1),
    ] {
        out.push_str(&format!("{} = {}\n", name, toml_array(vals)));
    }
    out
}

fn apply_tamper_pk(w: &mut WitnessPk, spec: &str) {
    let parts: Vec<&str> = spec.split(':').collect();
    assert_eq!(parts.len(), 3, "tamper format: name:idx:value");
    let idx: usize = parts[1].parse().expect("tamper idx");
    let val: i128 = parts[2].parse().expect("tamper value");
    let arr = match parts[0] {
        "pk0" => &mut w.pk0,
        "pk1" => &mut w.pk1,
        "c0" => &mut w.c0,
        "c1" => &mut w.c1,
        "u" => &mut w.u,
        "e0" => &mut w.e0,
        "e1" => &mut w.e1,
        "m" => &mut w.m,
        "r0" => &mut w.r0,
        "r1" => &mut w.r1,
        "q0" => &mut w.q0,
        "q1" => &mut w.q1,
        other => panic!("unknown tamper target: {}", other),
    };
    arr[idx] = val;
}

// --- field-element decimal emission (P - |v| for negatives), no bignum dep ---

fn big_sub_small(big: &str, small: u128) -> String {
    let mut digits: Vec<i32> = big.bytes().map(|c| (c - b'0') as i32).collect();
    let small_s = small.to_string();
    let small_digits: Vec<i32> = small_s.bytes().map(|c| (c - b'0') as i32).collect();
    let n = digits.len();
    let m = small_digits.len();
    let mut borrow = 0i32;
    for i in 0..n {
        let sub = if i < m { small_digits[m - 1 - i] } else { 0 } + borrow;
        let mut d = digits[n - 1 - i] - sub;
        if d < 0 {
            d += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        digits[n - 1 - i] = d;
    }
    assert_eq!(borrow, 0, "underflow: P - small went negative");
    let s: String = digits.iter().map(|d| (b'0' + *d as u8) as char).collect();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() { "0".into() } else { trimmed.into() }
}

fn field_decimal(v: i128) -> String {
    if v >= 0 {
        v.to_string()
    } else {
        big_sub_small(P_DEC, (-v) as u128)
    }
}

fn toml_array(v: &[i128]) -> String {
    let items: Vec<String> = v.iter().map(|&x| format!("\"{}\"", field_decimal(x))).collect();
    format!("[{}]", items.join(", "))
}

fn write_prover_toml(w: &Witness) -> String {
    let mut out = String::new();
    for (name, vals) in [
        ("c0", &w.c0),
        ("c1", &w.c1),
        ("s", &w.s),
        ("e", &w.e),
        ("m", &w.m),
        ("r", &w.r),
        ("q_as", &w.q_as),
    ] {
        out.push_str(&format!("{} = {}\n", name, toml_array(vals)));
    }
    out
}

fn write_verifier_toml(w: &Witness) -> String {
    // Public inputs only: c0, c1.
    format!("c0 = {}\nc1 = {}\n", toml_array(&w.c0), toml_array(&w.c1))
}

// --- CLI -------------------------------------------------------------------

fn apply_tamper(w: &mut Witness, spec: &str) {
    let parts: Vec<&str> = spec.split(':').collect();
    assert_eq!(parts.len(), 3, "tamper format: name:idx:value");
    let idx: usize = parts[1].parse().expect("tamper idx");
    let val: i128 = parts[2].parse().expect("tamper value");
    let arr = match parts[0] {
        "c0" => &mut w.c0,
        "c1" => &mut w.c1,
        "s" => &mut w.s,
        "e" => &mut w.e,
        "m" => &mut w.m,
        "r" => &mut w.r,
        "q_as" => &mut w.q_as,
        other => panic!("unknown tamper target: {}", other),
    };
    arr[idx] = val;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut out = "Prover.toml".to_string();
    let mut verifier_out = "Verifier.toml".to_string();
    let mut seed: u64 = 1;
    let mut message: Option<String> = None;
    let mut tamper: Option<String> = None;
    let mut n: usize = 1024;
    let mut scheme = "sk".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--out" => { out = args[i + 1].clone(); i += 2; }
            "--verifier-out" => { verifier_out = args[i + 1].clone(); i += 2; }
            "--seed" => { seed = args[i + 1].parse().expect("seed"); i += 2; }
            "--message" => { message = Some(args[i + 1].clone()); i += 2; }
            "--tamper" => { tamper = Some(args[i + 1].clone()); i += 2; }
            "--n" => { n = args[i + 1].parse().expect("n"); i += 2; }
            "--scheme" => { scheme = args[i + 1].clone(); i += 2; }
            "-h" | "--help" => {
                eprintln!(
                    "witness-gen [--scheme sk|pk] [--out P] [--verifier-out V] [--seed N] \\\n\
                     \t[--message S] [--tamper name:idx:val] [--n N]\n\
                     Preset: bfv_1024_27 (n=1024, q=134215681, t=65537, B=19).\n\
                     scheme sk: secret-key encryption (witnesses s,e,m,r,q_as).\n\
                     scheme pk: public-key encryption (pk0,pk1,c0,c1 + witnesses u,e0,e1,m,r0,r1,q0,q1)."
                );
                return;
            }
            other => { eprintln!("unknown arg: {}", other); std::process::exit(2); }
        }
    }

    let p = Params::preset_n(n);

    match scheme.as_str() {
        "sk" => {
            let mut w = gen(&p, seed, message.as_deref());
            verify(&w, &p); // honest witness must satisfy the identity + bounds
            if let Some(spec) = tamper {
                apply_tamper(&mut w, &spec); // applied AFTER the honest check (negative tests)
                eprintln!("applied tamper: {} (witness now INVALID by design)", spec);
            }
            std::fs::write(&out, write_prover_toml(&w)).expect("write Prover.toml");
            std::fs::write(&verifier_out, write_verifier_toml(&w)).expect("write Verifier.toml");
        }
        "pk" => {
            let mut w = gen_pk(&p, seed, message.as_deref());
            verify_pk(&w, &p);
            if let Some(spec) = tamper {
                apply_tamper_pk(&mut w, &spec);
                eprintln!("applied tamper: {} (witness now INVALID by design)", spec);
            }
            std::fs::write(&out, write_prover_toml_pk(&w)).expect("write Prover.toml");
            // Digest circuit: the single public input is the returned digest (computed by
            // `nargo execute`), so there is nothing to write for the verifier here.
            std::fs::write(
                &verifier_out,
                "# pk uses the digest circuit: the lone public input is the returned digest\n\
                 # (= H(pk0||pk1||c0||c1)), computed in-circuit by `nargo execute`.\n",
            )
            .expect("write Verifier.toml");
        }
        other => {
            eprintln!("unknown scheme: {} (expected sk or pk)", other);
            std::process::exit(2);
        }
    }

    eprintln!(
        "wrote {} and {} (scheme={}, n={}, q={}, t={}, B={}, seed={})",
        out, verifier_out, scheme, p.n, p.q, p.t, p.b, seed
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_is_valid_for_several_seeds() {
        let p = Params::preset();
        for seed in 0..20 {
            let w = gen(&p, seed, None);
            verify(&w, &p);
        }
    }

    #[test]
    fn gen_pk_is_valid_for_several_seeds() {
        for &n in &[512usize, 1024] {
            let p = Params::preset_n(n);
            for seed in 0..15 {
                let w = gen_pk(&p, seed, None);
                verify_pk(&w, &p); // both Z[X] identities + all bounds
            }
        }
    }

    #[test]
    fn message_encoding_roundtrips_into_range() {
        let p = Params::preset();
        let w = gen(&p, 7, Some("hello, rlwe"));
        verify(&w, &p);
        assert_eq!(w.m[0], b'h' as i128 + ((b'e' as i128) << 8));
    }

    #[test]
    fn field_decimal_negatives() {
        assert_eq!(field_decimal(5), "5");
        assert_eq!(
            field_decimal(-1),
            "21888242871839275222246405745257275088548364400416034343698204186575808495616"
        );
        // P - 19
        assert_eq!(
            field_decimal(-19),
            "21888242871839275222246405745257275088548364400416034343698204186575808495598"
        );
    }
}
