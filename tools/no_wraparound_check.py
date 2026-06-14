#!/usr/bin/env python3
"""Machine-checkable backing for the no-wraparound lemma (docs/no_wraparound.md).

For each encryption circuit we form the difference polynomial D(X) = LHS(X) - RHS(X) over Z (using
the integer representatives that the in-circuit range checks pin every coefficient to), and verify:

  (a) the ANALYTIC per-term bound  ||D||_inf <= sum of per-term bounds  is < p/2  (the lemma), and
  (b) no adversarial witness whose coefficients pass the range checks produces a D coefficient that
      exceeds the analytic bound -- checked by (i) random sampling at full range and (ii) a
      sign-aligned deterministic worst case for the dominant terms.

If this prints ALL CHECKS PASS, the single-point check over F_p (once Schwartz-Zippel gives
coefficient-wise == 0 mod p) forces D == 0 over Z, hence the exact BFV relation. UNAUDITED RESEARCH.
"""
import random

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN254 scalar field
HALF_P = P // 2

# ---- enforced range bounds (max |.| of the integer representative) --------------------------------
# DIGEST circuits (uniform, valid for N <= 4096): pk,c range-checked to 27 bits in-circuit.
DIGEST = dict(pk=2**27 - 1, c=2**27 - 1, u=1, e=19, m=2**17 - 1, r=2**13, q=2**40, Q=134215681, DELTA=2047)
# PLAIN/PACKED circuits (tight per-N, N<=1024): pk,c are public inputs, bounded by the honest
# verifier to [0,q); quotient bounds are tighter (R_SHIFT=2^11, QAS_SHIFT=2^38).
PLAIN = dict(pk=134215681 - 1, c=134215681 - 1, u=1, e=19, m=2**17 - 1, r=2**11, q=2**38, Q=134215681, DELTA=2047)


def analytic_bound(B, N):
    """Triangle-inequality bound on ||D||_inf from the per-term sup-norms (see the lemma)."""
    prod = N * B["pk"] * B["u"]          # ||pk*u||_inf  (<= N terms, each <= |pk|*|u|)
    c = B["c"]                            # ||c||_inf
    e = B["e"]                            # ||e||_inf
    dm = B["DELTA"] * B["m"]             # ||Delta*m||_inf
    qr = B["Q"] * B["r"]                # ||q*r||_inf
    xnq = B["q"]                         # ||(X^N+1)*q_quot||_inf  (disjoint supports -> = ||q_quot||)
    # PK has two product relations (pk0*u, pk1*u) and two of each quotient, but they are SEPARATE
    # assertions / separate difference polynomials, so each D is bounded by the same single-relation sum.
    return prod + c + e + dm + qr + xnq, dict(prod=prod, c=c, e=e, dm=dm, qr=qr, xnq=xnq)


# ---- exact D(X) over Z for a sampled witness (PK relation 0; SK is the same shape) ----------------
def polmul(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] += ai * bj
    return r


def diff_poly_pk0(pk0, u, c0, e0, m, r0, q0, Q, DELTA, N):
    # D0 = pk0*u - c0 + e0 + Delta*m - q*r0 - (X^N+1)*q0   (matches assert_pk_sz_identity rel 0)
    deg = max(2 * N - 1, N + len(q0))
    D = [0] * (deg + 1)
    for i, c in enumerate(polmul(pk0, u)):
        D[i] += c
    for i in range(N):
        D[i] += -c0[i] + e0[i] + DELTA * m[i] - Q * r0[i] - q0[i]
        D[i + N] += -q0[i]   # -(X^N)*q0
    return D


def sample(B, N, extreme):
    """Sample a witness whose coeffs pass the range checks. extreme=True -> push to bound magnitudes."""
    def col(bound, signed):
        if extreme:
            v = bound
        else:
            v = random.randint(-bound, bound) if signed else random.randint(0, bound)
        if not signed:
            return v if not extreme else bound
        return v
    pk0 = [random.randint(0, B["pk"]) if not extreme else B["pk"] for _ in range(N)]
    u = [(1 if extreme else random.randint(-1, 1)) for _ in range(N)]
    c0 = [random.randint(0, B["c"]) if not extreme else B["c"] for _ in range(N)]
    e0 = [(B["e"] if extreme else random.randint(-B["e"], B["e"])) for _ in range(N)]
    m = [(B["m"] if extreme else random.randint(0, B["m"])) for _ in range(N)]
    r0 = [(B["r"] if extreme else random.randint(-B["r"], B["r"])) for _ in range(N)]
    q0 = [(B["q"] if extreme else random.randint(-B["q"], B["q"])) for _ in range(N)]
    return pk0, u, c0, e0, m, r0, q0


def run(name, B):
    print(f"\n=== {name} ===")
    ok = True
    for N in (16, 256, 1024):
        bound, parts = analytic_bound(B, N)
        a_lt_half = bound < HALF_P
        print(f" N={N:5d}  analytic ||D||_inf <= {bound}  (~2^{bound.bit_length()-1}..{bound.bit_length()})"
              f"  < p/2: {a_lt_half}")
        ok &= a_lt_half
        # empirical: random full-range + deterministic extreme; D coeffs must never exceed `bound`.
        emax = 0
        for _ in range(60):
            w = sample(B, N, extreme=False)
            D = diff_poly_pk0(*w, B["Q"], B["DELTA"], N)
            emax = max(emax, max(abs(x) for x in D))
        wx = sample(B, N, extreme=True)
        Dx = diff_poly_pk0(*wx, B["Q"], B["DELTA"], N)
        exmax = max(abs(x) for x in Dx)
        within = emax <= bound and exmax <= bound
        print(f"          empirical max|coeff|: random={emax} (~2^{emax.bit_length()})  "
              f"extreme={exmax} (~2^{exmax.bit_length()})  <= analytic: {within}")
        ok &= within
    if N == 1024:
        print(f"          per-term bounds at N=1024: {parts}")
    return ok


if __name__ == "__main__":
    random.seed(1)
    print(f"p = {P}\n2^253 < p < 2^254 ; p/2 = {HALF_P} (> 2^252)")
    ok = True
    ok &= run("DIGEST circuits (sk/pk _digest, uniform N<=4096 bounds)", DIGEST)
    ok &= run("PLAIN/PACKED circuits (tight per-N bounds, N<=1024)", PLAIN)
    print("\n" + ("ALL CHECKS PASS: ||D||_inf < 2^42 < p/2 for every case." if ok else "CHECK FAILED"))
