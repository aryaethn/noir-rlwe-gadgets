#!/usr/bin/env python3
"""Machine-checkable backing for the quotient-bound completeness lemma (docs/completeness.md).

The circuits range-check the prover-supplied quotient polynomials: |r| < 2^13 and |q| < 2^40 (uniform
N<=4096 windows). Completeness asks the converse of the no-wraparound (soundness) lemma: does an HONEST
witness -- the r, q computed by genuine BFV encryption from inputs in the declared coefficient ranges --
always satisfy those checks? We verify:

  (a) the ANALYTIC worst-case bounds  ||q||_inf <= (N-1)(q-1) < 2^40  and  ||r||_inf <= N+2 < 2^13
      hold for all N <= 4096 (so the circuit ACCEPTS every genuine encryption), and
  (b) no input in the declared ranges -- random, or the sign-aligned extreme that maximizes the
      quotients -- produces an r or q outside the enforced window.

Inputs use the witness generator's representation: pk0,pk1,a in [0,q) (unsigned reduced), u,s ternary,
|e|<=B, m in [0,t). UNAUDITED RESEARCH.
"""
import random

Q = 134215681      # ciphertext modulus q < 2^27
T = 65537          # plaintext modulus
B = 19             # error bound
DELTA = Q // T     # = 2047
R_WIN = 2**13      # enforced: |r| < 2^13
Q_WIN = 2**40      # enforced: |q| < 2^40


def polmul(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i + j] += ai * bj
    return r


def div_xn1(full, n):
    """full = (X^n+1)*quo + rem, deg(rem)<n; quo padded to length n. Mirrors the Rust/Noir witness gen."""
    f = list(full)
    quo = [0] * n
    for d in range(len(f) - 1, n - 1, -1):
        c = f[d]
        if c:
            quo[d - n] += c
            f[d] -= c
            f[d - n] -= c
    return quo, f[:n]


def encrypt_relation(base, u, add, n):
    """One BFV ring relation: given base (pk0/pk1/a, in [0,q)), ternary u, and an additive small part
    `add` (= Delta*m + e for c0, or e for c1), return the honest quotients (q_quot, r). Mirrors gen_pk."""
    q_quot, reduced = div_xn1(polmul(base, u), n)        # (X^n+1) quotient + negacyclic remainder
    raw = [reduced[i] + add[i] for i in range(n)]
    c = [raw[i] % Q for i in range(n)]                    # rem_euclid into [0,q)
    r = [(raw[i] - c[i]) // Q for i in range(n)]           # mod-q quotient = floor(raw/q)
    return q_quot, r


def analytic(n):
    return (n - 1) * (Q - 1), n + 2     # ||q||_inf bound, ||r||_inf bound


def maxabs(v):
    return max(abs(x) for x in v)


def trial(n, mode):
    """mode: 'random' honest inputs, or 'extreme' sign-aligned worst case for the quotients."""
    if mode == "random":
        base = [random.randrange(Q) for _ in range(n)]
        u = [random.randrange(3) - 1 for _ in range(n)]
        e = [random.randrange(-B, B + 1) for _ in range(n)]
        m = [random.randrange(T) for _ in range(n)]
    else:  # extreme: base=q-1, u=+1 (maximizes the product), m=t-1, e=B (maximizes raw -> r)
        base = [Q - 1] * n
        u = [1] * n
        e = [B] * n
        m = [T - 1] * n
    add = [DELTA * m[i] + e[i] for i in range(n)]
    q_quot, r = encrypt_relation(base, u, add, n)
    return maxabs(q_quot), maxabs(r)


def run():
    print(f"q={Q} (<2^27), t={T}, B={B}, Delta={DELTA}; enforced |r|<2^13={R_WIN}, |q|<2^40={Q_WIN}")
    ok = True
    print("\n-- analytic worst-case bounds (all N<=4096) --")
    for n in (16, 256, 1024, 2048, 4096):
        qb, rb = analytic(n)
        within = qb < Q_WIN and rb < R_WIN
        ok &= within
        print(f" N={n:5d}  ||q||<= (N-1)(q-1) = {qb} (~2^{qb.bit_length()-1}) <2^40:{qb<Q_WIN} ;"
              f"  ||r||<= N+2 = {rb} <2^13:{rb<R_WIN}")
    print("\n-- empirical (honest inputs in range; r,q derived by exact encryption) --")
    for n in (16, 256, 1024):
        rq = [trial(n, "random") for _ in range(50)]
        rqx = trial(n, "extreme")
        eq = max(x[0] for x in rq); er = max(x[1] for x in rq)
        qb, rb = analytic(n)
        good = (eq <= qb and er <= rb and rqx[0] <= qb and rqx[1] <= rb
                and rqx[0] < Q_WIN and rqx[1] < R_WIN)
        ok &= good
        print(f" N={n:5d}  random: max|q|={eq} (~2^{eq.bit_length()}), max|r|={er} ;"
              f"  extreme: |q|={rqx[0]} (~2^{rqx[0].bit_length()}), |r|={rqx[1]}  within&<window:{good}")
    print("\n" + ("ALL CHECKS PASS: honest quotients satisfy |q|<2^40 and |r|<2^13 for all N<=4096."
                  if ok else "CHECK FAILED"))


if __name__ == "__main__":
    random.seed(2)
    run()
