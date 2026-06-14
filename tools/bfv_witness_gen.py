#!/usr/bin/env python3
"""Toy SK-BFV witness generator for the noir-rlwe sk_enc_circuit (preset bfv_1024_27).

Produces a valid (c0, c1, s, e, m, r, q_as) satisfying the exact Schwartz-Zippel identity
  a(X) s(X) = Delta m(X) + e(X) - c0(X) - q r(X) + (X^N + 1) q_as(X)   over Z[X]
and emits Prover.toml. Signed coefficients are written as BN254 field representatives.

This is the Phase-2 validation generator (Python). The production witness generator is Rust
(attack plan 2.3); this proves the circuit is correct end to end first.
"""
import random, sys

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
N, q, t, B = 1024, 134215681, 65537, 19
DELTA = q // t  # 2047

def polymul(a, b):
    r = [0]*(len(a)+len(b)-1)
    for i, ai in enumerate(a):
        if ai:
            for j, bj in enumerate(b):
                r[i+j] += ai*bj
    return r

def divide_by_xn_plus_1(full, n):
    f = full[:]
    quo = [0]*max(1, len(f)-n)
    for d in range(len(f)-1, n-1, -1):
        c = f[d]
        if c:
            quo[d-n] += c
            f[d]   -= c
            f[d-n] -= c
    return quo, f[:n]

def fld(v):       # signed int -> field representative
    return v % P

def gen(seed=1, tamper=None):
    random.seed(seed)
    a = [random.randrange(q) for _ in range(N)]
    s = [random.choice([-1, 0, 1]) for _ in range(N)]
    e = [random.randrange(-B, B+1) for _ in range(N)]
    m = [random.randrange(t) for _ in range(N)]

    as_full = polymul(a, s)
    q_as, as_R = divide_by_xn_plus_1(as_full, N)
    if len(q_as) < N:
        q_as = q_as + [0]*(N - len(q_as))
    raw = [-as_R[i] + DELTA*m[i] + e[i] for i in range(N)]
    c0  = [raw[i] % q for i in range(N)]
    r   = [(raw[i] - c0[i]) // q for i in range(N)]

    # sanity: identity at a random gamma over Z
    g = random.randrange(2**80)
    ev = lambda poly: sum(c*g**i for i, c in enumerate(poly))
    lhs = ev(a)*ev(s)
    rhs = DELTA*ev(m) + ev(e) - ev(c0) - q*ev(r) + (g**N + 1)*ev(q_as)
    assert lhs == rhs, "identity check failed"
    assert max(abs(x) for x in r) < 2048, "r bound violated"
    assert max(abs(x) for x in q_as) < 2**38, "q_as bound violated"

    wit = {"c0": c0, "c1": a, "s": s, "e": e, "m": m, "r": r, "q_as": q_as}
    if tamper:
        name, idx, val = tamper
        wit[name] = wit[name][:]
        wit[name][idx] = val
    return wit

def emit_toml(wit, path):
    def arr(vals):
        return "[" + ", ".join('"%d"' % fld(v) for v in vals) + "]"
    with open(path, "w") as f:
        for name in ["c0", "c1", "s", "e", "m", "r", "q_as"]:
            f.write("%s = %s\n" % (name, arr(wit[name])))

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "Prover.toml"
    wit = gen(seed=int(sys.argv[2]) if len(sys.argv) > 2 else 1)
    emit_toml(wit, out)
    print("wrote", out, "(valid witness; identity + bounds verified)")
