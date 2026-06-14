#!/usr/bin/env python3
"""Independent reference-decryption validation of the witness generator's BFV encryption.

The Rust/Python witness generators self-check the *circuit identity* (well-formedness). This script
cross-checks the *scheme* with a DIFFERENT operation: it re-encrypts (matching the generator's formulas)
and then DECRYPTS with the secret key, asserting the plaintext is recovered. Encryption and decryption
are independent computations, so recovery validates the encryption logic (a sign error would not decrypt).

It also characterizes the decryption NOISE vs the BFV budget Delta/2 at the q27/t65537 preset, for both
SK and PK. Decryptability is explicitly out of scope for the proof (the circuit proves the *relation*,
not decryptability) -- but knowing whether the demo params yield a usable scheme is worth recording.
UNAUDITED RESEARCH.
"""
import random
import numpy as np

Q, T, B = 134215681, 65537, 19
DELTA = Q // T            # 2047
N = 1024


def polmul(a, b):
    # C-speed convolution; all intermediate products/sums (< N*q^2-ish here, in fact < 2^38) fit int64.
    return list(np.convolve(np.asarray(a, dtype=np.int64), np.asarray(b, dtype=np.int64)))


def negacyclic(full, n):
    """Reduce mod (X^n + 1): out[i] = full[i] - full[i+n]."""
    out = [0] * n
    for k, c in enumerate(full):
        if k < n:
            out[k] += c
        else:
            out[k - n] -= c
    return out


def center(v):
    v %= Q
    return v - Q if v > Q // 2 else v


def decrypt(c0, c1, s):
    """Floor-Delta BFV: v = [c0 + c1*s]_q = Delta*m + e_total; m = round(v / Delta) mod t. (Using
    round(t*v/q) instead is wrong here because Delta=floor(q/t) with large t makes t*Delta/q ~ 0.9995,
    drifting ~30 per unit m.) Returns (m', max |e_total|)."""
    cs = negacyclic(polmul(c1, s), N)
    m_out, noise = [], 0
    for i in range(N):
        v = (c0[i] + cs[i]) % Q                      # = Delta*m + e_total in [0, q)
        k = round(v / DELTA)
        m_out.append(k % T)
        noise = max(noise, abs(v - DELTA * k))       # |e_total| at this coefficient
    return m_out, noise


def gen_sk(rng):
    a = [rng.randrange(Q) for _ in range(N)]
    s = [rng.randrange(3) - 1 for _ in range(N)]
    e = [rng.randrange(-B, B + 1) for _ in range(N)]
    m = [rng.randrange(T) for _ in range(N)]
    asr = negacyclic(polmul(a, s), N)
    c0 = [(-asr[i] + DELTA * m[i] + e[i]) % Q for i in range(N)]
    return c0, a, s, m


def gen_pk(rng):
    a = [rng.randrange(Q) for _ in range(N)]
    sk = [rng.randrange(3) - 1 for _ in range(N)]
    ek = [rng.randrange(-B, B + 1) for _ in range(N)]
    pk0 = [(-negacyclic(polmul(a, sk), N)[i] + ek[i]) % Q for i in range(N)]
    pk1 = a
    u = [rng.randrange(3) - 1 for _ in range(N)]
    e0 = [rng.randrange(-B, B + 1) for _ in range(N)]
    e1 = [rng.randrange(-B, B + 1) for _ in range(N)]
    m = [rng.randrange(T) for _ in range(N)]
    c0 = [(negacyclic(polmul(pk0, u), N)[i] + e0[i] + DELTA * m[i]) % Q for i in range(N)]
    c1 = [(negacyclic(polmul(pk1, u), N)[i] + e1[i]) % Q for i in range(N)]
    return c0, c1, sk, m


def run(label, gen, trials=20):
    ok = 0
    maxnoise = 0
    for seed in range(trials):
        rng = random.Random(1000 + seed)
        if label == "SK":
            c0, c1, s, m = gen(rng)          # c1 = a
        else:
            c0, c1, s, m = gen(rng)          # s = s_key
        m2, noise = decrypt(c0, c1, s)
        maxnoise = max(maxnoise, noise)
        if m2 == m:
            ok += 1
    budget = DELTA // 2
    print(f"{label}: decrypted correctly {ok}/{trials};  max |e_total| = {maxnoise}  "
          f"(budget Delta/2 = {budget};  {'WITHIN' if maxnoise < budget else 'EXCEEDS'} budget)")
    return ok, trials, maxnoise, budget


if __name__ == "__main__":
    print(f"preset q27: q={Q}, t={T}, Delta={DELTA}, B={B}, N={N}\n")
    sk = run("SK", lambda r: gen_sk(r))
    pk = run("PK", lambda r: gen_pk(r))
    print()
    print("SK: noise is just |e| <= B, well inside Delta/2 -> faithful, decryptable BFV." )
    print("PK: fresh-encryption noise e_total = <e_key*u> + e0 + <e1*s_key> is a ring convolution")
    print("    (~B*sqrt(N) per coeff) and EXCEEDS Delta/2 at t=65537 -> ciphertext is WELL-FORMED")
    print("    (what the circuit proves) but NOT reliably decryptable at this preset. A usable PK-FHE")
    print("    deployment needs a smaller t (larger Delta) / more noise budget. Decryptability is")
    print("    out of scope for the proof (security.md §1).")
