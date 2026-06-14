# noir-rlwe-witness-gen

> **UNAUDITED RESEARCH.** Toy SK-BFV witness generator for the `sk_enc_circuit` (preset `bfv_1024_27`).

Generates a valid secret-key BFV encryption and emits Nargo `Prover.toml` / `Verifier.toml`
matching the exact Schwartz-Zippel identity the circuit proves:

```
a(X) s(X) = Delta*m(X) + e(X) - c0(X) - q*r(X) + (X^N + 1) * q_as(X)   over Z[X]
```

It is a **zero-dependency** pure-Rust implementation (integer/polynomial arithmetic only):
fast compile, offline, no Apple-Silicon issues. The honest witness is checked coefficient-wise
against the identity and the quotient bounds (`|r| < 2^11`, `|q_as| < 2^38`) before emission.

> Swapping in a production library (fhe.rs / OpenFHE / SEAL) for standardized parameters is a
> follow-up: it requires recovering `e` (= `c0 + a*s - Delta*m` centered) and recomputing the
> quotients `r`, `q_as`, and matching their modulus to the circuit's `q = 134215681`.

## Usage

```bash
cargo build --release

# valid witness from an ASCII message (packed 2 bytes/coefficient into m)
./target/release/witness-gen --out Prover.toml --verifier-out Verifier.toml \
    --seed 42 --message "noir-rlwe vFHE"

# random plaintext
./target/release/witness-gen --seed 7

# negative-test witnesses (tamper applied AFTER the honest identity check)
./target/release/witness-gen --tamper e:0:20      # out-of-bound error  -> circuit rejects
./target/release/witness-gen --tamper q_as:5:99   # wrong quotient      -> circuit rejects
./target/release/witness-gen --tamper c0:0:12345  # tampered ciphertext -> circuit rejects
```

Then drive the circuit:

```bash
cd ../bench/circuit
nargo execute witness          # "Circuit witness successfully solved" for a valid witness
bb prove  -b ./target/sk_enc_circuit.json -w ./target/witness.gz -o ./proof_out --write_vk
bb verify -k ./proof_out/vk -p ./proof_out/proof -i ./proof_out/public_inputs
```

Flags: `--out`, `--verifier-out`, `--seed`, `--message`, `--tamper name:idx:value`.
Preset is fixed to bfv_1024_27 (n=1024, q=134215681, t=65537, B=19).

`cargo test` checks the identity over 20 seeds, message encoding, and field-representative
emission. Witness generation takes ~0.6 s at n=1024.
