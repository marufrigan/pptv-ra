# PPTV-RA: Privacy-Preserving Transaction Validation with Regulatory Auditability

Prototype and evaluation code for the paper *A Privacy-Preserving and Auditable Transaction Validation Framework for Permissioned Blockchain Banking Systems* (M. Farhan).

## What is implemented (`src/`)
- **Committed account model**: balances and amounts as twisted ElGamal ciphertexts over Ristretto255, with decryption handles for sender, receiver and regulator committee; 32-bit limbs; available/pending balances with owner rollover.
- **Algorithm 1** (`protocol::create_tx`): limb commitments, handles, ciphertext-validity sigma proofs, balance-equality sigma proof, aggregated 4 x 32-bit Bulletproof, Ed25519 signature.
- **Algorithm 2** (`protocol::verify_tx`): nonce, signature, validity, balance and range checks (no plaintext).
- **Algorithm 4** (`protocol::partial_decrypt`, `combine_disclose`): t-of-n regulator committee with Chaum-Pedersen (DLEQ) proofs bound to the logged request id.
- 13 security/correctness tests and micro-benchmarks (`src/main.rs`).

No trusted setup is required.

## Run
```bash
cargo run --release -- 200 results/crypto_bench.json          # tests + benchmarks
python3 sim/simulate.py results/crypto_bench.json results/sim.json   # consensus, trust, quorum simulation
cd figures/scripts && python3 fig_arch.py && python3 fig_seq.py && python3 fig_misc.py && python3 fig_results.py
```
Requires Rust 1.75+ and Python 3.10+ with numpy and matplotlib.

## Key results (2 vCPU container)
| Quantity | Value |
|---|---|
| Prove transfer | 23.9 ms |
| Verify transfer | 4.11 ms (range 2.54, validity 0.80, balance 0.62, signature 0.15) |
| Record size | 1,808 bytes (range proof 736) |
| Verification throughput | 254 tx/s per core |
| 3-of-5 disclosure | 13.4 ms |
| Honest nodes falsely excluded (simulation) | 0 of 500 runs |
| Rounds with Byzantine share above 1/3 | 1.9% gated vs 100% static |

## Layout
`src/` prototype · `sim/` Monte Carlo simulator · `results/` outputs reported in the paper · `figures/` diagrams and charts with their scripts.
