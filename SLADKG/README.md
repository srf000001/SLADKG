# SLADKG

Signature-free lattice-based distributed key generation / secret sharing demo (Python).

## Parameter Sets

### Parameter Set A (default in `SLACSS.py`)

- **Number of participants (N)**: 6
- **Threshold (T)**: 2
- **sigma_x**: 1.00
- **sigma_y**: 18.36 (= √337 × sigma_x)
- **slack_factor**: 10.0
- **Algebraic setting**: Module lattice \(R_q^k\)
  - **Base ring** \(R_q\): \(\mathbb{Z}_q[X]/(X^8 + 1)\)
  - **Modulus** \(q\): 12289
  - **Ring dimension** \(n\): 8
  - **Module rank** \(k\) (a.k.a. \(d\)): 4
- **Bound**: slack_factor × σ_v × √(d × ring_degree)
- **Encryption**: X25519 KEM + AES-256-GCM (Ed25519 signatures)

### Parameter Set B (new)

- **Ring dimension** \(n\): 256 (i.e., \(R_q = \mathbb{Z}_q[X]/(X^{256} + 1)\))
- **Modulus** \(q\): \(2^{32} - 99\) (= 4294967197)

> Note: this README only documents the additional parameter set. To actually run with Parameter Set B,
> you also need to update the corresponding constants in code (e.g., `RING_DEGREE` and `PRIME`).

## Requirements

- **Python**: 3.10.12 or newer
- **Python packages**: install all imported packages (at least `numpy`)
- **Tongsuo**: build Tongsuo and make `libcrypto` discoverable by the Python wrapper
  - Clone and build: `https://github.com/Tongsuo-Project/Tongsuo.git`
  - Runtime: place `libcrypto.so` in `SLADKG/Tongsuo/` or set `TONGSUO_LIBCRYPTO_PATH`

## How to Run

From the project root:

```bash
python3 SLACSS.py
```
