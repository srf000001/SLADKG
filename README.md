# Signature-free Lattice-Based Distributed Key Generation without PKI setup Implementation

**SLADKG** is a paper that is undergoing peer review and is currently submitted to USENIX Security 2026.

The **SLADKG** project is implemented using Python 3.10.12 and integrates the Tongsuo cryptographic library for secure cryptographic primitives. The following provides an overview of the project structure, dependencies, and usage instructions.

> **Note**: This repository is not a complete implementation, but the correctness of the technology can be verified. The code will be updated after organization and refinement.

## Quick Start

### Prerequisites

- Python 3.10.12 or higher
- Rust 1.84 or higher
- All required Python packages (see Dependencies section)
- Tongsuo cryptographic library (see Installation section)

### Installation

1. **Clone Tongsuo Project**:
   ```bash
   cd SLADKG
   git clone https://github.com/Tongsuo-Project/Tongsuo.git
   cd Tongsuo
   # Build and install Tongsuo according to its documentation
   ```

2. **Install Python Dependencies**:
   ```bash
   pip install numpy
   # Install other required packages as needed
   ```

3. **Set Tongsuo Library Path** (if needed):
   ```bash
   export TONGSUO_LIBCRYPTO_PATH=/path/to/Tongsuo/libcrypto.so
   # Or place libcrypto.so in SLADKG/Tongsuo/
   ```

### Running the DKG Protocol

Run the distributed key generation protocol:

```bash
cd SLADKG
python3 SLACSS.py
```

The program will execute a complete DKG protocol with the default parameters and output detailed logs to the `log/` directory.

### Configuration Parameters

The default protocol parameters can be adjusted in `SLACSS.py` within the `test_distributed_v3s()` function:

```python
num_participants = 6      # Number of participants (N)
threshold = 2            # Threshold (T)
dimension = 4            # Module rank k (d)
sigma_x = 1.0            # Standard deviation for secret vector
sigma_y = 18.36          # Standard deviation for noise (√337 × sigma_x)
slack_factor = 10.0      # Verification bound slack factor
```

**Parameter Set A (default):**
- Base ring R_q: ℤ_q[X]/(X^8+1)
- Modulus q: 12289
- Ring dimension n: 8
- Module rank k (d): 4

**Parameter Set B:**
- Base ring R_q: ℤ_q[X]/(X^256+1)
- Modulus q: 2^32 - 99 (= 4294967197)
- Ring dimension n: 256

> **Note**: Parameter Set B is documented but requires code modifications (e.g., updating `RING_DEGREE` and `PRIME` constants) to use. See `SLADKG/README.md` for details.

**Encryption:**
- X25519 KEM + AES-256-GCM
- Ed25519 signatures

## Project Overview

This repository contains multiple implementations related to distributed key generation and cryptographic protocols:

- **SLADKG/** - Signature-free Lattice-Based Distributed Key Generation implementation
- **ADKG/** - Asynchronous Distributed Key Generation protocol based on SM2 elliptic curve
- **MVBA/** - Multi-Valued Byzantine Agreement implementation
- **NIZK/** - Non-Interactive Zero-Knowledge proof implementations for MLWE samples
- **OPRBC/** - Optimistic Reliable Broadcast and RBC (Bracha Reliable Broadcast) protocols

### Key Features

- **Module Lattice Cryptography**: Uses module lattices R_q^k over polynomial rings
- **Shamir Secret Sharing**: Threshold secret sharing with Reed-Solomon error correction
- **Verifiable Secret Sharing**: Merkle tree-based commitment scheme for share verification
- **Asynchronous Communication**: Network-based distributed protocol execution
- **Post-Quantum Security**: Based on lattice-based cryptographic assumptions
- **Performance Monitoring**: Built-in performance statistics and timing analysis

## Project Structure

```
仓库/
│
├── README.md           # This file - project documentation
│
├── SLADKG/             # Signature-free Lattice-Based DKG implementation
│   ├── ...
│   └── README.md       # SLADKG-specific documentation
│
├── ADKG/               # Asynchronous Distributed Key Generation BaseLine
│   ├── ...
│   └── README.md       # ADKG-specific documentation
│
├── MVBA/               # Multi-Valued Byzantine Agreement
│   ├── beat/           # BEAT protocol implementation
│   │   ├── ...
│   │   └── README.md   # BEAT documentation
│   └── README.md       # MVBA documentation
│
├── NIZK/               # Non-Interactive Zero-Knowledge proofs
│   ├── ...
│   └── README.md       # NIZK documentation
│
└── OPRBC/              # Optimistic Reliable Broadcast protocols
    ├── ...
    └── README.md       # OPRBC documentation
```

## Dependencies

### Cryptographic Libraries

1. **Tongsuo**
   The Tongsuo cryptographic library provides the underlying cryptographic primitives:
   - AES-256-GCM encryption
   - Ed25519 digital signatures
   - X25519 key exchange
   - HKDF key derivation
   
   **Installation:**
   - Clone from: https://github.com/Tongsuo-Project/Tongsuo.git
   - Build and install according to Tongsuo documentation
   - Set `TONGSUO_LIBCRYPTO_PATH` environment variable or place library in `Tongsuo/` directory
   
   **Folder:** `Tongsuo/`
   **Documentation:** See Tongsuo project repository

### Python Packages

- **numpy** - Numerical computations for polynomial operations
- **hashlib** - Hash functions (SHA-256, SHAKE-128, SHAKE-256)
- **threading/asyncio** - Asynchronous network communication
- **json/pickle** - Data serialization
- **base64** - Encoding utilities

## Protocol Details

### DKG Protocol Phases

1. **Shamir Secret Sharing**: Each participant generates shares of their secret vector
2. **Merkle Tree Construction**: Builds commitment trees for share verification
3. **Challenge Matrix and Bound Computation**: Generates verification challenges
4. **Validation Vector Calculation**: Computes verification vectors for share validation
5. **NIZK Proof Generation**: Generates non-interactive zero-knowledge proofs for share validation
6. **Network Communication**: Distributed share exchange and verification
7. **Aggregated Share Generation**: Combines shares from multiple participants
8. **Global Public Key Generation**: Reconstructs the global public key

### Security Parameters

**Parameter Set A (default):**
- **Number of participants (N)**: 6
- **Threshold (T)**: 2
- **Sigma_x**: 1.00
- **Sigma_y**: 18.36 (= √337 × sigma_x)
- **Slack factor**: 10.0
- **Bound**: slack_factor × σ_v × √(d × ring_degree)

**Parameter Set B:**
- **Ring dimension (n)**: 256
- **Modulus (q)**: 2^32 - 99 (= 4294967197)
- Other parameters (N, T, sigma_x, sigma_y, slack_factor) remain the same as Parameter Set A

## Logging

The implementation automatically creates log files in the `log/` directory:
- Log files are named with date and sequence: `YYYYMMDD-NNN.log`
- All standard output and error messages are redirected to log files
- Logs include detailed protocol execution traces and performance statistics

## Performance Monitoring

The implementation includes built-in performance monitoring that tracks:
- Execution time for each protocol phase
- Operation counts (polynomial operations, hash operations, etc.)
- Network communication statistics
- Detailed performance reports printed at the end of execution

## Acknowledgments

This project makes use of the following open-source libraries and implementations:

- [Tongsuo Project](https://github.com/Tongsuo-Project/Tongsuo) - Cryptographic library providing AES-GCM, Ed25519, X25519, and HKDF primitives
- [LBZKP](https://github.com/khanhcrypto/LBZKP) - Lattice-Based Zero-Knowledge Proofs implementation used by the NIZK module
- [BEAT](https://github.com/fififish/beat/tree/master/BEAT0/BEAT) - BEAT protocol implementation used by the MVBA module
- [ReliableBroadcast](https://github.com/trevoraron/ReliableBroadcast) - Bracha Broadcast algorithm implementation used by the OPRBC module
- [ADKG](https://github.com/sourav1547/adkg) - Asynchronous Distributed Key Generation baseline implementation used by the ADKG module



## License

This project is licensed under the OpenAtom Open Hardware License, Version 1.0 - see the [license](SLADKG/license) file for details.
