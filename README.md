# Signature-free Lattice-Based Distributed Key Generation without PKI setup Implementation

**SLADKG** is a paper that is undergoing peer review and is currently submitted to USENIX Security 2026.

The **SLADKG** project is implemented using Python 3.10.12 and integrates the Tongsuo cryptographic library for secure cryptographic primitives. The following provides an overview of the project structure, dependencies, and usage instructions.

## Quick Start

### Prerequisites

- Python 3.10.12 or higher
- All required Python packages (see Dependencies section)
- Tongsuo cryptographic library (see Installation section)

### Installation

1. **Clone Tongsuo Project**:
   ```bash
   cd SLACSS
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
   # Or place libcrypto.so in SLACSS/Tongsuo/
   ```

### Running the DKG Protocol

Run the distributed key generation protocol:

```bash
cd SLACSS
python3 V3S_DKG.py
```

The program will execute a complete DKG protocol with the default parameters and output detailed logs to the `log/` directory.

### Configuration Parameters

The default protocol parameters can be adjusted in `V3S_DKG.py` within the `test_distributed_v3s()` function:

```python
num_participants = 6      # Number of participants (N)
threshold = 2            # Threshold (T)
dimension = 4            # Module rank k (d)
sigma_x = 1.0            # Standard deviation for secret vector
sigma_y = 18.36          # Standard deviation for noise (√337 × sigma_x)
slack_factor = 10.0      # Verification bound slack factor
```

**Algebraic Setting:**
- Base ring R_q: ℤ_q[X]/(X^8+1)
- Modulus q: 12289
- Ring dimension n: 8
- Module rank k (d): 4

**Encryption:**
- X25519 KEM + AES-256-GCM
- Ed25519 signatures

## Project Overview

The implementation consists of several core components:

- **V3S_DKG.py** - Main DKG protocol implementation
- **tongsuo.py** - Tongsuo cryptographic library bindings (AES-GCM, Ed25519, X25519, HKDF)
- **secure_rng.py** - Cryptographically secure random number generation utilities
- **Tongsuo/** - Tongsuo cryptographic library directory

### Key Features

- **Module Lattice Cryptography**: Uses module lattices R_q^k over polynomial rings
- **Shamir Secret Sharing**: Threshold secret sharing with Reed-Solomon error correction
- **Verifiable Secret Sharing**: Merkle tree-based commitment scheme for share verification
- **Asynchronous Communication**: Network-based distributed protocol execution
- **Post-Quantum Security**: Based on lattice-based cryptographic assumptions
- **Performance Monitoring**: Built-in performance statistics and timing analysis

## Project Structure

```
SLACSS/
│
├── V3S_DKG.py          # Main DKG protocol implementation
├── tongsuo.py          # Tongsuo cryptographic primitives wrapper
├── secure_rng.py       # Secure random number generation
├── Tongsuo/            # Tongsuo library directory (cloned separately)
│   └── libcrypto.so    # Compiled Tongsuo library (or .dylib/.dll)
├── log/                # Runtime logs directory (auto-generated)
├── README.md           # Project documentation
└── license             # License file
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
5. **Network Communication**: Distributed share exchange and verification
6. **Aggregated Share Generation**: Combines shares from multiple participants
7. **Global Public Key Generation**: Reconstructs the global public key

### Security Parameters

- **Number of participants (N)**: 6
- **Threshold (T)**: 2
- **Sigma_x**: 1.00
- **Sigma_y**: 18.36 (= √337 × sigma_x)
- **Slack factor**: 10.0
- **Bound**: slack_factor × σ_v × √(d × ring_degree)

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

## License

This project is licensed under the OpenAtom Open Hardware License, Version 1.0 - see the [license](SLACSS/license) file for details.
