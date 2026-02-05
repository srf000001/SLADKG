# ADKG Implementation

ADKG is an implementation of an Asynchronous Distributed Key Generation (ADKG) protocol based on the SM2 elliptic curve cryptographic algorithm. This project provides a robust framework for distributed key generation in Byzantine fault-tolerant systems with asynchronous communication, featuring a web-based interface for node management and key generation monitoring.

## Prerequisites

1. `Python >= 3.7.10` (Lower versions may work but are untested)
2. `Node >= 16`
3. Install `flask`, `flask-cors` for backend
4. Install dependencies for frontend directory `access-control-front-end`
5. Docker and Docker Compose

## Quick Start 

### 1. Build Docker Image 

First, install Docker if not already installed: 

```bash
# Install Docker
sudo apt update 
sudo apt upgrade

# Install dependencies
sudo apt install apt-transport-https ca-certificates curl software-properties-common

# Add Docker repository (USTC mirror)
curl -fsSL https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://mirrors.ustc.edu.cn/docker-ce/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update

# Install Docker CE
sudo apt install docker-ce

# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker
sudo docker --version

# Build the image (first time will take longer)
cd SM2_ADKG
sudo docker-compose build adkg
```

### 2. Run the System 

Start the backend server:

```bash
python3 start.py
```

Then access the web interface: 
1. Open your browser and visit `localhost:5173`
2. Login directly (no authentication required)
3. Navigate to "节点管理" (Node Management)
4. Click "节点密钥生成" (Node Key Generation)
5. Wait for the key generation process to complete
6. View the generated keys and status

## Project Overview

The implementation consists of several core modules:

- **ADKG Core Protocol** - Asynchronous Distributed Key Generation
- **ACSS (Asynchronous Complete Secret Sharing)** - Asynchronous secret sharing protocol
- **Polynomial Commitments** - Multiple commitment schemes including Feldman, SM2, and others
- **Byzantine Broadcast** - Reliable broadcast and binary agreement protocols  
- **Pairing-Based Cryptography** - BLS12-381 and Curve25519 implementations
- **Web Interface** - Flask backend + Vue.js frontend for node management
- **Preprocessing & MPC** - Multi-party computation primitives

## Project Structure

```
SM2_ADKG/
│
├── start.py                 (Main entry point - Flask backend server)
├── setup.py                 (Python package setup)
├── Dockerfile               (Docker container configuration)
├── docker-compose.yml       (Docker Compose configuration)
├── Makefile                 (Build automation)
│
├── adkg/                    (Core ADKG implementation)
│   ├── adkg.py              (Core ADKG protocol)
│   ├── acss.py              (Asynchronous Complete Secret Sharing)
│   ├── poly_commit_sm2.py   (SM2-based polynomial commitment)
│   ├── poly_commit_feldman.py (Feldman commitment)
│   ├── poly_commit_log.py   (Logarithmic-size commitment)
│   ├── hbavss.py            (HoneyBadger AVSS)
│   ├── broadcast/           (Byzantine broadcast protocols)
│   ├── ntl/                 (NTL library bindings)
│   │   └── README.md        (NTL integration documentation)
│   └── utils/               (Utility functions)
│
├── pairing/                 (Pairing-based cryptography)
│   ├── src/
│   │   ├── bls12_381/       (BLS12-381 curve implementation)
│   │   └── curve25519-dalek/ (Curve25519 implementation)
│   └── README.md            (Pairing library documentation)
│
├── access-control-front-end/ (Vue.js frontend for web UI)
│
├── apps/                    (Application examples)
│   └── tutorial/
│       ├── adkg-tutorial.py (Tutorial example)
│       └── test_sm2.py      (SM2 cryptography test)
│
├── scripts/                 (Launch and utility scripts)
│   ├── adkg_run.py          (ADKG run script)
│   ├── launch-tmuxlocal.sh  (Local launch script)
│   └── launch-tmux.sh       (Docker launch script)
│
├── benchmark/               (Benchmark tests)
│   └── README. md            (Benchmarking documentation)
├── tests/                   (Unit tests)
├── conf/                    (Configuration files)
├── logs/                    (Log files for each node)
├── aws/                     (AWS deployment scripts)
│   └── README.md            (AWS deployment documentation)
├── data-paper/              (Experimental data)
└── LICENSE                  (License file)
```

## System Architecture

The system consists of three main components:

1. **Flask Backend (`start.py`)**:  
   - Manages Docker containers for ADKG nodes
   - Provides REST API for frontend
   - Collects and aggregates results from nodes
   - Endpoints: 
     - `/api/generate` - Start key generation
     - `/api/data` - Get generated key data
     - `/api/log` - Get logs for specific node
     - `/api/zG` - Get public key set

2. **ADKG Protocol (`adkg/`)**:
   - Runs in Docker containers
   - Each container represents one node
   - Implements distributed key generation
   - Communicates through ZMQ

3. **Web Frontend (`access-control-front-end/`)**:
   - Vue.js-based user interface
   - Node management dashboard
   - Real-time status monitoring
   - Log viewing

## Dependencies

### Core Requirements

```
Python >= 3.7.10
Node >= 16
Docker
Docker Compose
```

### Python Dependencies

```
flask
flask-cors
gmpy2
zfec
pycrypto
cffi
psutil
pyzmq
uvloop
asyncio
```

### Cryptographic Modules

#### SM2 Cryptography
SM2 is a Chinese national standard elliptic curve cryptographic algorithm: 
- Key generation and management
- Digital signatures
- Encryption/Decryption

Library: `gmssl` (GmSSL library for SM2)
File: `apps/tutorial/test_sm2.py`

#### Pairing-Based Cryptography
- **BLS12-381**: Pairing-friendly elliptic curve for efficient bilinear pairings
- **Curve25519**: Fast elliptic curve for general-purpose cryptography

Folder: `pairing/`
Documentation: See `pairing/README.md`

#### Polynomial Commitments
Multiple polynomial commitment schemes:
- **Feldman Commitment** (`poly_commit_feldman.py`)
- **SM2 Commitment** (`poly_commit_sm2.py`)
- **Logarithmic Commitment** (`poly_commit_log.py`)
- **Bulletproof Commitment** (`poly_commit_bulletproof.py`)

#### NTL Library Integration
Number Theory Library for efficient polynomial operations:
- Cython bindings for performance
- Parallel computation support via OpenMP

Folder: `adkg/ntl/`
Documentation: See `adkg/ntl/README. md`


## Configuration

Configuration files are located in the `conf/` directory. Each node requires a separate configuration file in JSON format.

Example configuration structure (`conf/adkg/local.0.json`):
```json
{
  "N": 10,
  "t": 3,
  "my_id": 0,
  "peers": ["localhost:13000", "localhost:13001", ... ],
  "port": 13000
}
```

Parameters:
- `N`: Total number of nodes
- `t`: Fault tolerance threshold (number of Byzantine nodes tolerated)
- `my_id`: Node identifier
- `peers`: List of peer addresses
- `port`: Node listening port


## Frontend Development

```bash
cd access-control-front-end
npm install
npm run dev
```


## Acknowledgments

This project builds upon several open-source libraries and research implementations: 

- **BLS12-381 Pairing Library** - zkcrypto implementation
- **Curve25519-dalek** - Dalek Cryptography
- **NTL (Number Theory Library)** - Victor Shoup
- **HoneyBadgerBFT** - Andrew Miller et al.
- **GmSSL** - Chinese cryptographic library for SM2

## License

This project is licensed under the GNU General Public License - see the LICENSE file for details. 
