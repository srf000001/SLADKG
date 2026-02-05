# proving_mlwe_sample — Run Guide

## Overview

This script computes the **non-interactive proof size** for proving knowledge of an MLWE (Module-LWE) sample, as described in Section 6.2. Specifically, the prover proves knowledge of a vector **s** such that `||(s, As-u)|| ≤ B`.

The script automatically derives parameters for ~128-bit security (Module-SIS and Module-LWE dimensions, moduli, etc.) and estimates the proof size.

## Dependencies

- **SageMath** (required)

The script relies on SageMath for symbolic computation and number theory, and on the external [LWE-Estimator](https://bitbucket.org/malb/lwe-estimator/) for MLWE security estimation.

### Installing SageMath

- **Conda**:
  ```bash
  conda create -n sage -c conda-forge sage
  conda activate sage
  ```
- **apt (Linux/WSL)**:
  ```bash
  sudo apt install sagemath sagemath-jupyter
  ```
- See `install_sage_conda.md` or `install_sage_wsl.md` in the project root for more options.

## How to Run

### Option 1: Run directly with Sage (recommended)

```bash
cd DSN
sage proving_mlwe_sample.py
```

### Option 2: Run the .sage.py variant

```bash
cd DSN
sage proving_mlwe_sample.sage.py
```

Or:

```bash
sage -python proving_mlwe_sample.sage.py
```

### Option 3: Run from Sage interactive shell

```bash
sage
>>> load("proving_mlwe_sample.py")
```

## Output

The script produces:

1. **Progress messages**
   - Computing the Module-LWE dimension...
   - Computing the Module-SIS dimension...
   - Computing the parameter gamma...
   - Computing moduli q1, q etc. ...
   - Computing the parameter D...
   - Checking knowledge soundness conditions...

2. **Computed parameters**
   - `q1`: smallest prime divisor of q
   - `q`: proof system modulus
   - `gamma`: parameter for dropping low-order bits of w
   - `D`: parameter for dropping low-order bits of t_A
   - Module-SIS and Module-LWE dimensions
   - Standard deviations stdev1, stdev2, stdeve, etc.

3. **Security analysis**
   - Repetition rate
   - Log of the knowledge soundness error
   - Root Hermite factors for MSIS and MLWE

4. **Proof size**
   - Total proof size (KB)
   - Breakdown: full-sized polynomials, challenge, short-sized polynomials

## Tunable Parameters

Main parameters in the script header:

| Parameter   | Default | Description                              |
|-------------|---------|------------------------------------------|
| `secpam`    | 128     | Security parameter (bits)                |
| `d`         | 128     | Ring dimension R = Z[X]/(X^d+1)          |
| `logq` / `logq1` | 32 | Bit length of modulus q                  |
| `m1`        | 8       | Length of vector s1                      |
| `BoundsToProve` | [√2048] | Norm bounds to prove                     |
| `gamma1`, `gamma2`, `gammae` | 19, 2, 2 | Rejection sampling parameters |

Edit these and re-run to obtain new parameter and proof-size estimates.

## Network Requirement

`findMLWEdelta` loads the LWE-Estimator over the network:

```python
load("https://bitbucket.org/malb/lwe-estimator/raw/HEAD/estimator.py")
```

Internet access to Bitbucket is required. If offline, download `estimator.py` locally and change `load()` to point to the local file.

## Troubleshooting

### 1. `sage: command not found`

SageMath is not installed or not in PATH. Install SageMath and ensure it is on your PATH.

### 2. `NameError: name 'estimate_lwe' is not defined`

LWE-Estimator failed to load, usually due to network issues. Check connectivity or load the estimator from a local file.

### 3. Long runtime

The script performs many lattice-attack estimates and parameter searches; runtime of several minutes is normal.

### 4. Errors like `ERROR: can't use Lemma 2.9`

Current parameters violate knowledge soundness conditions. Try adjusting `secpam`, `d`, `logq`, or other parameters; see the paper for parameter selection guidance.

## Files

| File                      | Description                                |
|---------------------------|--------------------------------------------|
| `proving_mlwe_sample.py`  | Original Sage script                       |
| `proving_mlwe_sample.sage.py` | Preprocessed variant with extra comments and timing |

## References

- [GamNgu08, Mic08]: MSIS hardness estimation
- [AlbPlaSco15]: LWE-Estimator
- Paper Section 6.2: MLWE sample knowledge proof and parameter choices
