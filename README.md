# Secure Image Transmission System (SIT)

[![CI](https://github.com/TODO_USER/SecureImageTransmission/actions/workflows/ci.yml/badge.svg)](TODO_USER)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![License: TODO_USER](https://img.shields.io/badge/License-TODO__USER-lightgrey.svg)](LICENSE_TODO.md)

An error-resilient, authenticated image transmission system designed for distributed edge-to-cloud visual analytics pipelines. By partitioning images into $16\times 16$ RGB blocks encapsulated in 800-byte framed records, bound via a 20-byte Additional Authenticated Data (AAD) structure and authenticated under AES-256-GCM, the system provides **strictly bounded error containment ($\text{EPR} = 1.00$)**, eliminating both the catastrophic desynchronization of Cipher Block Chaining (CBC) and the whole-image discard of monolithic Authenticated Encryption with Associated Data (AEAD).

---

## Architecture Overview

- **800-Byte Record Framing**: 
  $$\text{Record } R_i = \text{uint32}(\text{index}) \parallel \text{IV} (12\text{B}) \parallel \text{Ciphertext} (768\text{B}) \parallel \text{GHASH Tag} (16\text{B})$$
- **20-Byte Multi-Attribute AAD**:
  $$\text{AAD}_i = \text{uint32}(i) \parallel \text{uint16}(H) \parallel \text{uint16}(W) \parallel \text{uint32}(N) \parallel \text{uint32}(\text{epoch}) \parallel \text{uint32}(0)$$
  Eliminates cross-block splicing, cross-session replays, and spatial dimensional tampering.
- **134-Byte Authenticated Session Header**:
  Carries protocol magic (`'SITH'`), version, PBKDF2/HKDF salts, sender ephemeral X25519 public key, epoch, image dimensions $(H, W)$, block count $N$, and an HMAC-SHA256 tag over the first 102 bytes.
- **Key Agreement & Derivation**:
  - Receiver static X25519 keypair; sender ephemeral X25519 keypair.
  - Shared secret: $K_{\text{session}} = \text{X25519}(\text{eph\_priv}, \text{receiver\_pub})$.
  - Passphrase stretching: PBKDF2-HMAC-SHA256 (600,000 rounds) $\implies P_{\text{stretched}}$.
  - Session key derivation: HKDF-SHA256 bound to receiver Device ID digest (never sent over the wire) and monotonic epoch.
- **Tag-Directed Spatial Error Concealment**:
  Quarantines authenticated tag failures and interpolates corrupted regions from valid spatial boundaries using vectorized inverse-distance interpolation ($+10.78$ to $+11.55\text{ dB}$ PSNR gain).
- **Standardized Receiver Policy**:
  Deterministic evaluation returning exact action labels: `detected_and_quarantined`, `concealed`, `duplicate_ignored`, `rejected_over_threshold`, and `session_rejected`.

---

## Security Model & Boundary Disclaimers

> [!IMPORTANT]
> **No Forward Secrecy**: The system derives session keys from a combination of ephemeral-static X25519 key agreement and a long-term passphrase stretched via PBKDF2 (600,000 iterations). Compromise of the long-term passphrase and receiver static private key allows retroactive decryption of recorded sessions. This system provides defense-in-depth, not forward secrecy. See [SECURITY.md](docs/SECURITY.md) for details.

> [!NOTE]
> **Device Identifier Privacy**: The receiver's Device ID (SHA-256 digest of hardware MAC or OS UUID) is strictly used as an internal key-binding factor in HKDF and is **never transmitted across the network**.

---

## Installation & Requirements

The codebase is validated on **Python 3.11, 3.12, and 3.13** on both Windows 11 and Linux (Ubuntu 22.04+).

```bash
# Clone the repository
git clone https://github.com/TODO_USER/SecureImageTransmission.git
cd SecureImageTransmission

# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# Install pinned dependencies
pip install -r requirements.txt
```

---

## Quickstart & Task Execution

A cross-platform task runner `tasks.py` (and standard `Makefile`) is provided for automated workflow execution:

### 1. Run Unit Tests (74 tests)
```bash
python tasks.py test
# Or directly:
python -m unittest discover tests
```

### 2. Run Comprehensive Experiments
```bash
python tasks.py exp
# Or directly:
python experiments/run_all.py
```

### 3. Generate LaTeX Tables and Results Macros
```bash
python tasks.py tables
# Or directly:
python scripts/make_tables.py
```
Outputs: `tables/table1_crypto.tex` through `tables/table8_multi_image_containment.tex`, `tables/table9_stream_comparison.tex`, `tables/table5_multi_hardware.tex`, and `tables/results_macros.tex` (synced to `paper_icmlde/`).

### 4. Generate Publication Figures
```bash
python tasks.py figures
# Or directly:
python scripts/make_figures.py
```
Outputs: `figures/fig1_architecture.*` through `figures/fig6_multi_image_containment.*` (synced to `paper_icmlde/figures/`).

### 5. Run LaTeX Linter
```bash
python tasks.py lint
# Or directly:
python scripts/lint_latex.py
```

---

## Reproducing Paper Results (Step-by-Step)

To reproduce every table, figure, and macro in the revised manuscript from scratch:

1. **Verify Test Suite (74 tests passing):**
   ```bash
   python tasks.py test
   ```
2. **Execute Multi-Image Containment Benchmark (Task 1):**
   ```bash
   python experiments/exp_multi_image_containment.py
   ```
3. **Execute Chaotic and Selective Encryption Baselines (Task 2):**
   ```bash
   python experiments/exp_chaotic_baselines.py
   ```
4. **Execute Hardware Profiling (Task 3):**
   ```bash
   python scripts/benchmark_portable.py
   python scripts/aggregate_hardware.py
   ```
5. **Regenerate Publication Tables & Synced Macros:**
   ```bash
   python scripts/make_tables.py
   ```
6. **Regenerate Publication Figures (Fig 1 through Fig 6):**
   ```bash
   python scripts/make_figures.py
   ```
7. **Lint LaTeX Manuscript:**
   ```bash
   python tasks.py lint
   ```

### 6. Launch Interactive Streamlit Dashboard
```bash
python tasks.py app
# Or directly:
streamlit run app.py
```

### 7. Run Hardware Benchmark on Second Device
```bash
python scripts/benchmark_portable.py
```
This executes the unified 15-session portable benchmark, recording power profiles, pure crypto throughput, end-to-end throughput, and video streaming feasibility into `results/bench_<hostname>.json` and `results/bench_<hostname>_runs.json`.

---

## Experiment Suite & Utility Manifest

All benchmark and experiment scripts execute with fixed random seeds for strict determinism.

| Script | Purpose / Method | Primary Inputs | Primary Outputs | Seed | Typical Runtime |
|---|---|---|---|:---:|:---:|
| `experiments/exp_crypto.py` | Shannon entropy, correlation ($r_H, r_V, r_D$), NPCR/UACI, chi-square, key sensitivity | `data/benchmark/*.png` (6 images) | `results/crypto_metrics.json\|csv`, `results/crypto_metrics_cbc.json\|csv`, `results/dataset_manifest.json` | 42 | ~15 s |
| `experiments/exp_containment.py` | Multi-image error containment (M1, M2, M3) across 5 schemes, 30 trials/level | `data/benchmark/*.png` | `results/containment_*.json\|csv`, `results/containment_summary.json`, `results/fig2_metrics.json` | 42 | ~45 s |
| `experiments/exp_security.py` | Security test matrix across 17 attack vectors (100 trials each, 1,700 total) | Submarine benchmark image | `results/security_tests.json\|csv` | 42 | ~12 s |
| `experiments/exp_ml_downstream.py` | Downstream MobileNetV2 classification resilience under S1 and S2 | `data/imagenet_subset.txt`, `models/mobilenetv2-7.onnx` | `results/ml_downstream.json\|csv` | 42 | ~25 s |
| `experiments/exp_blocksize_tradeoff.py`| Block granularity trade-off ($8\times 8$, $16\times 16$, $32\times 32$, $64\times 64$) | Submarine benchmark image | `results/blocksize_tradeoff.json\|csv` | 42 | ~8 s |
| `experiments/exp_concealment_baselines.py`| Comparison between mean-color fill and spatial interpolation | Submarine benchmark image | `results/concealment_baselines.json\|csv` | 42 | ~6 s |
| `scripts/benchmark_portable.py` | Hardware profiling, pure crypto & end-to-end throughput, streaming feasibility | Synthetic buffers & Submarine | `results/bench_<hostname>.json`, `results/environment.json` | 42 | ~5 s |
| `scripts/make_tables.py` | Generates Elsevier LaTeX tables (Tabs 1–7) & macro definitions | `results/*.json`, `data/literature_table.csv` | `tables/*.tex`, `tables/results_macros.tex` | N/A | ~1 s |
| `scripts/make_figures.py` | Generates vector PDFs and 300 DPI PNG figures (Figs 1–5) | `results/*.json`, Submarine benchmark image | `figures/fig1` to `figures/fig5` | 42 | ~5 s |
| `scripts/lint_latex.py` | Static linter for table cell counts, `%` escaping, macro definitions, citations | `paper_icmlde/sw.tex`, `paper_icmlde/tables/*.tex` | Terminal diagnostic report | N/A | < 1 s |
| `tools/drl_tool.py` | CLI utility for generating Ed25519 keypairs, signing, and verifying DRLs | Command-line arguments | Signed DRL JSON documents | N/A | < 1 s |

---

## Test Suite & Code Coverage

The unit test suite encompasses 63 rigorous test cases covering all cryptographic primitives, framing structures, receiver policies, error concealment edge cases, and dashboard logic:

```bash
python scripts/measure_coverage.py
```

### Module Line Coverage Summary:
- `src/error_simulator.py`: **76.0%**
- `src/image_crypto_metrics.py`: **71.0%**
- `src/error_concealment.py`: **69.5%**
- `src/decryption.py`: **57.7%**
- `src/image_processor.py`: **57.5%**
- `src/encryption.py`: **55.3%**
- `src/key_manager.py`: **54.5%**
- `src/record_format.py`: **53.8%**
- `src/baseline_ciphers.py`: **57.1%**
- **Overall `src/` Line Coverage**: **57.2%** (650 / 1136 executable lines covered across 63 tests).

---

## License

Software licence selection is pending author designation (see [LICENSE_TODO.md](LICENSE_TODO.md) and [PAPER_OPEN_ITEMS.md](PAPER_OPEN_ITEMS.md)).

## Contact

Corresponding Author: Radhu Krishna R. (`radhukr@am.amrita.edu`), School of Computing, Amrita Vishwa Vidyapeetham, Amritapuri, Kollam, India.

