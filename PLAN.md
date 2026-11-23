# PLAN.md: Secure Image Transmission System (Project Revision Plan)

This plan outlines the systematic implementation of Tasks 0 through 13 according to the ground rules and technical decisions.

---

## 1. Scope & Architecture Decisions
- **Scope:** Project only (`src/`, `tests/`, `experiments/`, `scripts/`, `tools/`, `app.py`, `results/`, `tables/`, documentation). Do NOT hand-edit `paper_icmlde/sw.tex`.
- **D1 (Key Transport):** X25519 ephemeral-static key agreement with 134-byte authenticated session header.
- **D2 (DRL Authentication):** Ed25519-signed JSON document with rollback protection.
- **D3 (Nonce Guard):** Random 96-bit nonce by default with $2^{32}$ invocation guard; optional deterministic nonce `salt32 || uint64(index)` behind flag.

---

## 2. Task Breakdown, Files Touched, and Risks

### Task 0: Repo Audit and Baseline
- **Files touched:** `AUDIT.md`, `results/archive_20261104/baseline/`, `tables/archive_20261104/`.
- **Actions:** Inspect repository, inventory files, verify existing 26 tests, archive current `results/` and `tables/`, complete `AUDIT.md` highlighting all 6 audit items (forward secrecy mentions, device ID leakage/headers, abort vs conceal policies, PSNR 40 dB rule, throughput definitions).
- **Risk:** Missing baseline outputs. **Mitigation:** Copy all existing files before making any modifications.

### Task 1: Session Header & Key Transport (X25519 + Two-Factor Key Schedule)
- **Files touched:** `src/record_format.py`, `src/key_manager.py`, `src/config.py`, `tests/test_key_transport.py`, `docs/SECURITY.md`.
- **Actions:**
  - Implement receiver static X25519 key generation/storage with passphrase-derived encryption and 16-byte key fingerprint (`SHA-256(pubkey)[:16]`).
  - Implement sender ephemeral X25519 key pair, shared secret derivation, and HKDF-derived $K_{\text{session}}$.
  - Implement 2-factor key schedule: PBKDF2 (600,000 iterations default) $\implies$ IKM $\implies$ PRK $\implies K_{\text{AES}}$ and $K_{\text{hdr}}$.
  - Layout 134-byte session header: `magic(4) || ver(1) || flags(1) || epoch(4) || H(4) || W(4) || N(4) || S_hkdf(16) || S_pbkdf2(16) || eph_pub(32) || fingerprint(16) || HMAC(32)`.
  - Constant-time HMAC verification before parsing fields.
  - Monotonic epoch persistence with atomic writes (temp file + fsync + rename).
  - Remove all forward secrecy claims and document precise security guarantees in `docs/SECURITY.md`.
  - Add comprehensive unit tests (header roundtrip, bit flip rejection, RFC test vectors, epoch rollback, restart persistence).
- **Risk:** Breaking existing encryption/decryption calls. **Mitigation:** Update `encrypt_blocks` / `decrypt_blocks` to integrate seamlessly with the new session header or provide high-level sender/receiver wrappers.

### Task 2: Explicit Receiver Policy (Loss, Duplicates, Truncation, Tau)
- **Files touched:** `src/decryption.py`, `src/error_concealment.py`, `tests/test_receiver_policy.py`.
- **Actions:**
  - Standardize receiver return structure: `{authentic_blocks, failed_blocks, missing_blocks, duplicate_blocks_ignored, concealed_block_mask, failed_fraction, action}`.
  - Implement 5 strict action labels: `concealed`, `rejected_over_threshold`, `duplicate_ignored`, `session_rejected`, `detected_and_quarantined`.
  - Handle missing index gaps and tail truncation via spatial concealment when `failed_fraction <= tau` (default $\tau = 0.25$).
  - Never label concealed images as authentic.
- **Risk:** Concealment performance under high corruption. **Mitigation:** Ensure $\tau$ threshold raises typed exception or returns structured failure.

### Task 3: Device Revocation List (Ed25519 Signed)
- **Files touched:** `src/key_manager.py`, `tools/drl_tool.py`, `tests/test_drl.py`.
- **Actions:**
  - Create Ed25519 signature generator and validator for JSON DRL (`version`, `entries`, `issued_at`).
  - Enforce rollback protection (`version >= stored_version`) and reject revoked key fingerprints or device IDs.
  - CLI tool `tools/drl_tool.py` for generating keys, signing lists, and verifying DRL.
- **Risk:** Signature verification performance. **Mitigation:** Ed25519 verification is sub-millisecond in `cryptography`.

### Task 4: Nonce & Key-Usage Guards
- **Files touched:** `src/encryption.py`, `src/record_format.py`, `tests/test_nonce_guard.py`.
- **Actions:**
  - Track GCM counter per key, enforcing $2^{32}$ limit (NIST SP 800-38D).
  - Unit test 4,096 blocks across 100 sessions asserting zero duplicate (key, IV) pairs.
  - Implement optional deterministic nonce `salt32 || uint64(index)` (default off).
  - Best-effort zeroization of bytearrays.

### Task 5: Experiment Harness: Baselines and 3 Corruption Models
- **Files touched:** `src/baseline_ciphers.py`, `experiments/exp_containment.py`, `tests/test_containment_baselines.py`.
- **Actions:**
  - Baselines: (a) Monolithic GCM, (b) Unframed CBC, (c) Framed CBC (4B sequence header), (d) Per-block CBC + HMAC-SHA256 (Encrypt-then-MAC with AAD equivalent), (e) Proposed block AES-GCM.
  - 3 Corruption Models: M1 (in-place bit flip), M2 (record deletion without sequence info), M3 (record deletion with sequence index).
  - Exact failure definition: byte difference vs original (eliminate PSNR < 40 dB heuristic).
  - Metrics: `blocks_wrong`, `blocks_detected`, precision, recall, EPR (null at $K=0$), PSNR, SSIM, runtime, availability.
  - 30 trials per level on all 6 authentic benchmark images. Deterministic `fig2_metrics.json` ($K=25$, Seed 42).

### Task 6: Security Test Matrix (17 Vectors)
- **Files touched:** `experiments/exp_security.py`, `results/security_tests.json`, `results/security_tests.csv`.
- **Actions:**
  - 100 trials each across 17 attack vectors (including header bit flips, ephemeral key substitution, static key mismatch, DRL rollback, forged signature).
  - Store exact action labels matching Task 2.7.

### Task 7: Downstream ML Resilience (500 ImageNet Images, S1 & S2 Scenarios)
- **Files touched:** `experiments/exp_ml_downstream.py`, `data/imagenet_subset.txt`.
- **Actions:**
  - 500 ImageNet validation images (file list + SHA-256 recorded in `data/imagenet_subset.txt`).
  - Scenarios: S1 (record loss) and S2 (in-place bit flips).
  - Exact corruption fractions: $K \in \{1, 2, 5, 9, 18\}$ of 196 blocks ($0.51\%, 1.02\%, 2.55\%, 4.59\%, 9.18\%$).
  - Evaluated on MobileNetV2 with 95% bootstrap CI; CBC+HMAC baseline included.

### Task 8: Cryptographic Metrics Suite
- **Files touched:** `experiments/exp_crypto.py`, `results/dataset_manifest.json`, `results/crypto_metrics_cbc.json`.
- **Actions:**
  - Plain and cipher entropy, per-channel, correlation ($r_H, r_V, r_D$ from 4,000 random pairs), max $|r|$, chi-square, NPCR & UACI (fresh nonces and fixed nonces), key sensitivity test.
  - Evaluate CBC baseline under same protocol.
  - Manifest of 6 benchmark images with SHA-256 and TODO_USER fields.

### Task 9: Block-Size & Performance Profiling
- **Files touched:** `experiments/exp_overhead.py`, `scripts/benchmark_portable.py`, `results/blocksize_tradeoff.json`.
- **Actions:**
  - Block size trade-off (8, 16, 32, 64) over constant corrupted area fractions.
  - `benchmark_portable.py` recording pure crypto vs end-to-end throughput in decimal MB/s, system environment, and video load metrics.

### Task 10: Advanced Concealment Baselines & Unit Tests
- **Files touched:** `src/error_concealment.py`, `experiments/exp_concealment.py`, `tests/test_concealment_exact.py`.
- **Actions:**
  - Mean-color fill baseline, OpenCV Telea / Navier-Stokes baselines.
  - Comprehensive unit tests for 2-neighbor, 4-neighbor, and empty-neighbor fallback corner/edge cases.

### Task 11: Streamlit Dashboard Overhaul
- **Files touched:** `app.py`, `tests/test_app_pure.py`.
- **Actions:**
  - Add key-transport status, passphrase strength meter, scenario selectors, failed vs missing block overlays, side-by-side comparisons, tau threshold slider, and JSON session export.
  - Pure function unit test.

### Task 12: Automated Tables, Linting & Paper Hand-Off
- **Files touched:** `scripts/make_tables.py`, `scripts/lint_latex.py`, `scripts/check_handoff.py`, `HANDOFF_FOR_PAPER.md`, `data/literature_table.csv`.
- **Actions:**
  - Regenerate all LaTeX tables and macros with strict escaping and row/column assertions.
  - Enhanced linter checking for prohibited strings, missing citations, and table dimensions.
  - Generate `HANDOFF_FOR_PAPER.md` programmatically listing all new macros, header layouts, and sw.tex mismatches.

### Task 13: Reproducibility, Repo Hygiene & Test Coverage
- **Files touched:** `requirements.txt`, `README.md`, `Makefile`, `tasks.py`, `.github/workflows/ci.yml`, `docs/SECURITY.md`, `OPEN_ITEMS.md`.
- **Actions:**
  - Lock requirements with exact versions.
  - Provide comprehensive README with exact reproduction commands and table/figure mapping.
  - Provide Makefile and tasks.py (`make test`, `make lint`, `make reproduce`).
  - Provide GitHub Actions CI workflow.
  - Measure line coverage of core modules using standard library `trace` (target $\ge 90\%$).

---

## 3. Verification & Acceptance Tracking
Each task will conclude with a complete test run (`python -m unittest discover tests`) and progress documentation.

