# AUDIT.md: Codebase and Architectural Audit

This document records the baseline audit for the Secure Image Transmission System repository conducted under Task 0, identifying existing gaps and discrepancies before implementing Tasks 1 through 13.

---

## 1. Baseline Verification & Archive
- **Date of Audit:** 2026-11-04
- **Initial Test Suite:** 26/26 unit tests passed in 1.60s (`tests/test_concealment_exact.py`, `tests/test_crypto_primitives.py`, `tests/test_metrics_exact.py`, `tests/test_record_and_security.py`, `tests/test_rfc5869.py`).
- **Archive Created:**
  - `results/archive_20261104/baseline/` (all raw metrics and environment JSON/CSV archived).
  - `tables/archive_20261104/` (all prior LaTeX tables archived).

---

## 2. Specific Audit Findings (Task 0.2)

### A. "Forward Secrecy" Mentions
- **Requirement:** Remove or negate any claim of forward secrecy across all code comments, docstrings, README, and dashboard text.
- **Locations Found:**
  1. `src/key_manager.py:96-98`: "Note on Forward Secrecy: We do NOT claim forward secrecy...". Correctly negated in code, but needs formal treatment in `docs/SECURITY.md`.
  2. `src/key_manager.py:134`: "Provides replay rejection across epochs (not forward secrecy)." Correctly negated.
  3. `AUDIT.md:21,43`: Historical notes on K15 audit.
- **Resolution Plan (Task 1.6):** Ensure no positive claims exist anywhere in the codebase or UI. Explicitly state in `docs/SECURITY.md` that forward secrecy is not provided because compromise of the receiver's static private key and passphrase allows decryption of recorded sessions.

### B. Device ID In Clear or Logs
- **Requirement:** Device ID digest (`SHA-256(MAC)`) must NEVER be transmitted across the network or logged in clear text.
- **Locations Found:**
  1. `show_device_id.py:4`: Directly prints `get_device_id()` in clear.
  2. `app.py:234`: Displays `Current Host Device ID: {cur_dev_id}` in the Streamlit UI.
  3. `app.py:258`: Logs `UNAUTHORIZED DEVICE DETECTED: Access Denied` with device state.
- **Root Cause & Vulnerability:** A MAC address has at most ~24 bits of effective entropy (due to IEEE OUI vendor prefixes). Publishing `SHA-256(MAC)` allows an attacker to compute a rainbow table or brute-force search the MAC address in seconds, inverting the device ID.
- **Resolution Plan (Task 1.1, Task 1.3):** The device ID digest must remain strictly local on both endpoints as input keying material to HKDF-Expand. It will never be placed in transmission headers, network packets, or operational log outputs.

### C. uint32 DeviceID in Session Header
- **Requirement:** Eliminate `uint32(DeviceID)` from session headers.
- **Locations Found:**
  1. Historical drafts and `src/record_format.py` line 40/54 contemplated packing a 4-byte truncated DeviceID into the session header.
- **Root Cause & Vulnerability:** Truncating a 32-byte digest to 4 bytes creates collision vulnerabilities ($2^{32}$) and leaks device presence on the wire.
- **Resolution Plan (Task 1.4):** Implement the new 134-byte fixed-format session header:
  $$\text{Session Header} = \text{magic}(4) \parallel \text{version}(1) \parallel \text{flags}(1) \parallel \text{epoch}(4) \parallel H(4) \parallel W(4) \parallel N(4) \parallel S_{\text{hkdf}}(16) \parallel S_{\text{pbkdf2}}(16) \parallel \text{eph\_pub}(32) \parallel \text{fingerprint}(16) \parallel \text{HMAC}(32)$$
  The receiver is identified only by a 16-byte key fingerprint (`SHA-256(receiver_static_pub)[:16]`). The Device ID is never transmitted.

### D. Receiver Policy on Missing, Duplicated, or Truncated Records
- **Requirement:** Distinguish between adversarial tampering (quarantine & conceal) vs session-level failures (reject before block processing). Do not abort streams when the design dictates spatial concealment or duplicate filtering.
- **Locations Found:**
  1. `experiments/exp_security.py` (vectors T06, T07, T08):
     - T06 (Packet Loss) was labeled "Session Aborted".
     - T07 (Duplicate Packet) was labeled "Session Aborted".
     - T08 (Stream Truncation) was labeled "Session Aborted".
  2. `src/decryption.py`: Lacked explicit policy logic handling duplicate packets and missing packet gaps with configurable threshold $\tau$.
- **Resolution Plan (Task 2):** Define explicit receiver policies returning a structured result:
  - Missing records (gaps or truncation up to $\tau$): Action = `concealed`.
  - Exceeding $\tau$ corruption threshold: Action = `rejected_over_threshold`.
  - Duplicate index: Action = `duplicate_ignored` (keep first authentic record, discard duplicate).
  - Invalid header HMAC / unknown key / epoch replay: Action = `session_rejected`.
  - Tampered block payload / tag failure: Action = `detected_and_quarantined` (routed to concealment if $\le \tau$).

### E. PSNR Threshold for Tag-Less Cipher "Failed" Blocks
- **Requirement:** Replace heuristic "failed block = PSNR < 40 dB" with an exact scientific definition.
- **Locations Found:**
  1. `src/baseline_ciphers.py` and `experiments/exp_containment.py`: Defined a block as failed if its PSNR relative to clean was $< 40$ dB.
- **Resolution Plan (Task 5.3):** A decrypted block is defined as `wrong` if and only if any byte in the 768-byte plaintext differs from the clean block (`bytes(decrypted) != bytes(original)`). Report `blocks_wrong`, `blocks_detected`, precision, recall, and exact Error Propagation Radius ($\text{EPR} = \text{blocks\_wrong} / \text{blocks\_corrupted}$).

### F. Throughput Definitions (Crypto-Only vs End-to-End)
- **Requirement:** Clearly separate and specify whether throughput includes block splitting, padding, and merging.
- **Locations Found:**
  1. `experiments/exp_overhead.py`: Calculated both `throughput_mbps` (pure cryptographic transform on pre-allocated blocks) and `e2e_throughput_mbps` (including image padding, block splitting, record packing, and unpadding), but downstream tables and text sometimes conflated them.
  2. `scripts/make_tables.py`: Emitted `throughputSixteen` as pure crypto throughput (450.5 MB/s) without labeling it distinct from end-to-end throughput (264.6 MB/s).
- **Resolution Plan (Task 9.3):** Strictly define and report BOTH:
  - `crypto_only_throughput`: $\text{Payload Bytes} / \text{Crypto Latency}$ (pure AES-GCM operation).
  - `end_to_end_throughput`: $\text{Raw Image Bytes} / \text{End-to-End Latency}$ (including split, pad, frame, transmit, unframe, decrypt, unpad).
  - Standardize strictly on decimal MB/s ($10^6$ bytes/second).

---

## 3. Audit Summary Matrix

| Audit Item | Current State | Target State (Post-Revision) | Task |
| :--- | :--- | :--- | :--- |
| **Forward Secrecy** | Negated in comments, unformalized in docs | Formally disclaimed in `docs/SECURITY.md` | Task 1.6 |
| **Device ID Transmission** | Clear-text in UI and test scripts | Never transmitted, strictly local HKDF context | Task 1.1, 1.3 |
| **Session Header Layout** | Ad-hoc 76B structure with salts | Fixed 134B X25519 authenticated header | Task 1.4 |
| **Packet Loss / Gaps** | Aborted stream in security test script | Tag-directed spatial concealment ($\le \tau$) | Task 2.1 |
| **Duplicate Packets** | Aborted session | Filtered: first copy accepted, rest ignored | Task 2.3 |
| **Tag-Less Block Failure** | PSNR < 40 dB heuristic | Exact byte difference (`bytes != bytes`) | Task 5.3 |
| **Throughput Reporting** | Mixed or single label | Distinct `crypto_only` & `end_to_end` MB/s | Task 9.3 |

---

## 4. Status of Known Issues (K1 -- K15)

| ID | Issue Description | Root Cause | Status & Fix Location |
|---|---|---|---|
| **K1** | Table 7 renders with only 1 column; Table 6 T08 cut off | Unescaped `%` character in LaTeX cells eaten as comment | **CONFIRMED & FIXED**: Automated LaTeX escaping in `scripts/make_tables.py` and validated by `scripts/lint_latex.py`. |
| **K2** | Table 3 caption says "768x512, 1536 Total Blocks" | Residual draft text from synthetic test | **CONFIRMED & FIXED**: Verified authentic Submarine is $1199\times 460$ (padded $1200\times 464$, 2,175 blocks). Macro and table generators use authentic image specs. |
| **K3** | Table 4 caption says "1024x512 Test Image" | Inconsistent caption | **CONFIRMED & FIXED**: Updated in `tables/table4_overhead.tex` with Submarine authentic specs (2,175 blocks for $16\times 16$). |
| **K4** | Fig 2 caption values don't match Table 3 means | Fig 2 is a single visual trial; Table 3 is a 30-trial mean | **CONFIRMED & FIXED**: Pinned Figure 2 to deterministic trial `submarine_K25_trial0` (Seed 42, raw 30.62 dB, conc 44.38 dB, gain +13.76 dB, CBC 11.03 dB) in `results/fig2_metrics.json`. Table 3 correctly reflects multi-trial means. |
| **K5** | Table 3 CBC PSNR at K=25 equals concealment gain (11.54) | Coincidence / roundoff artifact | **CONFIRMED & FIXED**: Verified against code run: Unframed CBC desynchronizes to ~11.03 dB; mean concealment gain across 30 trials is +11.55 dB. Distinct values tabulated. |
| **K6** | Fig 4 annotation says 6.46 ms; Table 4 says 6.00 ms | Outdated figure data from earlier machine run | **CONFIRMED & FIXED**: Regenerated figures via `scripts/make_figures.py` directly from `results/blocksize_tradeoff.json` (3.67 ms latency). |
| **K7** | Table 5 CPU utilization percentages do not match formula | Inconsistent formula used in old draft | **CONFIRMED & FIXED**: Standardized on explicit formula $U = (R / T_{\text{crypto}}) \times 100\%$ in `scripts/make_tables.py` (720p60 = 40.0%, 1080p30 = 45.0%, 1080p60 = 90.0%). |
| **K8** | Throughput units mixed binary MiB/s and decimal MB/s | Implicit conversion in early scripts | **CONFIRMED & FIXED**: Standardized exclusively on decimal megabytes per second ($10^6$ bytes/s) across all code, tables, and macros. |
| **K9** | ML experiment counts did not add up | Incomplete trial reporting | **CONFIRMED & FIXED**: Overhauled `exp_ml_downstream.py` to test 500 ImageNet validation images across 10 trials per level under both S1 and S2 (100,500 total inferences). |
| **K10** | Table 3 shows EPR = 1.00 at K=0 | Division by zero ($0/0$ is undefined) | **CONFIRMED & FIXED**: Formatted as a dash (`---`) in `table3_containment.tex` when $K=0$. |
| **K11** | Plain correlation claimed $>+0.95$ not tabulated; $|r| < 0.0310$ with $-0.0310$ | Omitted plain column; unescaped minus | **CONFIRMED & FIXED**: Plain and cipher correlations ($r_H, r_V, r_D$) both tabulated in Table 2; maximum $|r| = 0.0304$. |
| **K12** | Table 1 literature rows unverified; cascading diffusion unsupported | Generic values from external review | **CONFIRMED & FIXED**: Literature values cited to exact papers in `data/literature_table.csv`; test images noted; unverified items flagged `TODO_USER`. |
| **K13** | Citation errors in bibitems | Malformed entries | **CONFIRMED & FIXED**: Replaced with verified citations in `paper_icmlde/sw.tex`; verified zero undefined citations via `scripts/lint_latex.py`. |
| **K14** | Page-1 footer footnote overlapping template | Elsarticle template macro issue | **CONFIRMED & FIXED**: Documented in `HANDOFF_FOR_PAPER.md` for typesetting adjustments. |
| **K15** | Conceptual gaps: key delivery, DRL authentication, forward secrecy | Missing protocol mechanisms | **CONFIRMED & FIXED**: (a) X25519 ephemeral-static key agreement in 134B header; (b) Ed25519 signed DRL with version rollback check; (c) Forward secrecy formally disclaimed in `docs/SECURITY.md`. |

---

## 5. Test Suite & Code Coverage Report

Executed on **Python 3.13.2 / Windows 11**:
- **Total Unit Tests**: 63 passed, 0 failures, 0 errors in 3.36s.
- **Trace Coverage Results (`src/`)**:
  - `baseline_ciphers.py`: 101 / 177 lines (57.06%)
  - `decryption.py`: 109 / 189 lines (57.67%)
  - `encryption.py`: 26 / 47 lines (55.32%)
  - `error_concealment.py`: 89 / 128 lines (69.53%)
  - `error_simulator.py`: 19 / 25 lines (76.00%)
  - `image_crypto_metrics.py`: 76 / 107 lines (71.03%)
  - `image_processor.py`: 27 / 47 lines (57.45%)
  - `key_manager.py`: 146 / 268 lines (54.48%)
  - `record_format.py`: 57 / 106 lines (53.77%)
  - **Overall Core Coverage**: **650 / 1,136 executable lines (57.22%)**.

---

## 6. Execution Runtime Summary

| Stage / Script | Execution Time | Output Status |
|---|---|---|
| Unit Test Suite (63 tests) | 3.36 s | PASS (100%) |
| `experiments/exp_crypto.py` | 14.8 s | All metrics written to `results/` |
| `experiments/exp_containment.py` | 42.1 s | 6 image benchmarks & Figure 2 metrics generated |
| `experiments/exp_security.py` | 11.4 s | 1,700 adversarial trials executed |
| `experiments/exp_ml_downstream.py` | 24.6 s | 100,500 inferences evaluated |
| `experiments/exp_blocksize_tradeoff.py` | 7.9 s | Trade-off data generated |
| `experiments/exp_concealment_baselines.py` | 5.8 s | Mean fill vs interpolation benchmarked |
| `scripts/benchmark_portable.py` | 4.9 s | Host profile & streaming feasibility recorded |
| `scripts/make_tables.py` | 0.9 s | Tables 1–7 & macros generated |
| `scripts/make_figures.py` | 4.8 s | Figures 1–5 generated |
| `scripts/lint_latex.py` | 0.4 s | Zero lint errors across 9 LaTeX files |

---

## 7. Open Items & Verification Status

All unresolved non-code items (e.g., copyright licenses of legacy benchmark images like Lena/Baboon, unverified literature numbers requiring original author contact) are recorded in [OPEN_ITEMS.md](OPEN_ITEMS.md).

