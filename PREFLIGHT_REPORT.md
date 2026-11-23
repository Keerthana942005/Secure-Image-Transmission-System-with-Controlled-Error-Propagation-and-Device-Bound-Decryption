# PREFLIGHT_REPORT.md: Pre-Flight Audit of Secure Image Transmission System

**Audit Date:** 2026-11-04  
**Audit Scope:** Read-Only verification of codebase, unit tests, experimental results, performance benchmarks, LaTeX tables, macros, and documentation prior to paper revision.  
**Operating Environment:** Windows 11 AMD64, 13th Gen Intel Core i5-13420H, Python 3.13.2, `cryptography 50.0.2`, `numpy 2.5.2`, `onnxruntime 1.31.1`.

---

## 12. Pre-Flight Verdict & Summary Table

| Check Item | Verdict | Evidence / Status Summary |
|---|:---:|---|
| **Unit Tests** | **PASS** | 63 passed, 0 failed, 0 skipped in 4.99s via `python tasks.py test`. |
| **LaTeX Linter** | **PASS** | `python scripts/lint_latex.py`: 0 errors across 9 files, 42 macros validated. |
| **Session Header Design** | **PASS** | Exact 134 bytes: magic(4), ver(1), flags(1), epoch(4), H(4), W(4), N(4), salts(32), eph_pub(32), fingerprint(16), HMAC(32). HMAC covers bytes 0..101. |
| **Receiver Order of Operations** | **PARTIAL** | Key derivation and HMAC verification happen before payload decryption; however, `verify_and_update_epoch` commits epoch advancement before HMAC verification. |
| **Device-ID Non-Transmission** | **PARTIAL** | Device ID digest is never sent over the wire, in headers, or in records. However, `app.py` displays `get_device_id()` in UI and `show_device_id.py` prints it locally. |
| **Forward-Secrecy Claims Removed** | **PASS** | Zero positive claims found. Explicit disclaimers exist in `docs/SECURITY.md`, `README.md`, `app.py`, and `sw.tex`. |
| **Action Labels & Security Matrix** | **PASS** | 5 exact action labels implemented. 17 attack vectors evaluated across 100 trials each (1,700 total), achieving 100.0% detection. |
| **Containment for 6 Benchmark Images** | **PASS** | All 6 images evaluated across 30 trials per level for $K \in \{0, 10, 25, 50, 100, 200\}$. |
| **CBC+HMAC Baseline** | **PASS** | Implemented and evaluated in both `exp_containment.py` and `exp_ml_downstream.py`. |
| **ML Scenarios (S1 & S2)** | **PASS** | Both S1 (Record Loss) and S2 (In-Place Bit Flips) present in `results/ml_downstream.json` across 500 ImageNet images (100,500 total inferences). |
| **Concealment Baselines** | **PARTIAL** | Zero-mask and mean-color fill benchmarked. OpenCV Telea/Navier-Stokes are `null` because `opencv-python` is not installed. |
| **Block-Size Trade-off** | **PASS** | Evaluated for [8, 16, 32, 64] across constant area fractions (1.0%, 2.3%, 4.6%, 9.2%). |
| **Crypto Metrics with Plain Correlation** | **PASS** | Plain and cipher entropy, NPCR/UACI, chi-square, and H/V/D correlations tabulated across 6 images; max $|r| = 0.0304$. |
| **CBC Baseline Crypto Metrics** | **PASS** | `results/crypto_metrics_cbc.json` present across 6 images (mean entropy 7.9997, NPCR 99.61%, UACI 33.46%). |
| **Real-Time Load Reporting** | **PARTIAL** | Real-time supported for pure crypto throughput (414.8 MB/s; 720p60 at 40.0% load, 1080p30 at 45.0% load). End-to-end (138.7 MB/s) is not real-time on a single core. |
| **Second Hardware Device** | **FAIL** | Only 1 host machine benchmarked (`LAPTOP-95MMSK7G`). Second hardware platform is not present. |
| **Results Macros Completeness** | **PARTIAL** | 42 macros defined and validated. Secondary parameters (header bytes, record bytes, PBKDF2 time) remain in prose/tables without macros. |
| **Generated LaTeX Tables** | **PASS** | Tables 1–7 complete, 0 unescaped `%`, cell counts match specs, no truncated lines. |
| **Publication Figure Regeneration** | **PASS** | All 5 figures regenerate cleanly to vector PDF and 300 DPI PNG in `figures/` and `paper_icmlde/figures/`. |
| **Figure 1 Content** | **PARTIAL** | Illustrates high-level pipeline and 800-byte record format; does not illustrate the 134-byte session header layout or 2D mask grid. |
| **Open Items Documentation** | **PASS** | `OPEN_ITEMS.md` catalogs dataset licensing, literature verification, and hardware extensions. |
| **Repository URL Verified** | **FAIL** | `\url{https://github.com/SecureImageTransmission/SecureImageTransmission_new}` in `sw.tex:350` is a placeholder / unverified URL. |
| **Code Coverage Target** | **PARTIAL** | Overall `src/` line coverage is 57.22% (650 / 1136 lines); core modules are below 90% target. |

---

### A. Blockers
None that halt the writing process. The repository code is functionally complete, test suite passes 100%, and all tables/macros/figures regenerate cleanly from verified experimental data.

### B. Paper Constraints (Claims the Paper Must NOT Make)
1. **Do NOT claim forward secrecy**: Must explicitly state that the scheme provides defense-in-depth ephemeral-static key agreement and epoch-based replay rejection, but not forward secrecy under passphrase and static private key compromise.
2. **Do NOT claim real-time streaming for uncompressed end-to-end processing on a single core**: Pure cryptographic transformation achieves 414.8 MB/s (supporting 720p60 at 40.0% load and 1080p30 at 45.0% load), but single-threaded end-to-end Python throughput is 138.7 MB/s (119.6% load for 720p60).
3. **Do NOT claim multi-device hardware evaluation**: Performance was benchmarked on a single host processor (13th Gen Intel Core i5-13420H, 12 threads).
4. **Do NOT claim empirical numerical comparison against OpenCV inpainting**: OpenCV Telea and Navier-Stokes were not evaluated because OpenCV is an optional external dependency; report comparisons against zero-mask and mean-color fill.
5. **Do NOT claim 90% test coverage**: Empirical line coverage is 57.22% across `src/`.
6. **Do NOT claim ChaCha20-Poly1305 was benchmarked**: Only AES-GCM and AES-CBC schemes were benchmarked.
7. **Do NOT attribute the 600,000 PBKDF2 iteration count or the 16-character passphrase policy to NIST SP 800-132**: NIST SP 800-132 specifies the PBKDF2 mechanism, while the 600,000 count is guided by OWASP 2023 recommendations and the passphrase complexity is a local heuristic.

### C. User Actions Required
1. **Repository URL**: Replace placeholder `https://github.com/SecureImageTransmission/SecureImageTransmission_new` in `paper_icmlde/sw.tex:350` and `README.md` with the authentic repository URL.
2. **License & Citation**: Add `LICENSE` (e.g. MIT) and `CITATION.cff` to the root directory.
3. **Literature Table Verification**: Confirm experimental conditions and test images for Chai et al., Hua et al., and Zhou et al. in `data/literature_table.csv`.
4. **Dataset Attribution**: Verify acquisition licenses for benchmark images (`submarine.png`, `cameraman_256.png`, etc.) in `results/dataset_manifest.json`.

### D. Recommended Improvements (Non-Blocking)
1. Expand unit tests for `key_manager.py` and `decryption.py` to lift line coverage from 57% toward 80%+.
2. Move epoch state update in `src/decryption.py` so that it is committed strictly after `verify_session_header_hmac` succeeds.
3. Run `python scripts/benchmark_portable.py` on a secondary machine (e.g., Raspberry Pi or second laptop) to add a second hardware profile.

```
VERDICT: GO (with 7 paper constraints and 4 user actions)
```

---

## Detailed Audit Evidence by Section

### 1. Repo and Test Health

#### 1.1 Repo State
- **Status:** PARTIAL.
- **Evidence:** `git` is not installed in the Windows PATH (`where.exe git` returns "Could not find files"). The workspace is not an initialized git repository (`Test-Path .git` returns False).
- **Task Tracking:** Commit history (T0–T13) is maintained textually in [`CHANGELOG.md`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/CHANGELOG.md).
- **Consequence for Paper:** The paper must not claim a specific git commit SHA unless the repository is initialized in git prior to publication.

#### 1.2 Full Test Suite
- **Status:** PASS.
- **Command:** `python tasks.py test`
- **Evidence:** `Ran 63 tests in 4.995s. OK.` (63 passed, 0 failed, 0 skipped, exit code 0).

#### 1.3 Line Coverage
- **Status:** PARTIAL.
- **Command:** `python scripts/measure_coverage.py`
- **Evidence:**
  - `record_format.py`: 57 / 106 lines (53.77%)
  - `key_manager.py`: 146 / 268 lines (54.48%)
  - `encryption.py`: 26 / 47 lines (55.32%)
  - `decryption.py`: 109 / 189 lines (57.67%)
  - `baseline_ciphers.py`: 101 / 177 lines (57.06%)
  - `error_concealment.py`: 89 / 128 lines (69.53%)
  - `error_simulator.py`: 19 / 25 lines (76.00%)
  - `image_crypto_metrics.py`: 76 / 107 lines (71.03%)
  - `image_processor.py`: 27 / 47 lines (57.45%)
  - **Overall `src/` Line Coverage:** **650 / 1,136 lines (57.22%)**.
- **Consequence for Paper:** Core modules do not reach the 90% aspirational target. The paper must not claim 90% unit test coverage.

#### 1.4 LaTeX Linter & Failure Injection
- **Status:** PASS.
- **Command:** `python scripts/lint_latex.py`
- **Output:** Loaded 42 defined macros from `results_macros.tex`. Linted 9 LaTeX files with 0 errors.
- **Prohibited Phrases Checked:**
  1. `\bforward\s*secrecy\b`
  2. `\bproven\s+contain`
  3. `\bzero\s+leakage\b`
  4. `\bmathematical\s+proof\s+of\s+containment\b`
- **Failure Injection Test:** Tested against a corrupted sample in `preflight/broken.tex` containing an unescaped `%` and a truncated row (2 cells instead of 3). The linter caught both errors cleanly.

#### 1.5 Pipeline Execution in Temp Copy
- **Status:** PASS.
- **Command:** Copied repository to `$env:TEMP\sit_preflight_test`, ran `python tasks.py all`.
- **Output:** ExitCode: 0, Elapsed time: 40.66s. All tests, tables, figures, and linter passed.

#### 1.6 Dependency Lock
- **Status:** PARTIAL.
- **Evidence:** [`requirements.txt`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/requirements.txt) has 8 strictly pinned packages: `cryptography==50.0.2`, `numpy==2.5.2`, `pillow==12.3.0`, `scipy==1.18.1`, `scikit-learn==1.9.1`, `onnxruntime==1.31.1`, `matplotlib==3.11.2`, `streamlit==1.62.0`.
- **Torch / Torchvision Status:** Not present in requirements or environment JSON because the ML evaluation uses standalone ONNX Runtime (`models/mobilenetv2-7.onnx`). Torchvision weights enum is not recorded.

---

### 2. Security Design Checks

#### 2.1 Session Header Byte Layout
- **Status:** PASS.
- **Evidence:** [`src/record_format.py:46-72`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/record_format.py#L46-L72):
  - Offset 0 (4B): Magic `b"SIT1"`
  - Offset 4 (1B): Version `0x01`
  - Offset 5 (1B): Flags `0x00`
  - Offset 6 (4B): Epoch (`uint32`)
  - Offset 10 (4B): Height (`uint32`)
  - Offset 14 (4B): Width (`uint32`)
  - Offset 18 (4B): Total Blocks $N$ (`uint32`)
  - Offset 22 (16B): $S_{\text{hkdf}}$
  - Offset 38 (16B): $S_{\text{pbkdf2}}$
  - Offset 54 (32B): Ephemeral X25519 public key
  - Offset 86 (16B): Receiver key fingerprint (`SHA-256(PK_rx)[:16]`)
  - Offset 102 (32B): HMAC-SHA256 tag
  - Total length: **134 bytes**. The HMAC tag covers bytes 0..101.

#### 2.2 Order of Operations in Receiver
- **Status:** PARTIAL.
- **Evidence:** In [`src/decryption.py:180-220`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/decryption.py#L180-L220):
  1. Header fields parsed (`parse_session_header_fields`).
  2. Receiver fingerprint checked against local key; DRL checked.
  3. **Epoch monotonicity checked and committed** (`verify_and_update_epoch`).
  4. Keys derived (`derive_session_keys`).
  5. Header HMAC verified in constant time (`verify_session_header_hmac`).
  6. Image dimensions used to allocate buffers and decrypt blocks.
- **Consequence for Paper:** The epoch state update is committed at step 3 before the HMAC is verified at step 5. The paper should note that in the reference implementation, epoch advance precedes HMAC verification.

#### 2.3 Constant-Time Comparisons
- **Status:** PASS.
- **Evidence:**
  - Header HMAC: `hmac.compare_digest(hmac_tag, expected_hmac)` in [`src/record_format.py:148`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/record_format.py#L148).
  - Device ID: `hmac.compare_digest(current_id.lower(), authorized_device_id.lower())` in [`src/key_manager.py:301`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/key_manager.py#L301).
  - AEAD tags: Verified in constant time inside OpenSSL native C implementation (`aesgcm.decrypt`).

#### 2.4 Device ID Non-Transmission & Logging
- **Status:** PARTIAL.
- **Evidence:**
  - Wire transmission: Never written to session headers or block records.
  - Results JSON / Tables: Zero occurrences across `results/` and `tables/`.
  - UI Exposure: [`app.py:179, 294, 460`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/app.py#L294) displays `get_device_id()` in the Streamlit UI, and [`show_device_id.py:4`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/show_device_id.py#L4) prints it locally.
- **Consequence for Paper:** Do not claim that the prototype UI completely suppresses displaying the device ID digest to the local user.

#### 2.5 Key Schedule
- **Status:** PASS.
- **Evidence:** In [`src/key_manager.py:147-190`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/key_manager.py#L147-L190):
  - $K_{\text{session}} = \text{HKDF-SHA256}(\text{salt}=S_{\text{hkdf}}, \text{IKM}=\text{SharedSecret}, \text{info}=\text{"SIT-v1-session"} \parallel PK_{\text{eph}} \parallel PK_{\text{rx}})$.
  - $P_{\text{stretched}} = \text{PBKDF2-HMAC-SHA256}(\text{passphrase}, S_{\text{pbkdf2}}, \text{iterations}=600000, 32)$.
  - $\text{IKM} = K_{\text{session}} \parallel P_{\text{stretched}}$ (64 bytes).
  - $\text{PRK} = \text{HMAC-SHA256}(S_{\text{hkdf}}, \text{IKM})$.
  - $K_{\text{AES}} = \text{HKDF-Expand}(\text{PRK}, \text{"SIT-v1"} \parallel \text{device\_id} \parallel \text{uint32}(\text{epoch}), 32)$.
  - $K_{\text{hdr}} = \text{HKDF-Expand}(\text{PRK}, \text{"SIT-v1-header"}, 32)$.

#### 2.6 Epoch Persistence
- **Status:** PARTIAL.
- **Evidence:** Atomic file replacement using `.tmp.<pid>`, `f.flush()`, `os.fsync()`, and `os.replace()` in [`src/key_manager.py:227-235`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/key_manager.py#L227-L235). Tested across restart in `tests/test_key_transport.py:197`. However, inter-process file locking is not implemented.

#### 2.7 Device Revocation List (DRL)
- **Status:** PASS.
- **Evidence:** Ed25519 signature verification and rollback protection implemented in [`src/key_manager.py:310-385`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/key_manager.py#L310-L385). Tested in [`tests/test_drl.py`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/tests/test_drl.py) and `tests/test_receiver_policy.py:142`.

#### 2.8 Nonce Guards
- **Status:** PARTIAL.
- **Evidence:**
  - $2^{32}$ invocation counter guard implemented in [`src/encryption.py:34-39`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/encryption.py#L34-L39) and tested in `tests/test_nonce_guard.py:21`.
  - Nonce uniqueness tested across 409,600 nonces (100 sessions $\times$ 4,096 blocks) in `tests/test_nonce_guard.py:40`.
  - Deterministic nonce mode: default is OFF (`USE_DETERMINISTIC_NONCE = False`).
  - Benchmarked: Not separately benchmarked in `results/`.

#### 2.9 Forward Secrecy Claims
- **Status:** PASS.
- **Evidence:** Zero positive claims. Explicit disclaimers in `docs/SECURITY.md`, `README.md`, `app.py:477`, `AUDIT.md`, `CHANGELOG.md`, `HANDOFF_FOR_PAPER.md`. Zero occurrences in `paper_icmlde/sw.tex`.

#### 2.10 Passphrase Policy & Standards Attribution
- **Status:** PARTIAL.
- **Evidence:** Enforces length $\ge 16$ and $\ge 3$ of 4 character classes in [`src/key_manager.py:54-68`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/key_manager.py#L54-L68). No entropy estimation is computed.
- **Consequence for Paper:** The paper must cite OWASP for the 600,000 PBKDF2 iteration count rather than NIST SP 800-132, and describe the passphrase policy as a custom heuristic.

#### 2.11 Buffer Zeroization
- **Status:** PASS.
- **Evidence:** `best_effort_zeroize` in [`src/key_manager.py:42-50`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/key_manager.py#L42-L50) scrubs mutable `bytearray` buffers. `docs/SECURITY.md:89` explicitly documents that Python runtime semantics cannot guarantee complete memory erasure.

---

### 3. Receiver Policy and Action Labels

#### 3.1 Permitted Action Labels
- **Status:** PASS.
- **Evidence:** [`src/decryption.py:24-30`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/decryption.py#L24-L30) defines:
  - `detected_and_quarantined`
  - `concealed`
  - `duplicate_ignored`
  - `rejected_over_threshold`
  - `session_rejected`
  - (plus `authentic` for clean transmissions).

#### 3.2 Action Label Return Mapping
- **Status:** PASS.
- **Evidence:**
  - Tag failure: `detected_and_quarantined` (or `concealed` if $\le \tau$).
  - Missing record (gap / truncation): `concealed`.
  - Duplicate index: `duplicate_ignored`.
  - Stale epoch / Replay: `session_rejected`.
  - Header HMAC failure: `session_rejected`.
  - Revoked key/device: `session_rejected`.
  - Failed fraction $> \tau$: `rejected_over_threshold`.

#### 3.3 Default $\tau$
- **Status:** PASS.
- **Evidence:** `DEFAULT_TAU = 0.25` in [`src/config.py:23`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/src/config.py#L23).

#### 3.4 Concealed Image Marking
- **Status:** PASS.
- **Evidence:** Result dictionary sets `action = "concealed"`, `concealment_applied = True`, and returns a 2D boolean array `concealed_block_mask`. It is never marked as `authentic`.

---

### 4. Experiment Coverage

#### 4.1 All Six Images
- **Status:** PASS.
- **Evidence:** `containment_submarine.json`, `containment_cameraman_256.json`, `containment_baboon_512.json`, `containment_peppers_512.json`, `containment_medical_mri_512.json`, `containment_satellite_1024.json`, and `containment_summary.json` exist.

#### 4.2 Corruption Models (M1, M2, M3)
- **Status:** PASS.
- **Evidence:** Evaluated in `experiments/exp_containment.py`: M1 (in-place bit flips), M2 (unannounced stream loss), M3 (packet record loss).

#### 4.3 Schemes Present
- **Status:** PARTIAL.
- **Evidence:** Monolithic GCM, Unframed CBC, Framed CBC, Per-block CBC+HMAC, and Proposed Block GCM are all evaluated. ChaCha20-Poly1305 is NOT present.

#### 4.4 Trials and K Levels
- **Status:** PARTIAL.
- **Evidence:** 30 trials per level, $K \in \{0, 10, 25, 50, 100, 200\}$. Aggregated statistics stored in `containment_<image>.json`; per-trial corrupted indices stored in `results/fig2_metrics.json` for trial 0.

#### 4.5 Detection Metrics & EPR
- **Status:** PASS.
- **Evidence:** `gcm_precision_mean`, `gcm_recall_mean`, `gcm_wrong_mean`, `gcm_failed_mean`, `gcm_epr_mean` (`null` at $K=0$), `gcm_ssim_raw_mean`, `gcm_ssim_conc_mean` are all tabulated.

#### 4.6 Tag-Less EPR Definition
- **Status:** PASS.
- **Evidence:** `sum(1 for orig, d in zip(blocks, dec) if orig.tobytes() != d.tobytes())`. Strict byte difference; no PSNR threshold.

#### 4.7 CBC In-Place Bit-Flip Result
- **Status:** PASS.
- **Evidence:** At $K=10$, `cbc_bit_wrong_aes_mean = 20.0` (exactly 2.0 AES blocks per bit flip). At $K=25$, `cbc_bit_wrong_aes_mean = 50.0` (2.0 AES blocks). Image blocks wrong: 1.28 to 1.33 per flip.

#### 4.8 Figure 2 Pin
- **Status:** PASS.
- **Evidence:** [`results/fig2_metrics.json`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/results/fig2_metrics.json) specifies `trial_id: "submarine_K25_trial0"`, seed 42, $K=25$, raw PSNR 30.62 dB, concealed PSNR 44.38 dB, gain +13.76 dB, unframed CBC 11.03 dB.

#### 4.9 Concealment Baselines
- **Status:** PARTIAL.
- **Evidence:** Zero-mask and mean-color fill benchmarked. OpenCV Telea and Navier-Stokes are `null`.

#### 4.10 Six-Image Concealment Gain Range
- **Status:** PASS (Wider than Submarine).
- **Evidence:** Submarine alone is **10.78 to 11.55 dB**. Across all six images, the gain ranges from **5.83 dB** (cameraman at 78% corruption) to **21.80 dB** (medical MRI at $K=25$).

#### 4.11 Block-Size Trade-off
- **Status:** PASS.
- **Evidence:** At 9.2% corrupted area:
  - 8x8: Concealed PSNR = 33.29 dB, SSIM = 0.9951, Overhead = 16.67%, Tput = 66.1 MB/s
  - 16x16: Concealed PSNR = 31.49 dB, SSIM = 0.9925, Overhead = 4.17%, Tput = 219.3 MB/s
  - 32x32: Concealed PSNR = 29.52 dB, SSIM = 0.9880, Overhead = 1.04%, Tput = 608.7 MB/s
  - 64x64: Concealed PSNR = 28.67 dB, SSIM = 0.9837, Overhead = 0.26%, Tput = 1188.4 MB/s
  16x16 provides the optimal Pareto trade-off between quality (+2.82 dB over 64x64) and overhead (4x lower than 8x8).

#### 4.12 Crypto Metrics
- **Status:** PASS.
- **Evidence:** `results/crypto_metrics.json` contains plain and cipher entropy, per-channel entropy, theoretical max (8.0000), Chi-Square stats, fresh and fixed NPCR/UACI, key sensitivity (99.6%), and plain/cipher correlation ($r_H, r_V, r_D$). Max $|r| = \mathbf{0.0304}$ (baboon Vertical).

#### 4.13 CBC Crypto Baseline
- **Status:** PASS.
- **Evidence:** `results/crypto_metrics_cbc.json` present across 6 images: Mean Cipher Entropy = **7.9997**, Mean NPCR = **99.61%**, Mean UACI = **33.46%**.

#### 4.14 Dataset Manifest
- **Status:** PASS.
- **Evidence:** [`results/dataset_manifest.json`](file:///c:/Users/lenovo/Documents/SecureImageTransmission_new/results/dataset_manifest.json) lists all 6 images with dimensions, channels, sizes, and SHA-256 digests. Source and license fields are marked `TODO_USER`.

---

### 5. Security Matrix (Table 6)

- **Total Vectors:** 17.
- **Trials per Vector:** 100.
- **Total Attacks Evaluated:** 1,700.
- **Detection Rate:** **100.0%** across all 17 vectors.
- **Vector List:**
  - T01: In-Place Bit-Flip in Ciphertext (`detected_and_quarantined`)
  - T02: Block Swap / Index Splicing (`detected_and_quarantined`)
  - T03: Header Index Tampering (`detected_and_quarantined`)
  - T04: Cross-Session Splice (`detected_and_quarantined`)
  - T05: Cross-Epoch Replay in Stream (`detected_and_quarantined`)
  - T06: Dropped Record (Packet Loss) (`concealed`)
  - T07: Duplicated Record Injection (`duplicate_ignored`)
  - T08: Stream Truncation Attack (`rejected_over_threshold`)
  - T09: Dimension Tampering in AAD (`detected_and_quarantined`)
  - T10: Unauthorized Device ID (`detected_and_quarantined`)
  - T11: Incorrect Passphrase (`detected_and_quarantined`)
  - T12: Revoked Device Access (`session_rejected`)
  - T13: Session Header Bit-Flip (`session_rejected`)
  - T14: Ephemeral Public Key Substitution (`session_rejected`)
  - T15: Wrong Receiver Static Key (`session_rejected`)
  - T16: DRL Rollback Attack (`session_rejected`)
  - T17: Forged DRL Signature (`session_rejected`)

---

### 6. Downstream ML Experiment

- **Dataset:** 500 authentic ImageNet validation images (`data/imagenet_subset.txt` with SHA-256 digests).
- **Trials per Level:** 10.
- **Levels Evaluated:** $K \in \{1, 2, 5, 9, 18\}$ of 196 blocks (0.51%, 1.02%, 2.55%, 4.59%, 9.18%).
- **Scenarios Present:**
  - **S1 (Record Loss):** Unframed CBC drops to 23.54% agreement, Monolithic GCM yields 0%, Proposed Zero-Fill yields 41.64%, Proposed Concealed achieves **83.78%** (+42.14 pp gain).
  - **S2 (In-Place Bit Flips):** Unframed CBC retains 91.20% agreement (self-synchronization without integrity detection), Proposed Concealed achieves **83.78%** with full cryptographic authentication.
- **Total Inferences:** $500 \text{ clean} + (500 \text{ images} \times 10 \text{ trials} \times 5 \text{ levels} \times 4 \text{ evaluations}) = \mathbf{100,500\text{ deep inferences}}$.
- **ResNet-18:** Single architecture (MobileNetV2 only).

---

### 7. Performance and Hardware

- **Benchmark Hardware Profile:** 1 host machine (`LAPTOP-95MMSK7G`, 13th Gen Intel Core i5-13420H, 12 threads, Windows 11).
- **Measured Throughput (16x16 Proposed):**
  - Pure Crypto Throughput: **414.8 MB/s** (Latency: 3.67 ms).
  - End-to-End Throughput: **138.7 MB/s** (Latency: 11.93 ms enc, 14.27 ms dec).
- **Streaming Load Analysis ($U = R / T \times 100\%$):**
  - **720p60** ($R = 165.9\text{ MB/s}$): Crypto Load = **40.0%** (Feasible); End-to-End Load = **119.6%** (Infeasible on single core).
  - **1080p30** ($R = 186.6\text{ MB/s}$): Crypto Load = **45.0%** (Feasible); End-to-End Load = **134.6%** (Infeasible on single core).
  - **1080p60** ($R = 373.2\text{ MB/s}$): Crypto Load = **90.0%** (Feasible); End-to-End Load = **269.1%** (Infeasible).
  - **4K60** ($R = 1493.0\text{ MB/s}$): Crypto Load = **359.9%** (Requires GPU offload).
- **Discrepancy Note:** Table 4 lists 450.5 MB/s from block microbenchmarks (`overhead_metrics.json`), while Table 5 and `\throughputSixteen` use 414.8 MB/s from the portable multi-run benchmark (`bench_LAPTOP-95MMSK7G.json`).

---

### 8. Table and Macro Generation

- **Tables Generated:**
  - `table1_crypto.tex`: 6 authentic images, 11 columns.
  - `table2_chaotic.tex`: Literature comparison with Chai, Hua, Zhou (unverified entries footnoted).
  - `table3_containment.tex`: Submarine benchmark, 6 corruption levels, 14 columns.
  - `table4_overhead.tex`: Block sizes [8, 16, 32, 64] and Monolithic.
  - `table5_hardware.tex`: Host hardware profile and video streaming load.
  - `table6_security.tex`: 17 attack vectors, 100 trials each, 100.0% detection.
  - `table7_ml.tex`: Downstream MobileNetV2 agreement under packet loss.
- **Defined Macros (42 total in `results_macros.tex`):**
  - Complete list verified and synchronized with `paper_icmlde/tables/results_macros.tex`.
  - Secondary constants (e.g. 134 header bytes, 800 record bytes) remain in text.

---

### 9. Publication Figures

- All 5 figures exist as vector PDF and 300 DPI PNG in `figures/` and `paper_icmlde/figures/`:
  - `fig1_architecture`: System architecture and 800-byte record layout.
  - `fig2_visual_containment`: Visual comparison at $K=25$ (pinned trial `submarine_K25_trial0`).
  - `fig3_psnr_containment`: PSNR degradation and concealment gain curves across $K$.
  - `fig4_overhead_tradeoff`: Latency vs framing overhead across block granularities.
  - `fig5_ml_downstream`: MobileNetV2 classification agreement vs packet corruption rate.
- Fonts: Axes/titles 10–11 pt, legends 8.5–9 pt, sub-box annotations 7.5–8 pt.

---

### 10. Documentation and Hygiene

- **Present & Non-Empty:** `PLAN.md`, `AUDIT.md`, `CHANGELOG.md`, `HANDOFF_FOR_PAPER.md`, `OPEN_ITEMS.md`, `README.md`, `docs/SECURITY.md`, `Makefile`, `tasks.py`, `.github/workflows/ci.yml`.
- **Missing Files:** `CITATION.cff` and `LICENSE` do not exist.
- **Repository URL:** `sw.tex:350` references `https://github.com/SecureImageTransmission/SecureImageTransmission_new`, which is unverified.

---

### 11. Cross-Consistency Checks

1. **Analytical vs Total Framing Overhead:**
   - Analytical: $32 / 768 = 4.1667\% \implies \mathbf{4.17\%}$.
   - Submarine Total: $(2,175 \times 800 - 1,654,620) / 1,654,620 = 85,380 / 1,654,620 = \mathbf{5.16\%}$.
2. **Table 4 Arithmetic:** Submarine byte payloads and overheads for 8x8 (17.78%), 16x16 (5.16%), 32x32 (6.93%), and 64x64 (13.18%) match formulas exactly.
3. **Table 3 Subtractions:** Concealed PSNR minus Raw PSNR equals $\Delta\text{PSNR}$ across all $K$ rows.
4. **ML Gain Calculation:** $83.78\% - 41.64\% = \mathbf{+42.14\text{ pp}}$ gain over zero-fill at $K=18$.
5. **Random Nonce Collision Bounds:**
   - For $N = 2,175$: $P \approx 2.99 \times 10^{-23}$.
   - For $N = 4,096$: $P \approx 1.06 \times 10^{-22}$.
   - For $10^9$ nonces: $P \approx 6.31 \times 10^{-12}$.
6. **Key Invocation Capacity:** $2^{32} / 2,175 \approx \mathbf{1.97 \times 10^6\text{ images}}$ per key before mandatory rekeying.
7. **Fig. 2 Metrics vs Table 3:** Pinned single-trial metrics (raw 30.62 dB, conc 44.38 dB, gain +13.76 dB) are distinct from 30-trial averages in Table 3 (raw 29.90 dB, conc 41.44 dB, gain +11.55 dB) and documented.

---

```
PRE-FLIGHT AUDIT COMPLETE: PAPER REVISION AUTHORIZED UNDER CONSTRAINTS
```

