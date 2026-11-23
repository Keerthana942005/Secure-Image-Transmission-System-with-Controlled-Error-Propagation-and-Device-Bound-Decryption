# Final Revision Report: ICMLDE 5.0 (Paper ID 1323)

**Manuscript Title:** Secure Image Transmission System with Controlled Error Propagation, Device-Bound Decryption, and Downstream Machine Learning Resilience  
**Venue:** Procedia Computer Science (Elsevier) --- 5th International Conference on Machine Learning and Data Engineering (ICMLDE 5.0)  
**Authors:** Keerthana Nellyeri, Swetha Rajesh, Radhu Krishna R. (Corresponding Author, `radhukr@am.amrita.edu`)  
**Revision Date:** November 4, 2026  

---

## 1. Executive Summary

This revision comprehensively addresses all reviewer critiques and completes the 10 prioritized revision tasks for ICMLDE 5.0 Paper ID 1323. All ground rules were strictly enforced:
- **Zero Hallucination / Zero Hand-Typed Numbers:** Every quantitative figure and table in the manuscript (`paper_icmlde/sw.tex`) is derived directly from deterministic experiment runs ($S = 42$) via `scripts/make_tables.py` and synchronized through `tables/results_macros.tex`.
- **Full Test Suite Passing:** Unit test suite expanded from 67 to **74 tests**, passing 100% in 3.8s.
- **LaTeX Linter Green:** All **11 LaTeX files** passed `scripts/lint_latex.py` with 0 errors and 0 missing citation keys.
- **Single Source of Truth:** Results tables and publication figures are synchronized between repository root and `paper_icmlde/`.

---

## 2. Task-by-Task Implementation Summary

### Task 1: Multi-Image 5-Scheme Containment and Concealment
- **Implementation:** Created `experiments/exp_multi_image_containment.py` evaluating all five transmission schemes across the entire six-image benchmark suite (`cameraman_256`, `baboon_512`, `peppers_512`, `medical_mri_512`, `submarine`, `satellite_1024`) at matched loss fractions ($f \in [0.46\%, 1.15\%, 2.30\%, 4.60\%, 9.20\%]$, 30 trials per level per image).
- **Deliverables:**
  - `results/containment_multi_image_full.json`
  - `tables/table8_multi_image_containment.tex` (30 rows, synced to paper)
  - `figures/fig6_multi_image_containment.png` and `.pdf` (synced to paper)
- **Verified Findings:**
  - $\text{EPR} \equiv 1.00$ holds strictly across all images and corruption levels for the proposed scheme and framed CBC.
  - Mean concealment gains strictly span **+10.78 dB to +26.64 dB** across images (Submarine: +10.78 to +11.55 dB; Satellite: +20.14 to +20.41 dB; Medical MRI: +20.53 to +24.22 dB; Peppers: +15.84 to +16.27 dB; Baboon: +12.87 to +13.19 dB; Cameraman: +15.87 to +26.64 dB).
  - Unframed AES-CBC suffers severe byte desynchronization, with EPR reaching up to **206.90**. Monolithic GCM yields 0% availability.

### Task 2: Faithful Re-Implementation of Chaotic & Selective Baselines
- **Implementation:** Created `src/chaotic_ciphers.py` with faithful reference implementations of:
  1. Zhou et al. (2014) 1D Chaotic System (Logistic-Tent cascade + permutation + sequential XOR diffusion).
  2. Hua et al. (2015) 2D Sine-Logistic-Modulation Map (2D-SLMM) with coupled modular addition diffusion.
  3. MSB Selective Encryption (AES-256-CTR applied strictly to the 4 MSBs, leaving 4 LSBs in plaintext).
- **Testing & Benchmarking:**
  - Created `tests/test_chaotic_ciphers.py` (6 unit tests verifying gray/RGB roundtrips and LSB preservation).
  - Created `experiments/exp_chaotic_baselines.py` measuring entropy, NPCR, UACI, correlation, and runtime on all six benchmark images under 15 one-bit perturbations each.
  - Stored in `results/chaotic_baselines.json`.
- **Table Regeneration:** Updated `data/literature_table.csv` and regenerated `tables/table2_chaotic.tex`. All placeholders and `TODO_USER` tokens removed; all values labeled *"our re-implementation"* with genuine citations.

### Task 3: Hardware Portability & Multi-Config Profiling
- **Implementation:**
  - Validated single benchmark authority `scripts/benchmark_portable.py`.
  - Created `scripts/aggregate_hardware.py` which aggregates multi-machine JSON profiles into `tables/table5_multi_hardware.tex`.
  - Created `HARDWARE_RUNS.md` with drop-in benchmarking instructions for external architectures (Raspberry Pi, Jetson, Apple M-series).
- **Analyzed Overhead Ratio:** Documented monolithic GCM throughput ($1756.2\text{ MB/s}$) vs. $16\times 16$ block GCM ($569.2\text{ MB/s}$ pure crypto, $191.9\text{ MB/s}$ E2E), noting the $\sim 3.08\times$ pure crypto ratio due to 2,175 individual GHASH tag evaluations per image.

### Task 4: Consistency Bug Fix ($\tau = 0.25$)
- **Correction:** In `paper_icmlde/sw.tex:248`, changed `(default $\tau = 0.50$)` to `(default $\tau = 0.25$)`.
- **Verification:** Aligned with `src/config.py` (`DEFAULT_TAU = 0.25`), `src/decryption.py`, and security vector T08 in `experiments/exp_security.py` (*"Truncation of trailing 50% of stream (exceeding tau=0.25)"*).

### Task 5: Security Analysis & Arguments Strengthening
- **Formal Proof Sketches Added:** Added Section 3.5 in `paper_icmlde/sw.tex`:
  1. *IND-CPA Confidentiality Sketch:* Reduced to AES pseudorandom permutation assumption via PRP-PRF switching lemma.
  2. *INT-CTXT Integrity Sketch:* GHASH universal hash over $\text{GF}(2^{128})$ bounding forgery probability per block record to $\le 51 \cdot 2^{-128} \approx 1.49 \times 10^{-37}$.
  3. *Multi-Attribute AAD Security:* Algebraic proof that modifying index $i$, dimensions $(H, W)$, block count $N$, or epoch $t$ causes tag verification failure with probability $\ge 1 - 51 \cdot 2^{-128}$.
  4. *Softened EPR Language:* Clarified that $\text{EPR} = 1.00$ is an algebraic property of CTR-mode keystream independence under sequence framing, not a formal security proof.
  5. *Duplicate Nonce Guard Verification:* Added `test_duplicate_nonce_tamper_and_replay_detection` in `tests/test_nonce_guard.py` verifying receiver tag failure under reused nonce with modified ciphertext, and deduplication of replayed records.
  6. *Explicit Non-Guarantees:* Stated lack of forward secrecy across a static key lifetime, unauthenticated nature of spatial concealment (alerted via `concealed_block_mask`), LAN MAC spoofing limitations, and truncation limit $\tau$.

### Task 6: Novelty Positioning vs. STREAM and SRTP
- **Architectural Differentiation:** Rewrote Section 2.2 and contributions in Section 1 contrasting our 2D spatial visual AEAD against 1D STREAM and SRTP (RFC 3711).
- **Comparative Table:** Created and integrated `tables/table9_stream_comparison.tex` comparing STREAM, SRTP, Whole-Image GCM, Chaotic Schemes, and Proposed across framing, primitives, integrity, error containment, 2D concealment, and ML availability.
- **Relevance to ICMLDE Theme:** Highlighted downstream neural network inference availability under transmission noise (MobileNetV2 retaining 83.8% top-1 agreement under 9.18% block loss, where monolithic AEAD drops to 0% availability).

### Task 7: Abstract, Scope, and Conclusion
- **Abstract:** Preserved at 175 words, eliminating library names and implementation minutiae while highlighting core innovations, quantitative findings, and ML resilience.
- **Scope & Limitations:** Expanded Section 5 limitations (Limitation 6 updated to reflect six benchmark images across 5 corruption levels).
- **Conclusion:** Re-verified exact analytical framing overhead (4.17%), total overhead with padding (5.16%), and execution latencies (2.91 ms encryption / 2.84 ms decryption vs. 0.84 ms for monolithic GCM).

### Task 8: Paper Hygiene & Layout
- **Elsevier Footer Overlap:** Removed negative vertical space `\vspace*{-6pt}` after frontmatter to prevent footnote/footer collision in `elsarticle.cls`.
- **Author Checklist:** Created `TODO_FOR_AUTHOR.md` detailing repository URL replacement, benchmark image provenance/licences, and plagiarism audit instructions.
- **Proofreading Log:** Created `PROOFREAD_LOG.md` documenting terminology alignments.

### Task 9: Response to Reviewers
- **Deliverables:**
  - `response_to_reviewers.tex`: Complete standalone LaTeX response document with point-by-point callout boxes for every reviewer comment.
  - `response_to_reviewers.md`: Updated with Paper ID 1323, exact section/page/table cross-references, and PDF compilation instructions.

### Task 10: Final Verification & Reproducibility
- **Automated Validation:**
  - Ran `python tasks.py test`: **74 tests passing** in 3.8s.
  - Ran `python tasks.py lint`: **11 LaTeX files passed with 0 errors**, 214 defined macros loaded.
  - Ran `python scripts/make_tables.py`: all 8 tables generated and synced.
  - Ran `python scripts/make_figures.py`: all 6 publication figures generated and synced.
  - Updated `README.md` with complete step-by-step reproduction instructions.

---

## 3. Key Files Created and Modified

| File Path | Action | Description |
| :--- | :--- | :--- |
| `src/chaotic_ciphers.py` | Created | Faithful implementations of Zhou 1D, Hua 2D-SLMM, and MSB Selective AES-CTR. |
| `tests/test_chaotic_ciphers.py` | Created | Unit tests for chaotic and selective encryption ciphers (6 tests). |
| `tests/test_nonce_guard.py` | Modified | Added duplicate nonce tamper and replay detection test. |
| `experiments/exp_chaotic_baselines.py` | Created | Benchmarking script for chaotic/selective ciphers across 6 images (15 perturbations each). |
| `experiments/exp_multi_image_containment.py` | Created | Multi-image 5-scheme containment experiment (6 images, 5 fractions, 30 trials/level). |
| `results/chaotic_baselines.json` | Created | Empirical metrics for Zhou, Hua, and MSB Selective encryption. |
| `results/containment_multi_image_full.json` | Created | Full multi-image containment dataset across all 5 schemes. |
| `data/literature_table.csv` | Modified | Updated with empirically measured values from our reference implementations. |
| `tables/table2_chaotic.tex` | Regenerated | Literature comparison table with measured empirical values (no TBDs). |
| `tables/table8_multi_image_containment.tex` | Created | 30-row multi-image containment table across 6 images and 5 fractions. |
| `tables/table9_stream_comparison.tex` | Created | Architectural comparison table (STREAM vs. SRTP vs. Monolithic vs. Chaotic vs. Proposed). |
| `tables/table5_multi_hardware.tex` | Created | Multi-hardware platform aggregation table. |
| `figures/fig6_multi_image_containment.png/.pdf`| Created | Multi-image containment and concealment gain summary figure. |
| `scripts/aggregate_hardware.py` | Created | Script to compile hardware profiles into LaTeX tables. |
| `scripts/make_tables.py` | Modified | Added Table 8 generator, updated Table 2 footnote and syncing. |
| `scripts/make_figures.py` | Modified | Added Figure 6 generator and syncing. |
| `HARDWARE_RUNS.md` | Created | Guidelines for running portable benchmarks on external hardware. |
| `TODO_FOR_AUTHOR.md` | Created | Author checklist for external links, image licenses, and similarity check. |
| `PROOFREAD_LOG.md` | Created | English proofreading and terminology harmonization audit. |
| `response_to_reviewers.tex` | Created | Standalone LaTeX response letter formatted for submission. |
| `response_to_reviewers.md` | Modified | Updated point-by-point reviewer response with exact sections and Paper ID 1323. |
| `paper_icmlde/sw.tex` | Modified | Incorporated formal proof sketches, STREAM/SRTP comparison, Table 8/9, Fig 6, $\tau=0.25$ fix. |
| `README.md` | Modified | Added detailed reproduction guide and updated test/table counts. |

---

## 4. Instructions for Building `1323_revised_version.pdf`

Because `pdflatex` is not in the Windows sandbox PATH, compile using either of the two standard methods:

### Method A: Local Compilation (Command Prompt / PowerShell with TeX Live or MiKTeX)
```bash
cd paper_icmlde
pdflatex -interaction=nonstopmode sw.tex
pdflatex -interaction=nonstopmode sw.tex
cp sw.pdf ../1323_revised_version.pdf
```

### Method B: Overleaf (Recommended)
1. Compress the `paper_icmlde/` folder into a ZIP file.
2. Create a new project on [Overleaf](https://www.overleaf.com/) via *"Upload Project"*.
3. Ensure the project compiler is set to **pdfLaTeX** with TeX Live 2024.
4. Compile `sw.tex` and download the resulting PDF as `1323_revised_version.pdf`.

