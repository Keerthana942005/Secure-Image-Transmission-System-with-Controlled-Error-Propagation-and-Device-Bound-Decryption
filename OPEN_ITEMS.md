# OPEN_ITEMS.md: Unresolved Items, External Dependencies, and Verification Checklist

This document catalogs all items that could not be fully resolved within the project codebase and require author / user action before final camera-ready submission.

---

## 1. Dataset Licenses and Origins (`TODO_USER`)

In `results/dataset_manifest.json`, technical properties (dimensions, channels, byte sizes, block counts, and SHA-256 cryptographic hashes) have been measured and verified. However, legal licensing and provenance cannot be synthesized or guessed:

| Image File | Dimensions | SHA-256 Digest | Provenance / Open Question (`TODO_USER`) |
|---|---|---|---|
| `submarine.png` | $1199 \times 460$ | `e0350d3221e05beba02996e3db9822a10e74b5c7772634f1ec2f059296e83060` | Verify image license (public domain, Creative Commons, or author-acquired). |
| `cameraman_256.png` | $256 \times 256$ | `cb9201f8876feec999cfb9f5f00e9ec19b88cf189cb79b128c74384b6c31bf07` | Classic MIT/USC-SIPI benchmark image. Verify standard academic fair-use attribution. |
| `baboon_512.png` | $512 \times 512$ | `c048386b240ff8eb52aa00b467e41e5491ce7c01a938c5f6e85c2c77d46c8273` | USC-SIPI Image Database #4.2.03. Verify fair-use citation. |
| `peppers_512.png` | $512 \times 512$ | `ba0e98c772cbcf3fc4ffb1cbfe4953bf59c38148b37e2cb0ff90d1f73752e511` | USC-SIPI Image Database #4.2.07. Verify fair-use citation. |
| `medical_mri_512.png`| $512 \times 512$ | `e2541a7dc24fc287db1c3cf5675f92ff488e1bbd8d09559ef17765934440fa37` | Verify clinical open-access database source (e.g., TCIA, OASIS, or synthetic). |
| `satellite_1024.png`| $1024 \times 1024$ | `bcae88402f0674ea4f971c260268ecce49b29cfc70f1a265ae586b6279f532a3` | Verify USGS / NASA Earth Observatory open-data attribution. |

---

## 2. Literature Comparison Metrics (`TODO_USER`)

In `data/literature_table.csv` and `tables/table2_chaotic.tex`, benchmark comparisons against prior chaotic and lightweight schemes are tabulated.

| Scheme Cited | Claimed Entropy | Claimed NPCR / UACI | Verification Status (`TODO_USER`) |
|---|---|---|---|
| **Chai et al. (2019)** [Opt. Lasers Eng.] | 7.9993 | 99.62% / 33.45% | Verified from paper text for Lena $512\times 512$. Author should double-check whether plaintext-dependent diffusion mechanism has published CVEs or known chosen-plaintext vulnerabilities. |
| **Hua et al. (2015)** [IEEE TCSS] | 7.9994 | 99.61% / 33.46% | Verified from paper text for $512\times 512$ test images. |
| **Zhou et al. (2014)** [Signal Process.] | 7.9991 | 99.60% / 33.42% | Verified from paper text. Note: chaotic map schemes lack authentication tags; this fundamental architectural distinction is highlighted in the paper. |

---

## 3. Hardware Boundaries and Future Extensions

1. **Hardware Root of Trust (TPM 2.0 / ARM TrustZone)**:
   - The current implementation generates Device IDs from the host MAC address / OS UUID and binds them via HKDF.
   - *Limitation*: A physical attacker with administrative OS access can spoof MAC addresses in software. Full hardware isolation requires interfacing with a physical TPM 2.0 or ARM CryptoCell chip via PKCS#11.
2. **Ultra-High-Definition (4K 60fps) Video Streaming**:
   - The single-threaded pure cryptographic throughput measured on the test host (13th Gen Intel Core i5-13420H) is **414.8 MB/s**.
   - Uncompressed 720p60 (165.9 MB/s, 40.0% CPU) and 1080p30 (186.6 MB/s, 45.0% CPU) stream comfortably in real time.
   - Uncompressed 4K60 requires **1.49 GB/s**, which exceeds single-core CPU throughput ($359.9\%$ load) and requires multi-threaded task-parallel pipelines or GPU offloading via CUDA / Intel QuickSync.

---

## 4. Downstream Machine Learning Dataset Scope

- Full ImageNet (ILSVRC2012) validation set comprises 50,000 images (~6.5 GB).
- For reproducible CI and deterministic research iteration, we constructed `data/imagenet_subset.txt` comprising **500 authentic ImageNet validation images** with pinned SHA-256 digests.
- Across 10 Monte Carlo trials per level under 4 schemes and 5 corruption levels, this yields **100,500 total deep inferences**, providing narrow 95% bootstrap confidence intervals while executing in under 30 seconds.

