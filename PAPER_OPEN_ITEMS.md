# PAPER_OPEN_ITEMS.md: User Actions and Pending Discretionary Decisions

The following items in the manuscript (`paper_icmlde/sw.tex`) and repository require user input, domain credentials, or external verification before camera-ready submission. Each item is marked with a clear `TODO_USER` placeholder in the source files.

---

## 1. Literature Baseline Values (Table 2 / `data/literature_table.csv`)

| Scheme / Citation | Missing Fields | Current Paper Rendering | Action Required from User |
|---|---|---|---|
| **Chai et al. (2019)** [18] | Plain $H$, Cipher $H$, NPCR (\%), UACI (\%) | `TBD` | Extract or verify exact numerical metrics from Chai et al. (*Multimedia Tools and Applications*, 78(24), pp. 35419–35453) for the benchmark images evaluated. |
| **Hua et al. (2015)** [19] | Plain $H$, Cipher $H$, NPCR (\%), UACI (\%) | `TBD` | Extract or verify exact numerical metrics from Hua et al. (*Information Sciences*, 297, pp. 80–94) for the benchmark images evaluated. |
| **Zhou et al. (2014)** [20] | Plain $H$, Cipher $H$, NPCR (\%), UACI (\%) | `TBD` | Extract or verify exact numerical metrics from Zhou et al. (*Signal Processing*, 97, pp. 172–182) for the benchmark images evaluated. |

*Note: The script `scripts/make_tables.py` automatically populates Table 2 from `data/literature_table.csv`. Once the user enters the validated numbers into the CSV, re-running `python scripts/make_tables.py` will update the table without touching LaTeX prose.*

---

## 2. Benchmark Image Provenance and Licences (Section 4.1)

| Benchmark Image | Stated Dimensions / Format | Status in Paper | Action Required from User |
|---|---|---|---|
| **Cameraman** | $256\times 256$, RGB (from grayscale) | `[TODO_USER: source/licence]` | Provide official archival source (e.g., MIT/USC-SIPI database) and licence (e.g., Public Domain / CC-BY). |
| **Baboon Texture** | $512\times 512$, RGB | `[TODO_USER: source/licence]` | Provide official archival source (USC-SIPI Image Database 4.2.03) and licence. |
| **Peppers Color** | $512\times 512$, RGB | `[TODO_USER: source/licence]` | Provide official archival source (USC-SIPI Image Database 4.2.07) and licence. |
| **Medical MRI** | $512\times 512$, RGB (from grayscale) | `[TODO_USER: source/licence]` | Provide clinical or research scan repository provenance and licence (e.g., Cancer Imaging Archive / OpenNeuro). |
| **Satellite Aerial** | $1024\times 1024$, RGB | `[TODO_USER: source/licence]` | Provide satellite/geographic repository provenance (e.g., USGS EarthExplorer / NAIP) and licence. |
| **Submarine** | $1199\times 460$, RGB (padded $1200\times 464$) | `[TODO_USER: source/licence]` | Provide official photographic repository source and licence. |

---

## 3. Code and Data Availability Statement (Section 6)

| Field | Current Placeholder | Action Required from User |
|---|---|---|
| **Repository URL** | `https://github.com/TODO_USER/SecureImageTransmission` | Replace `TODO_USER` with the official organizational or institutional GitHub/GitLab repository path. |
| **Software Licence** | Documented in README as MIT / Apache 2.0 | Confirm software licence under which the research artifacts will be released. |
| **Dataset Manifest** | `data/dataset_manifest.json` | Confirm all dataset links and checksums in `data/dataset_manifest.json`. |

---

## 4. Hardware Evaluation Scope (Section 4.1 & Section 4.5)

- **Single Host Current Scope:** All throughput and latency benchmarks were collected on the primary development host (`13th Gen Intel Core i5-13420H`, 12 logical threads, Windows 11).
- **Optional Embedded / Multi-Device Benchmarking:** The repository includes `scripts/benchmark_portable.py`, designed to execute across heterogenous platforms (e.g., Raspberry Pi 4/5, Jetson Nano, Ubuntu Linux). If the authors wish to include a second physical hardware platform in Table 5, execute `python scripts/benchmark_portable.py` on the target device, commit the resulting `results/bench_<hostname>.json`, and regenerate tables.

---

## 5. Procedia Computer Science Page Limit & Layout Verification

- **Target Page Limit:** Typical Elsevier Procedia Computer Science conference articles require strict adherence to an 8-page or 10-page limit.
- **Verification Step:** Because `pdflatex` is not pre-installed in the local execution sandbox, the authors should compile `paper_icmlde/sw.tex` on their local LaTeX distribution or Overleaf:
  ```bash
  pdflatex sw.tex
  bibtex sw
  pdflatex sw.tex
  pdflatex sw.tex
  ```
- If the rendered article exceeds the target conference page limit, secondary benchmark tables (e.g., fraction-matched Table 8 or detailed hardware profiles) can be moved into a supplementary appendix repository.

---

## 6. Bibliographic Reference Verification Status ([VERIFY] Items)

All standard cryptographic and inpainting references cited in the manuscript have been cross-verified against official standards bodies, RFC registries, and publisher databases:

| Reference Key | Citation / Standard | Verification Source | Status |
|---|---|---|---|
| `turpy2010sp800132` | NIST SP 800-132 (2010) | NIST CSRC repository (Authors: Meltem Sönmez Turan, Elaine Barker, William Burr, Lily Chen) | **VERIFIED** |
| `langley2016rfc7748` | IETF RFC 7748 (Curve25519/X25519, 2016) | IETF RFC Editor (Authors: Adam Langley, Mike Hamburg, Sean Turner) | **VERIFIED** |
| `josefsson2017rfc8032` | IETF RFC 8032 (Ed25519/EdDSA, 2017) | IETF RFC Editor (Authors: Simon Josefsson, Ilari Liusvaara) | **VERIFIED** |
| `moriarty2017rfc8018` | IETF RFC 8018 (PKCS #5 v2.1 / PBKDF2, 2017) | IETF RFC Editor (Authors: Kathleen Moriarty, Burt Kaliski, Andreas Rusch) | **VERIFIED** |
| `owasp_pbkdf2` | OWASP PBKDF2 Iteration Recommendation | OWASP Password Storage Cheat Sheet recommends 600,000 iterations for PBKDF2-HMAC-SHA256 | **VERIFIED** |
| `hoang2015stream` | Hoang et al. (CRYPTO 2015) | Springer LNCS vol. 9216, pp. 493–517 | **VERIFIED** |
| `preishuber2018depreciating` | Preishuber et al. (2018) | IEEE Trans. Inf. Forensics Security, 13(9), pp. 2137–2150 | **VERIFIED** |
| `telea2004inpainting` | Telea Fast Marching (2004) | *Journal of Graphics Tools*, 9(1), pp. 23–34 | **VERIFIED** |
| `bertalmio2001navierstokes` | Navier-Stokes Inpainting (2001) | *Proc. IEEE CVPR 2001*, pp. I-355–I-362 (Authors: Bertalmio, Bertozzi, Sapiro) | **VERIFIED** |

---

## 7. Corresponding Author Metadata Confirmation

- **Primary Institutional Email:** `radhukr@am.amrita.edu` has been confirmed and unified across `paper_icmlde/sw.tex`, `README.md`, and `CITATION.cff`.
- **Author Affiliation:** Radhu Krishna R. (corresponding author), School of Computing, Amrita Vishwa Vidyapeetham, Amritapuri, Kollam, Kerala, India.

---

## 8. Software License Choice Pending (Author Decision Required)

- **License Options:** Outlined in `LICENSE_TODO.md` (MIT, Apache 2.0, BSD 3-Clause).
- **Action Required:** Authors must select the preferred open-source license, replace `LICENSE_TODO.md` with `LICENSE`, and update the `license:` field in `CITATION.cff`.


