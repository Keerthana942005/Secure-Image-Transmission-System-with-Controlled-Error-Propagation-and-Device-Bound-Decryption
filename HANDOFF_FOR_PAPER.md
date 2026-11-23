# Hand-off Document for Paper Revision (ICMLDE Procedia Computer Science)

This document provides the exhaustive technical specification, empirical macro catalog, known discrepancies, and receiver policies for revising the manuscript `paper_icmlde/sw.tex`. 

> **Important Boundary Rule**: Under the separation-of-concerns protocol, no paper prose in `paper_icmlde/sw.tex` was modified directly during the project phase. All updated empirical quantities are exported via LaTeX macros in `paper_icmlde/results_macros.tex` and structured tables in `paper_icmlde/tables/`.

---

## 1. Complete Catalog of Results Macros (`results_macros.tex`)

The following macros are auto-generated from empirical benchmark results using `python scripts/make_tables.py` and are synchronized to both `tables/results_macros.tex` and `paper_icmlde/results_macros.tex`.

| Macro Name | Value | Description / Source |
|---|---|---|
| `\headerBytes` | `134~bytes` | Authenticated session header size |
| `\headerBytesRaw` | `134` | Raw integer session header size |
| `\recordBytes` | `800~bytes` | Authenticated block record size ($4 + 12 + 768 + 16$) |
| `\recordBytesRaw` | `800` | Raw integer block record size |
| `\pbkdfIterations` | `600,000` | PBKDF2-HMAC-SHA256 iteration count |
| `\pbkdfTime` | `67.67~ms` | Mean PBKDF2 key derivation latency |
| `\handshakeTime` | `68.08~ms` | Mean X25519 + HMAC-SHA256 handshake latency |
| `\benchmarkCPU` | `13th Gen Intel(R) Core(TM) i5-13420H` | CPU model of test host |
| `\benchmarkThreads` | `12` | Total logical execution threads |
| `\benchmarkOS` | `Windows-11-10.0.26200-SP0` | Host operating system |
| `\cipherEntropyMin` | `7.9991` | Minimum ciphertext entropy across 6 benchmark images |
| `\cipherEntropyMax` | `7.9999` | Maximum ciphertext entropy across 6 benchmark images |
| `\npcrMin` | `99.60\%` | Minimum block NPCR under fresh nonces across 6 images |
| `\npcrMax` | `99.62\%` | Maximum block NPCR under fresh nonces across 6 images |
| `\uaciMin` | `33.48\%` | Minimum block UACI under fresh nonces across 6 images |
| `\uaciMax` | `33.51\%` | Maximum block UACI under fresh nonces across 6 images |
| `\maxCorrelation` | `0.0304` | Maximum absolute adjacent-pixel correlation across H/V/D directions |
| `\chiSquareCritical` | `293.25` | Critical value $\chi^2_{0.05, 255}$ |
| `\encTimeSixteen` | `3.68~ms` | Encryption time for proposed $16\times 16$ block AES-GCM (Submarine) |
| `\decTimeSixteen` | `3.23~ms` | Decryption time for proposed $16\times 16$ block AES-GCM (Submarine) |
| `\throughputSixteen` | `450.0~MB/s` | Pure cryptographic throughput ($16\times 16$ block AES-GCM) in decimal MB/s |
| `\throughputEndToEnd` | `267.9~MB/s` | End-to-end throughput including image padding, framing, split, merge |
| `\overheadBytesSixteen` | `85,380~bytes` | Total byte overhead for Submarine ($16\times 16$ framing + padding) |
| `\overheadPercentSixteen`| `5.16\%` | Total percentage overhead relative to unpadded Submarine image |
| `\analyticalOverheadPercent`| `4.17\%` | Analytical record overhead: $32 / 768 = 4.1667\%$ |
| `\loadCryptoSevenTwenty` | `40.0\%` | Streaming CPU load for 720p60 under pure crypto throughput ($165.9 / 414.8$) |
| `\loadEtoESevenTwenty` | `119.6\%` | Streaming CPU load for 720p60 under end-to-end throughput ($165.9 / 138.7$) |
| `\loadCryptoTenEighty` | `45.0\%` | Streaming CPU load for 1080p30 under pure crypto throughput ($186.6 / 414.8$) |
| `\loadEtoETenEighty` | `134.5\%` | Streaming CPU load for 1080p30 under end-to-end throughput ($186.6 / 138.7$) |
| `\monoEncTime` | `0.59~ms` | Encryption time for monolithic AES-256-GCM baseline |
| `\monoDecTime` | `0.66~ms` | Decryption time for monolithic AES-256-GCM baseline |
| `\monoThroughput` | `2783.0~MB/s` | Throughput of monolithic AES-256-GCM |
| `\psnrGainMin` | `10.78~dB` | Minimum mean PSNR concealment gain for Submarine ($K=10..200$) |
| `\psnrGainMax` | `11.55~dB` | Maximum mean PSNR concealment gain for Submarine ($K=10..200$) |
| `\psnrGainSixImageMin` | `5.83~dB` | Minimum mean PSNR concealment gain across all 6 benchmark images |
| `\psnrGainSixImageMax` | `21.80~dB` | Maximum mean PSNR concealment gain across all 6 benchmark images |
| `\eprValue` | `1.00` | Strictly bounded Error Propagation Radius ($\text{EPR} = 1.00$) |
| `\figTwoRawPSNR` | `30.62~dB` | Figure 2 Submarine raw PSNR at $K=25$, Seed 42 |
| `\figTwoConcPSNR` | `44.38~dB` | Figure 2 Submarine concealed PSNR at $K=25$, Seed 42 |
| `\figTwoCBCPSNR` | `11.03~dB` | Figure 2 Submarine unframed CBC PSNR at $K=25$, Seed 42 |
| `\figTwoGain` | `+13.76~dB` | Figure 2 Concealment gain at $K=25$, Seed 42 ($44.38 - 30.62$) |
| `\figTwoTrialId` | `submarine\_K25\_trial0` | Exact trial ID from `results/containment_submarine.json` |
| `\figTwoSeed` | `42` | Pinned random seed for Figure 2 |
| `\securityVectorsTested` | `18` | Total distinct attack vectors in security test suite |
| `\securityTrialsPerVector`| `100` | Trials per attack vector |
| `\securityTotalTrials` | `1,800` | Total empirical attack trials conducted |
| `\securityDetectionRate` | `100.0\%` | Detection & containment rate ($1800/1800$) |
| `\mlDatasetImages` | `500` | Authentic ImageNet validation subset images evaluated |
| `\mlTrialsPerLevel` | `10` | Monte Carlo trials evaluated per corruption level per image |
| `\mlLevelsCount` | `5` | Total corruption levels evaluated ($K \in \{1, 2, 5, 9, 18\}$) |
| `\mlEvalPerLevelPerScheme` | `5,000` | Evaluations per scheme per level ($n = 500 \times 10$) |
| `\mlTotalInferences` | `100,500` | Total deep model inferences ($500 \text{ clean} + 5 \times 4 \times 5,000$) |
| `\mlKOnePct` | `0.51\%` | Exact block loss percentage for $K=1/196$ |
| `\mlKTwoPct` | `1.02\%` | Exact block loss percentage for $K=2/196$ |
| `\mlKFivePct` | `2.55\%` | Exact block loss percentage for $K=5/196$ |
| `\mlKNinePct` | `4.59\%` | Exact block loss percentage for $K=9/196$ |
| `\mlKEighteenPct` | `9.18\%` | Exact block loss percentage for $K=18/196$ |
| `\mlAgreementKOne` | `97.1\%` | MobileNetV2 top-1 agreement at $K=1$ (0.51% packet loss) |
| `\mlAgreementKEighteen` | `83.8\%` | MobileNetV2 top-1 agreement at $K=18$ (9.18% packet loss) |
| `\mlZeroKEighteen` | `41.6\%` | MobileNetV2 top-1 agreement for Zero-Fill at $K=18$ |
| `\mlCbcKEighteen` | `23.5\%` | MobileNetV2 top-1 agreement for Unframed CBC under packet loss at $K=18$ |
| `\mlGainKEighteen` | `+42.1\%` | Net percentage-point gain of proposed concealment over zero-fill at $K=18$ |

---

## 2. Exhaustive Audit & Discrepancies to Reconcile in Paper Prose

During the project audit (`AUDIT.md`), the following issues were identified between the old draft prose and the empirical facts. Reviewers should verify that the paper text is updated accordingly:

### Discrepancy 1: Submarine Dimensions and Block Counts (Audit K2, K3)
- **Old Draft Claim**: Table 3 caption stated *"Submarine Benchmark, 768x512, 1,536 Total Blocks"*; Table 4 caption stated *"1024 x 512 Test Image"*.
- **Empirical Reality**: The authentic Submarine image (`data/benchmark/submarine.png`) is **$1199 \times 460$** pixels, 3 channels RGB (raw size 1,654,620 bytes). When padded to multiples of 16 ($1200 \times 464$), it segments into **$75 \times 29 = 2,175$** blocks.
- **Action for Paper**: Update Table 3 caption and Section 4 text to state: *"Submarine Benchmark ($1199\times 460$ padded to $1200\times 464$, 2,175 total $16\times 16$ blocks)"*. In Table 4, state *"Submarine Benchmark ($1199\times 460$)"* with block counts 2,175 ($16\times 16$), 8,700 ($8\times 8$), 570 ($32\times 32$), and 152 ($64\times 64$).

### Discrepancy 2: Figure 2 Caption vs Table 3 Multi-Trial Means (Audit K4, K5)
- **Old Draft Problem**: Old Figure 2 caption listed raw 27.08 dB, concealed 38.35 dB, CBC 9.28 dB; Table 3 listed raw 29.90 dB, concealed 41.44 dB, CBC 11.54 dB. The CBC value in Fig 2 was equal to Table 3's $K=200$ value.
- **Root Cause**: Figure 2 is a single visual sample trial, whereas Table 3 reports 30-trial Monte Carlo means.
- **Resolved Empirical Values**:
  - Figure 2 trial is pinned to **`trial_id: submarine_K25_trial0` (Seed 42, $K=25$)**:
    - Raw corrupted PSNR: **30.62 dB** (`\figTwoRawPSNR`)
    - Proposed concealed PSNR: **44.38 dB** (`\figTwoConcPSNR`)
    - Concealment gain: **+13.76 dB** (`\figTwoGain`)
    - Unframed CBC PSNR: **11.03 dB** (`\figTwoCBCPSNR`)
  - Table 3 reports the 30-trial mean at $K=25$:
    - Raw corrupted PSNR: **29.90 dB**
    - Concealed PSNR: **41.44 dB**
    - Concealment gain: **+11.55 dB**
    - Unframed CBC PSNR: **11.03 dB** (Unframed CBC desynchronizes from the first corrupted byte onward, yielding ~11 dB across trials).

### Discrepancy 3: CPU Utilization Formula & Throughput Units (Audit K7, K8)
- **Old Draft Problem**: CPU utilization was reported as 73.7% for 720p60 and 76.4% for 1080p30 without a documented formula, and throughput was ambiguously labeled "MB/s" while mixing binary MiB/s and decimal MB/s.
- **Standardized Formula**: All streaming rates and throughputs are strictly defined in decimal megabytes per second ($1\text{ MB/s} = 10^6\text{ bytes/s}$):
  $$\text{Required Data Rate } R = H \times W \times 3 \times \text{FPS} \times 10^{-6} \text{ MB/s}$$
  $$\text{CPU Utilization } U = \frac{R}{T_{\text{crypto}}} \times 100\%$$
- **Benchmark Measurements** (on 13th Gen Intel Core i5-13420H, $T_{\text{crypto}} = 414.8\text{ MB/s}$):
  - 720p60 ($1280\times 720\times 3\times 60$): $R = 165.89\text{ MB/s} \implies U = 165.89 / 414.8 = \mathbf{40.0\%}$.
  - 1080p30 ($1920\times 1080\times 3\times 30$): $R = 186.62\text{ MB/s} \implies U = 186.62 / 414.8 = \mathbf{45.0\%}$.
  - 1080p60 ($1920\times 1080\times 3\times 60$): $R = 373.25\text{ MB/s} \implies U = 373.25 / 414.8 = \mathbf{90.0\%}$.
  - 4K60 ($3840\times 2160\times 3\times 60$): $R = 1492.99\text{ MB/s} \implies U = 359.9\%$ (requires multi-threaded or GPU pipeline).

### Discrepancy 4: Downstream ML Evaluation Scope (Audit K9 & Fix F4)
- **Old Draft Claim**: "100 images, 10 trials per level, 2,000 inferences" (inconsistent math: $100 \times 10 \times 5 = 5,000$ per scheme).
- **Overhauled Scope & Exact Count Product**:
  - Image dataset: **500 authentic ImageNet validation images** (`data/imagenet_subset.txt` with verified SHA-256 digests).
  - 5 corruption levels evaluated on $224\times 224$ images ($14\times 14 = 196$ total $16\times 16$ blocks):
    - $K=1$ ($1/196 = \mathbf{0.51\%}$)
    - $K=2$ ($2/196 = \mathbf{1.02\%}$)
    - $K=5$ ($5/196 = \mathbf{2.55\%}$)
    - $K=9$ ($9/196 = \mathbf{4.59\%}$)
    - $K=18$ ($18/196 = \mathbf{9.18\%}$)
  - Monte Carlo sampling: 10 trials per level per image $\implies \mathbf{n = 5,000}$ evaluations per scheme per level ($500 \times 10 = 5,000$). Total evaluations across 5 levels = $25,000$.
  - 4 distinct deep neural network forward-pass inference schemes evaluated:
    1. Proposed Scheme (Concealed, S1 Record Loss)
    2. Proposed Scheme (Zero-Fill) / Framed CBC (S1 Record Loss, identical zero-fill tensor)
    3. Unframed CBC (S1 Record Loss, desynchronization tail)
    4. Unframed CBC (S2 Bit-Flips, two-block error propagation)
    *(Note: Monolithic GCM has 0% availability for $K \ge 1$ and aborts with empty output without running neural network inference; S2 Proposed Zero-Fill quarantined blocks produce the identical zero-filled tensor as S1).*
  - Baseline forward passes: **500 clean inferences** (1 per image on uncorrupted baseline).
  - **Exact Product**:
    $$\text{Total Inferences} = 500_{\text{clean}} + (500_{\text{images}} \times 10_{\text{trials}} \times 5_{\text{levels}} \times 4_{\text{schemes}}) = 500 + 100,000 = \mathbf{100,500\text{ inferences}}$$
  - Tested under two realistic channel failure models:
    - **Scenario 1 (S1 - Record Loss / Packet Drop)**: Truncated or lost UDP records. Unframed CBC desynchronizes and agreement plummets to 23.54% (95% CI: [22.36%, 24.72%]); Monolithic GCM gives 0%; Proposed Zero-Fill gives 41.64% (95% CI: [40.26%, 43.02%]); Framed CBC gives 41.64%; Proposed Concealed retains **83.78%** (95% CI: [82.74%, 84.82%]) yielding a net concealment gain of **+42.14 pp**.
    - **Scenario 2 (S2 - In-Place Bit Flips)**: Physical bit errors without payload length loss. Unframed CBC retains 91.20% (95% CI: [90.42%, 91.98%]) because bit flips propagate only across 2 AES blocks, but it provides **zero cryptographic detection or authentication**. In contrast, Proposed Scheme provides **100.0% cryptographic authentication** across all blocks, quarantines tampered blocks, and reconstructs them to achieve **83.78%** classification agreement with guaranteed tamper containment. Notice that under S2, Proposed Zero-Fill and Framed CBC yield identical results (41.64%) because quarantined blocks in both are zero-filled.

### Discrepancy 5: Error Propagation Radius at K=0 (Audit K10)
- **Old Draft Problem**: Table 3 listed $\text{EPR} = 1.00$ at $K=0$.
- **Mathematical Reality**: When $K=0$, $B_{\text{corrupted}} = 0$ and $B_{\text{failed}} = 0$. The ratio $0/0$ is mathematically undefined.
- **Resolution in Table 3**: Formatted as a dash (`---`) or explicitly marked undefined when $K=0$. For all $K \ge 1$, $\text{EPR} = 1.000$ strictly.

### Discrepancy 6: Adjacent-Pixel Correlation Reporting (Audit K11)
- **Old Draft Problem**: Text claimed plain correlation was $>+0.95$ but no plain correlation was tabulated; text said $|r| < 0.0310$ while the table had an unescaped negative value of $-0.0310$.
- **Empirical Tabulation in Table 2**: Both Plain and Cipher correlations are now explicitly tabulated for Horizontal ($r_H$), Vertical ($r_V$), and Diagonal ($r_D$) directions across all 6 benchmark images. Plain correlations range from $+0.9252$ to $+0.9856$; Cipher correlations all satisfy $|r| \le \mathbf{0.0304}$ (`\maxCorrelation`).

### Discrepancy 7: Literature Comparison Values (Audit K12)
- **Old Draft Problem**: Literature rows (Chai et al., Hua et al., Zhou et al.) listed near-ideal values with unsupported "Cascading Diffusion" labels.
- **Resolution in Table 1**: Literature values are labeled with citations and note test images used (e.g. Lena $512\times 512$). Where experimental conditions cannot be verified, values are marked with footnotes or marked `TODO_USER` in `data/literature_table.csv`.

### Discrepancy 8: Security Claims & Forward Secrecy (Audit K15b)
- **Prohibited Claim**: The project does NOT provide forward secrecy. PBKDF2 derives key material from a long-term passphrase; compromise of the passphrase and receiver static private key compromises past recorded sessions.
- **Paper Framing**: Section 3 and Section 5 should frame the security guarantees as *defense-in-depth ephemeral-static key agreement (X25519) + PBKDF2-HMAC-SHA256 (600,000 iterations) + HKDF-SHA256 device-and-epoch binding with revocation checking (DRL)*. Do NOT use the term "forward secrecy".

---

## 3. Cryptographic Formats & Protocol Specifications

### 3.1 134-Byte Session Header Layout
Every transmission session begins with a single 134-byte fixed-format header authenticated via HMAC-SHA256.

```
+---------------+---------------+--------------------+--------------------+---------------+---------------+---------------+
| Magic (4B)    | Version (2B)  | S_pbkdf2 (16B)     | S_hkdf (16B)       | Ephem Pub(32B)| Epoch (4B)    | H (2B)        |
| 'SITH' (BE)   | 0x0001        | Random Salt        | Random Salt        | X25519 PubKey | uint32 BE     | uint16 BE     |
+---------------+---------------+--------------------+--------------------+---------------+---------------+---------------+
 0               4               6                    22                   38              70              74              76

+---------------+---------------+--------------------+--------------------------------+
| W (2B)        | N (4B)        | Reserved (20B)     | Header HMAC-SHA256 (32B)       |
| uint16 BE     | uint32 BE     | 0x00 padding       | HMAC over bytes 0..101         |
+---------------+---------------+--------------------+--------------------------------+
 76              78              82                   102                              134
```

- **Receiver static public key**: Receiver possesses a static X25519 keypair. The sender uses this key to compute the ephemeral shared secret. The receiver's Device ID digest is bound via HKDF info but **never transmitted over the wire**.
- **HMAC Authentication**: Bytes 0..101 are authenticated using $K_{\text{hdr}} = \text{HKDF-Expand}(PRK, \text{"SIT-v1-hdr"}, 32)$.

### 3.2 800-Byte Block Record Layout
Each $16\times 16\times 3$ RGB block (768 plaintext bytes) is encrypted and framed into an 800-byte record:
```
+--------------------+--------------------+------------------------------------+--------------------+
| Block Index (4B)   | IV / Nonce (12B)   | Ciphertext (768B)                  | GHASH Tag (16B)    |
| uint32 BE          | 96-bit random/det  | AES-256-GCM encrypted block       | AEAD Tag           |
+--------------------+--------------------+------------------------------------+--------------------+
 0                    4                    16                                   784                  800
```

### 3.3 20-Byte Additional Authenticated Data (AAD)
To prevent cross-block splicing, cross-session replay, and dimensional tampering, each block's GHASH tag covers a 20-byte AAD:
$$\text{AAD} = \text{uint32}(\text{index}) \parallel \text{uint16}(H) \parallel \text{uint16}(W) \parallel \text{uint32}(N) \parallel \text{uint32}(\text{epoch}) \parallel \text{uint32}(0)$$

### 3.4 Standardized Receiver Policy & Actions
The receiver inspects each incoming record and executes a deterministic policy returning one of five exact action labels:
1. `detected_and_quarantined`: Block record arrived but authentication failed (corrupted IV, bit flips in ciphertext, or forged tag). Block is quarantined and passed to concealment.
2. `concealed`: Record was lost, truncated, or quarantined, and successfully reconstructed via boundary interpolation.
3. `duplicate_ignored`: An identical or duplicate block index was previously received; secondary duplicate is safely dropped.
4. `rejected_over_threshold`: Corrupted/missing block fraction exceeds policy threshold $\tau$ (e.g. $\tau = 0.50$); transmission aborted.
5. `session_rejected`: Session header HMAC mismatch, corrupted magic, version mismatch, or receiver public key revoked in DRL; entire session aborted before processing blocks.

---

## 4. Verification Check Before Submission
Run the automated test suite and linter before building the final paper PDF:
```bash
# 1. Run all unit tests (63 tests)
python -m unittest discover tests

# 2. Run LaTeX linter
python scripts/lint_latex.py
```
Both commands must complete with exit code 0.

