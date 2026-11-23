# Detailed Point-by-Point Response to Reviewers

**Manuscript Title:** Secure Image Transmission System with Controlled Error Propagation, Device-Bound Decryption, and Downstream Machine Learning Resilience  
**Authors:** Keerthana Nellyeri, Swetha Rajesh, Radhu Krishna R.  
**Target Venue:** Procedia Computer Science (Elsevier) -- International Conference on Machine Learning and Data Engineering (ICMLDE)  

---

Dear Editors and Reviewers,

We express our sincere gratitude to the reviewers for their constructive, thorough, and highly insightful critiques. Addressing these comments has significantly strengthened the scientific rigor, cryptographic integrity, empirical scope, and clarity of our manuscript. 

Below, we provide a detailed, point-by-point response explaining how each comment has been addressed in both the updated codebase and the revised manuscript. All numerical values reported in the revised paper originate directly from reproducible benchmark runs on our code and dataset (using pinned seed $S = 42$), orchestrated via our single-source-of-truth macro generation pipeline (`paper_icmlde/results_macros.tex`).

### Plain Summary of Weakened or Clarified Claims
In direct response to reviewer feedback and our rigorous internal pre-flight audit, we have explicitly weakened, scoped, or clarified several claims where earlier drafts over-reached:
1. **No Forward Secrecy Claim:** We explicitly state in Section 1 (Contribution 2), Section 3.3, and Section 5 (Limitations) that no forward secrecy claim is made; compromise of the receiver static X25519 private key and the shared passphrase would allow an attacker to decrypt previously recorded communication sessions.
2. **CBC Error Recovery Reality:** We removed claims of whole-frame "catastrophic error cascades" for standard CBC. We clarify in Section 1, Section 2.1, and Section 4.3 that an isolated in-place bit-flip in CBC self-recovers after exactly two 16-byte AES blocks (32 bytes). Stream desynchronization only occurs under packet or byte loss when transport sequence framing is absent.
3. **Hardware Scope:** We strictly scoped all hardware throughput and latency benchmarks to a single physical testbed host (`13th Gen Intel Core i5-13420H`, 12 logical threads), removing any extrapolated multi-hardware claims.
4. **End-to-End Real-Time Video Streaming Limits:** We explicitly differentiate Pure Cryptographic Throughput (569.2 MB/s, 15-run median) from End-to-End Processing Throughput (191.9 MB/s, 15-run median) in Table 4, Table 5, and Section 4.5. Following our 3-tier classification rule (<90% supported, 90-110% at the limit of this host, >110% not supported): 720p 60fps is supported on this host (29.1% crypto / 86.5% E2E load); 1080p 30fps is supported under pure crypto (32.8% load) and operates at the limit of this host end-to-end (97.2% load); higher resolutions (1080p 60fps at 194.5% E2E, 4K 60fps at 778.0% E2E) are not supported on this single-threaded pipeline and require multi-threading or hardware acceleration.
5. **Bit-Flip Downstream ML Accuracy vs. Authentication:** Under Scenario 2 (in-place bit flips), unauthenticated CBC achieves higher classification agreement (91.2%) than quarantine because an isolated bit flip corrupts only 32 bytes of the $16\times 16$ block, whereas quarantine discards the whole block. We openly concede this accuracy difference in Section 4.7 (within 7.4 percentage points) and clarify that the proposed scheme's core advantage under bit flips is cryptographic authentication and 100% tamper detection: CBC passes corrupted or adversarial bytes silently into the classifier, whereas our scheme prevents untrusted feature injection.

---

# Reviewer 1

### Comment 1.1: Single Test Image Limitation in Abstract
> *"The abstract clearly characterizes the system but needs to mention explicitly that the evaluation is performed on a single test image."*

**Author Response:**  
We agree completely. In our initial exploratory experiments, preliminary characterization was performed on a single image. In response to this critique, we have broadened our experimental evaluation across a diverse benchmark suite of **six benchmark images** spanning diverse spatial resolutions ($256\times 256$, $512\times 512$, $1024\times 1024$, and $1199\times 460$) and visual content domains (photographic, high-frequency texture, smooth chromatic gradients, clinical medical MRI scans, and aerial satellite terrain).

**Exact Changes in Manuscript & Code:**
- **Abstract (lines 53--55):** Evaluated across six benchmark images ($256\times 256$ to $1024\times 1024$), reporting entropy (7.9991--7.9999 bits), bounded error containment ($\text{EPR} = 1.00$), and fraction-matched concealment gains (10.78--26.64 dB).
- **Section 4.1 & Table 1:** Full empirical evaluation across Cameraman, Baboon, Peppers, Medical MRI, Satellite Aerial, and Submarine datasets.

---

### Comment 1.2: Novelty Beyond Per-Block AES-GCM
> *"Block-level AES-GCM, controlled error propagation, and device-bound key derivation can be considered as an engineering contribution. What makes the contribution novel apart from the application of AES-GCM per block?"*

**Author Response:**  
We appreciate this important question. Naively encrypting individual image blocks under AES-GCM introduces severe architectural vulnerabilities:
- Deleting or losing a single packet desynchronizes implicit indices, causing all subsequent authentications to fail.
- Adversaries can swap, duplicate, or splice blocks across spatial locations or transmission sessions without detection.
- MAC-based device binding in software is trivially spoofed.
- Corrupted blocks simply produce decryption errors without any path to recovery for downstream analytics.

Our core scientific and engineering contribution lies in the **systemic cross-layer co-design** that resolves the conflict between cryptographic authentication and channel fault tolerance:
1. **Explicit 800-Byte Record Framing & 20-Byte AAD:** We designed an explicit 4-byte big-endian header index combined with a 20-byte multi-attribute AAD ($\text{Index} \parallel \text{Height} \parallel \text{Width} \parallel \text{Total Blocks} \parallel \text{Epoch}$). This prevents block swapping, splicing, truncation, and dimension tampering without increasing per-record wire overhead.
2. **Defense-in-Depth Key Derivation:** We combine ephemeral-static X25519 agreement, PBKDF2-HMAC-SHA256 passphrase stretching (600,000 rounds per RFC 8018 and OWASP guidance) into secret IKM, and context expansion via HKDF-SHA256 (RFC 5869), providing computational security even if an adversary spoofs the MAC address.
3. **Cryptographic Quarantine Paradigm:** Instead of the catastrophic all-or-nothing discard of monolithic AEAD, our scheme quarantines corrupted blocks strictly at the boundary ($\text{EPR} = 1.00$).
4. **Tag-Directed Spatial Concealment:** The decoder uses fine-grained tag failure coordinates to direct spatial boundary interpolation, recovering $+10.78$ to $+11.55$~dB PSNR on Submarine (and up to $+26.64$~dB across benchmark images) without retransmission.
5. **Downstream ML Resilience:** We demonstrate that our scheme maintains 83.8\% classification agreement in deep neural networks (MobileNetV2 on 500 ImageNet validation images) under 9.18\% block corruption, where monolithic AEAD completely halts inference (0\% availability) and unframed CBC drops to 23.5\%.

**Exact Changes in Manuscript:**
- **Section 1 (Introduction, lines 81--90):** Explicitly itemized the six core contributions.
- **Section 2.2:** Added an explicit novelty formulation sentence.
- **Section 5 (Discussion):** Elaborated the cross-layer co-design rationale.

---

### Comment 1.3: Nonce and Key Handling Leakage Analysis
> *"The analysis must consider potential leakages related to nonce and key handling."*

**Author Response:**  
We have added a dedicated formal security and leakage analysis in **Section 3.4**, analyzing:
1. **Nonce Collision Probability:** For $N = 4096$ blocks, random 96-bit nonces have a collision probability of $P_{\text{coll}} \le \frac{N^2}{2 \cdot 2^{96}} \approx 1.06 \times 10^{-22}$ per session. Across $10^9$ sessions, the union-bound collision probability is approximately $1.1 \times 10^{-13}$, which is cryptographically negligible.
2. **Counter Rollover:** Each $16\times 16\times 3$ block requires only 48 counter invocations, mathematically bounded far below the $2^{32}-2$ limit. Furthermore, per NIST SP 800-38D, a single 256-bit key securely handles $> 1.9 \times 10^6$ full images before rekeying. An explicit invocation counter guard enforces rekeying prior to reaching $2^{32}$ invocations.
3. **MAC Entropy and Offline Dictionary Attacks:** We acknowledge that MAC addresses have low effective entropy ($\sim 24$ bits) and can be spoofed in software. In our scheme, MAC is never transmitted over the wire and is never used as a standalone key; it is only a supplementary physical context parameter in HKDF, while secret entropy is supplied by X25519 agreement and a PBKDF2-stretched secret passphrase (600,000 iterations).
4. **Side-Channel Timing Protections:** Authentication verification utilizes constant-time comparison (`hmac.compare_digest`) to eliminate timing side-channel leakage.
5. **Memory Hygiene:** Key buffers in RAM are purged using best-effort zeroization immediately after cryptographic operations.

**Exact Changes in Manuscript:**
- **Section 3.4: Nonce and Key Handling Leakage Analysis** (lines 194--208).

---

### Comment 1.4: Comparison to Chaotic and Selective Encryption Schemes
> *"It is necessary to compare the proposed scheme to other selective or chaotic image encryption algorithms using standard metrics like NPCR, UACI, and entropy."*

**Author Response:**  
We evaluated standard image cryptographic security metrics across all six benchmark images and incorporated a direct comparative analysis against prominent literature schemes: Chai et al. (2019) [memristive hyperchaos], Hua et al. (2015) [2D Logistic-Adjusted-Sine Map], Zhou et al. (2014) [1D chaotic map], and standard AES-CBC.

The results show that while chaotic schemes achieve comparable Shannon entropy ($\sim 7.999$) and NPCR ($\sim 99.61\%$), they offer **no ciphertext integrity verification (no authentication tags)** and provide no mechanism to detect tampering or localize channel errors. In contrast, our proposed block AES-256-GCM scheme provides standardized 128-bit GHASH authentication tags per block and strictly bounded error containment ($\text{EPR} = 1.00$).

**Exact Changes in Manuscript:**
- **Table 2 (`tab:chaotic_comparison`)** and **Section 2.1 & Section 4.3**: Comparing Cipher Entropy, NPCR (\%), UACI (\%), Cryptographic Primitive, Integrity Tag, and Containment (EPR).
- Genuine verified citations: Chai et al. (2019), Hua et al. (2015), Zhou et al. (2014), and Preishuber et al. (IEEE TIFS 2018 survey).

---

### Comment 1.5: Overhead Specification in Conclusion
> *"The conclusion must specify the overhead in file size and processing time caused by per-block tags."*

**Author Response:**  
We have updated the conclusion (and Section 4.4 / Section 4.5) to explicitly specify both the analytical and empirical overheads in file size and processing time:
- **File Size / Storage Overhead:** Exactly 32 bytes per 768-byte block (4-byte index + 12-byte IV + 16-byte GHASH tag), representing an analytical framing overhead of **4.17%** (and **5.16%** total payload expansion including edge padding on the Submarine benchmark image).
- **Processing Time Overhead:** Encryption latency is **2.91 ms** (throughput of **569.2 MB/s** pure crypto and **191.9 MB/s** end-to-end, 15-run medians) for block-level encryption compared to 0.84 ms (1964.7 MB/s) for monolithic encryption on our 12-thread host processor.

**Exact Changes in Manuscript:**
- **Section 6 (Conclusion):** Explicitly states: *"On standard hardware, the scheme incurs an exact 4.17% analytical framing overhead (5.16% total) and executes in 2.91 ms encryption and 2.84 ms decryption (569.2 MB/s pure crypto and 191.9 MB/s end-to-end throughput) compared to 0.84 ms for monolithic GCM, providing an effective foundation for secure visual data pipelines."*

---

# Reviewer 2

### Comment 2.1: Inappropriate Claim that EPR = 1.0 "Proves" Strong Containment
> *"It is inappropriate to say that EPR equals 1.0 and therefore “proves” strong containment."*

**Author Response:**  
We completely concede this point. An empirical observation of $\text{EPR} = 1.00$ does not constitute a mathematical proof of security. We have thoroughly revised the text across the manuscript to remove any claim that EPR "proves" containment. Instead, we clarify that $\text{EPR} = 1.00$ is an **algebraic property of CTR-mode keystream independence under per-block AEAD quarantine**: because keystreams are computed independently for each block, an error in block $i$ cannot mathematically corrupt block $i+1$.

**Exact Changes in Manuscript:**
- **Section 3.5:** Stated: *"$\text{EPR} = 1.00$ is an algebraic consequence of CTR-mode keystream and tag independence under per-block AEAD, not a formal security proof. It holds for in-place corruption and for record loss when records carry an explicit index header; it does not hold if transport framing is lost. Because EPR measures containment only rather than detection, we also report detection precision and recall."*

---

### Comment 2.2: MAC-Based Device Binding Vulnerability to Spoofing
> *"MAC-based device binding is vulnerable to spoofing; this drawback should be discussed."*

**Author Response:**  
We fully agree with the reviewer. Software-based MAC address spoofing is trivial using utilities such as `macchanger` or virtual machine cloning. We have expanded our manuscript to address this vulnerability directly:
1. We explicitly state in Section 3.3 and Section 5 that MAC address binding alone is insufficient.
2. In our architecture, the MAC address acts solely as a physical endpoint routing/binding factor in a **defense-in-depth model**. Cryptographic secrecy is provided by high-entropy X25519 key agreement combined with a secret passphrase strengthened through 600,000 iterations of PBKDF2-HMAC-SHA256 into secret IKM. An attacker spoofing the MAC address cannot derive the AES key without cracking the secret key material.
3. We discuss hardware-rooted alternatives (TPM 2.0 Platform Configuration Registers, ARM TrustZone, and PUFs) as the production deployment path in Section 5.

**Exact Changes in Manuscript:**
- **Section 3.3: Device Binding Disclaimer:** Detailed the supplementary nature of MAC binding and cited Radhakrishnan et al. (GTID, IEEE TDSC 2015).
- **Section 5: Limitations:** Explicitly itemized software MAC spoofing as Limitation (1).

---

### Comment 2.3: Formal Security Analysis and Threat Model
> *"A formal security analysis or a threat model will enhance the contribution."*

**Author Response:**  
We have added a formal threat model and security evaluation section (**Section 3.1** and **Section 4.6**):
- **Adversary Model:** Formalized under the standard Dolev-Yao model $\mathcal{A}$ with capabilities for eavesdropping, tampering, bit-flipping, packet loss, block swapping/splicing, cross-session injection, and MAC spoofing.
- **Security Objectives:** Formally defined IND-CPA confidentiality, IND-CTXT integrity, spatial anti-reordering, and replay immunity across monotonic epochs.
- **Concealment Trade-off:** Formally identified that an attacker capable of corrupting selected blocks can force concealment; mitigated by the `concealed_block_mask` and rejection threshold $\tau$.
- **Adversarial Test Matrix:** Evaluated across 18 distinct attack scenarios over 100 trials each (Table 6), confirming a **100.0% detection rate** across all 1,800 trials.

**Exact Changes in Manuscript:**
- **Section 3.1: Formal Threat Model and Security Objectives.**
- **Table 6 (`tab:security_matrix`):** Formal Security and Tamper Resistance Test Matrix across 18 attack vectors.

---

### Comment 2.4: Multi-Image Evaluation across Sizes and Content
> *"Evaluation of the method on multiple images of different sizes and content is needed."*

**Author Response:**  
As detailed in our response to Comment 1.1, we have evaluated our entire system across a diverse multi-image benchmark suite:
- Cameraman ($256\times 256$, photographic profile)
- Baboon ($512\times 512$, high-frequency texture)
- Peppers ($512\times 512$, continuous color gradients)
- Medical MRI ($512\times 512$, clinical high-dynamic-range slice)
- Satellite Aerial ($1024\times 1024$, large-scale terrain imagery)
- Submarine ($1199\times 460$, arbitrary-aspect photographic test)

All cryptographic, statistical, and containment metrics are reported in **Table 1** and **Section 4.2**.

---

### Comment 2.5: Comparison with AES-CBC Represented in Table with PSNR
> *"The comparison with AES-CBC is helpful and should be represented in a table containing PSNR values."*

**Author Response:**  
We have structured our error containment comparison into a comprehensive comparative table (**Table 3**) featuring PSNR, SSIM, EPR, and availability values across 30 trials per level for:
1. **Monolithic AES-GCM:** Discards entire payload upon single bit error (0% availability, $\text{PSNR} = 0.00$ dB).
2. **Unframed AES-CBC:** Evaluated under stream packet loss (desynchronizes, $\text{EPR} \le 200.48$, $\text{PSNR} = 13.95$ to $9.28$ dB).
3. **Framed AES-CBC:** Evaluated with sequence headers; preserves block alignment ($\text{EPR} = 1.00$, $\text{PSNR} = 34.79$ to $20.54$ dB) but provides zero cryptographic integrity verification; tampered bits pass undetected into plaintext.
4. **Proposed Scheme (Raw):** Strictly bounded ($\text{EPR} = 1.00$, $\text{PSNR} = 34.79$ to $20.54$ dB).
5. **Proposed Scheme (Concealed):** Restores image quality via boundary interpolation ($\text{PSNR} = 45.57$ to $31.48$ dB, consistent $+10.78$ to $+11.55$ dB gain on Submarine).

**Exact Changes in Manuscript:**
- **Table 3 (`tab:containment_metrics`)**: Error Containment, Availability, and Concealment Gain under Transmission Corruption.
- **Figure 2 (`fig:visual_containment`)**: Reconstructed visual comparison panels for single trial `submarine_K25_trial0` (seed 42).
- **Figure 3 (`fig:psnr_curve`)**: PSNR vs. corrupted blocks curve.

---

### Comment 2.6: Error Concealment of Failed Blocks and Future Work
> *"Error concealment of failed blocks is a natural continuation of future work."*

**Author Response:**  
We agree. In the current revision:
1. We present an immediate spatial boundary-directed interpolation algorithm (Eq. 9/10) that exploits the 2D coordinates revealed by block tag failures, achieving reliable $+10.78$ to $+11.55$ dB PSNR gains on Submarine (and up to $+26.64$ dB across benchmark images at equal fractions).
2. We benchmarked boundary interpolation against OpenCV Telea Fast Marching and Navier-Stokes, demonstrating that our closed-form interpolation achieves quality within 0.21--0.62 dB across all corruption levels on Submarine.
3. In **Section 5 (Limitations)** and **Section 6 (Future Work)**, we discuss advanced deep-learning-based generative inpainting (e.g., Context Encoders [Pathak et al., CVPR 2016] and Partial Convolutions [Liu et al., ECCV 2018]) as the natural continuation of this work for reconstructing stochastic medical and aerial imagery.

---

# Reviewer 3

### Comment 3.1: Shorten Abstract, Eliminate Implementation Details
> *"The abstract could be shortened by eliminating the implementation-level details."*

**Author Response:**  
We have streamlined the abstract to **167 words**, eliminating implementation-level minutiae (such as specific library calls, byte counts, and iteration numbers) while preserving the core problem statement, architectural innovations, quantitative findings, and downstream machine learning implications.

**Exact Changes in Manuscript:**
- **Abstract (lines 53--55):** Revised to 167 words.

---

### Comment 3.2: Explain Relevance to Machine Learning Theme
> *"The relevance of the work to the conference theme of machine learning should be explained in the manuscript."*

**Author Response:**  
This is a vital point for an ICMLDE paper. We have dedicated **Section 4.7** and **Table 7** to demonstrating the direct impact of our system on downstream deep learning inference:
- When transmitting visual data to edge neural network inference pipelines, channel errors cannot be tolerated by traditional cryptographic modes:
  - **Monolithic AEAD** discards the entire frame upon a single corrupted bit $\implies$ **0.0% downstream ML availability**, causing complete pipeline starvation.
  - **Unframed CBC** suffers stream desynchronization $\implies$ downstream classification accuracy collapses to **23.5%**.
  - **Proposed Scheme:** Isolates failed blocks and applies spatial concealment $\implies$ retains **83.8% top-1 classification agreement** under 9.18\% block corruption (a **+42.1 percentage points boost** over zero-masking and **+60.2 percentage points boost** over unframed CBC) without channel retransmission!
  - **Bit-Flip Trade-off:** Under in-place bit-flips without record loss, unauthenticated CBC retains 91.2% agreement solely because it passes corrupted bytes silently into the classifier. An adversary can exploit CBC bit malleability to inject adversarial perturbations without detection. Our scheme detects 100% of tampered blocks and achieves 83.8% agreement while ensuring authentic data integrity.

**Exact Changes in Manuscript:**
- **Section 4.7: Downstream Machine Learning Pipeline Robustness** (MobileNetV2 on 500 ImageNet validation images across 10 trials per level, 5,000 evaluations per scheme).
- **Table 7 (`tab:ml_downstream`)**: Downstream Classification Robustness Under Transmission Corruption.
- **Figure 5 (`fig:ml_downstream`)**: Top-1 agreement under random block corruption.

---

### Comment 3.3: Key Revocation and Session Management
> *"The discussion should cover key revocation and session management."*

**Author Response:**  
We have expanded **Section 3.3** to formally describe key revocation, session ratcheting, and epoch management:
1. **Authenticated Session Header:** Prior to block transmission, sender and receiver exchange a 134-byte authenticated session header protected by HMAC-SHA256 under key $K_{\text{hdr}}$.
2. **Device Revocation List (DRL):** An Ed25519-signed revocation list (RFC 8032) with monotonic version counters is consulted before key expansion; revoked devices are immediately rejected.
3. **Monotonic Epoch Ratcheting:** Each transmission batch carries a monotonic counter $t_{\text{epoch}}$. The receiver stores the highest accepted epoch $t_{\text{last\_epoch}}$ and verifies HMAC before updating epoch storage, eliminating forged epoch lockout and replay attacks.
4. **Key Rotation & Zeroization:** Fresh ephemeral keys $K_{\text{session}}$ are generated per session via X25519 agreement, and sensitive memory buffers are zeroized upon completion.

---

### Comment 3.4: Performance Results on Various Hardware
> *"Performance results on various hardware should be reported."*

**Author Response:**  
In adherence to the strict ground rule of reporting only empirically measured figures:
1. We scoped our evaluation to **actual measured performance** on our testbed: Intel 64-bit host processor (13th Gen Intel Core i5-13420H, 12 threads), Windows 11, OpenSSL AES-NI acceleration across 15 independent benchmark runs in one sitting (median reported, spread logged):
   - Block-level ($16\times 16$) pure crypto throughput: **569.2 MB/s** (latency: **2.91 ms** enc, **2.84 ms** dec, IQR 50.6 MB/s, range 482.9--660.7 MB/s).
   - End-to-end processing throughput: **191.9 MB/s** (latency: 8.62 ms enc, 9.55 ms dec, IQR 21.4 MB/s, range 178.1--214.0 MB/s).
   - Monolithic AES-GCM pure crypto throughput: **1964.7 MB/s** (latency: **0.84 ms** enc, **0.93 ms** dec).
2. We conducted an uncompressed video streaming feasibility analysis (**Table 5**), evaluating load as $(R / T) \times 100\%$ under our 3-tier classification rule (<90% supported, 90-110% at the limit of this host, >110% not supported):
   - **720p 60fps (165.9 MB/s):** Supported on this host under both Pure Crypto (29.1% load, range 25.1--34.4%) and End-to-End processing (86.5% load, range 77.5--93.1%).
   - **1080p 30fps (186.6 MB/s):** Supported on this host under Pure Crypto (32.8% load, range 28.2--38.6%) and operates at the limit of this host for single-threaded End-to-End processing (97.2% load, range 87.2--104.8%).
   - **1080p 60fps (373.2 MB/s):** Crypto is supported (65.6% load), but E2E is not supported (194.5% load), requiring multi-threaded software pipelining.
   - **4K 60fps (1.49 GB/s):** Not supported on this host (262.3% crypto / 778.0% E2E), requiring dedicated hardware ASIC or GPU offloading.
3. We provide `scripts/benchmark_portable.py` in the repository to enable standardized replication on embedded devices (e.g., Raspberry Pi, Jetson Nano).

---

### Comment 3.5: Speed Comparison Against Whole-Image AES-GCM
> *"A comparison of encryption speed to whole-image AES-GCM is needed."*

**Author Response:**  
We have provided a direct comparative benchmark between whole-image (monolithic) AES-GCM and our block-level scheme across multiple granularities ($8\times 8$, $16\times 16$, $32\times 32$, $64\times 64$) in **Table 4**:
- Monolithic GCM executes in **0.84 ms** enc / **0.93 ms** dec (1964.7 MB/s).
- Our $16\times 16$ block scheme executes in **2.91 ms** enc / **2.84 ms** dec (569.2 MB/s pure crypto, 191.9 MB/s end-to-end, 15-run medians).
- The modest ~2.0 ms latency delta is the minimal, worthwhile engineering trade-off that eliminates the catastrophic all-or-nothing discard of monolithic AEAD, ensuring $>90\%$ image availability under channel corruption.

---

# Summary of Deliverables

1. **Source Code & Unit Tests:** All core modules updated under `src/` (`record_format.py`, `key_manager.py`, `encryption.py`, `decryption.py`, `error_concealment.py`, `image_crypto_metrics.py`, `baseline_ciphers.py`, `chaotic_ciphers.py`, `session_protocol.py`). Full unit test suite (74 tests) passes with 100% green status.
2. **Master Experiment Automation:** Deterministic reproduction scripts in `experiments/` reproduce all raw JSON data in `results/`.
3. **Single Source of Truth:** `scripts/make_tables.py` generates all publication LaTeX tables (`tables/table1_crypto.tex` through `table8_multi_image_containment.tex`, plus architectural comparison `table9_stream_comparison.tex` and multi-hardware profile `table5_multi_hardware.tex`), `tables/results_macros.tex`, and synchronizes directly to `paper_icmlde/`.
4. **Single Canonical Manuscript:** `paper_icmlde/sw.tex` formatted for Procedia Computer Science using automated macro inputs; linted with zero errors across all 11 LaTeX files.
5. **Interactive Dashboard:** `app.py` updated with 800-byte framing, 2-factor derivation, spatial error mask overlay, and raw JSON benchmark data export.
6. **Traceability and Audit Documentation:** `TODO_FOR_AUTHOR.md` (author checklist), `PROOFREAD_LOG.md` (harmonization log), `HARDWARE_RUNS.md` (hardware benchmarking instructions), `response_to_reviewers.tex`, and `FINAL_REPORT.md`.

---

## Instructions for Building Revised Paper Deliverable (`1323_revised_version.pdf`)
1. **Local Build (System with LaTeX):**
   ```bash
   cd paper_icmlde
   pdflatex -interaction=nonstopmode sw.tex
   pdflatex -interaction=nonstopmode sw.tex
   cp sw.pdf ../1323_revised_version.pdf
   ```
2. **Overleaf / Cloud LaTeX Engine:**
   - Compress the entire `paper_icmlde/` directory into a `.zip` archive.
   - Import into Overleaf and ensure the compiler is set to **pdfLaTeX** with TeX Live 2024.
   - Compile `sw.tex` and export as `1323_revised_version.pdf`.
3. **Merging with Response to Reviewers (if requested by venue):**
   - Compile `response_to_reviewers.tex` via `pdflatex response_to_reviewers.tex`.
   - Use `pdfunite` or Adobe Acrobat to prepend the response letter to the revised manuscript.

We believe these substantial revisions thoroughly address all reviewer concerns and make the manuscript a rigorous, impactful contribution to Procedia Computer Science and ICMLDE.
