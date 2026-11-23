# CHANGELOG_PAPER.md: Manuscript Revisions Log (Procedia Computer Science / ICMLDE)

This changelog records all targeted modifications performed on `paper_icmlde/sw.tex` and accompanying LaTeX tables/macros to resolve reviewer comments and internal audits.

---

## B1: Front Matter and Metadata
- **Corresponding Author:** Standardized footnote notation to `\cortext[cor1]{Corresponding author. E-mail address: radhukrishna.r@amrita.edu}` to ensure zero visual overlap on page 1.
- **Abstract Overhaul:** Replaced with a strictly constrained ~167-word abstract. Removed all algorithmic names (except AES-256-GCM), byte counts, and iteration numbers. Embedded exact macros for entropy (`\cipherEntropyMin`--`\cipherEntropyMax`), fraction-matched concealment gain (`\psnrGainRestrictedMinRaw`--`\psnrGainRestrictedMax`), MobileNetV2 agreement under 9.18% loss (`\mlAgreementKEighteen` vs `\mlZeroKEighteen`), framing overhead (`\overheadPercentSixteen`), pure crypto throughput (`\throughputSixteen`), and end-to-end throughput (`\throughputEndToEnd`). Explicitly introduced the bit-flip detection trade-off against unauthenticated CBC.
- **Keywords:** Standardized to: `AES-256-GCM \sep Authenticated encryption \sep Device-bound key derivation \sep Error propagation radius \sep Spatial error concealment \sep Machine learning resilience \sep Threat model`.

---

## B2: Section 1 (Introduction)
- **Problem Statement on CBC:** Replaced inaccurate "catastrophic desynchronization" language with precise cryptographic facts: isolated in-place bit-flips self-recover after 2 AES blocks (32 bytes), but CBC carries no integrity tag, leaving tampering silent, untraceable, and malleable; packet/record loss causes stream misalignment unless explicit framing is provided.
- **Contribution 1:** Clarified that the 20-byte AAD is reconstructed from session parameters and adds 0 transmission bytes; the 4-byte index, 12-byte IV, and 16-byte tag introduce exactly 32 bytes per 768-byte payload (`\analyticalOverheadPercent` analytical overhead). Removed "without expanding transmission bandwidth".
- **Contribution 2:** Specified the defense-in-depth pipeline: ephemeral-static X25519 agreement, PBKDF2 passphrase strengthening (`\pbkdfIterations` iterations per RFC 8018 and OWASP guidance), HKDF expansion bound to receiver device identifier and epoch, and Ed25519-signed DRL with rollback protection. Explicitly stated: *"We make no forward-secrecy claim."*
- **Contribution 3:** Formulated EPR = 1.00 within its exact operational scope (in-place corruption and record loss with explicit indexing); replaced "CBC (EPR > 200)" with "unframed CBC streams".
- **Contribution 4:** Reported Submarine concealment gains (`\psnrGainMinRaw` to `\psnrGainMax`) alongside fraction-matched six-image gains (`\psnrGainRestrictedMinRaw` to `\psnrGainRestrictedMax`).
- **Contribution 5:** Reported downstream MobileNetV2 results with exact macros: `+\mlGainKEighteenRaw` percentage points over zero-filling, $+60.3$ percentage points over unframed CBC, and highlighted the bit-flip integrity trade-off.
- **Contribution 6:** Scoped hardware evaluation to a single host; stated streaming capabilities accurately: pure crypto supports 720p 60fps (`\loadCryptoSevenTwenty` load) and 1080p 30fps (`\loadCryptoTenEighty` load); end-to-end supports 720p 60fps (`\loadEtoESevenTwenty` load) and operates at boundary capacity for 1080p 30fps (`\loadEtoETenEighty` load).
- **Style Cleanup:** Removed the word "authentic" from benchmark image descriptions.

---

## B3: Section 2 (Related Work)
- **Section 2.1 (CBC Error Propagation):** Described the exact two-block recovery property of CBC under bit-flips and spatial misalignment under packet loss, citing NIST SP 800-38A and Burda (2006).
- **Section 2.1 (Chaotic Ciphers):** Replaced outdated critique with Preishuber et al. (IEEE TIFS 2018 survey), highlighting the lack of standardized NIST proofs, floating-point divergence, and absent ciphertext authentication tags.
- **Section 2.2 (Streaming AEAD & Novelty):** Added an explicit novelty statement articulating our cross-layer co-design: adapting segmented AEAD to 2D image pipelines via spatial indexing, geometry binding in AAD, device/passphrase-bound key derivation, EPR containment, and tag-directed spatial concealment.
- **Section 2.3 (Availability & Inpainting):** Cited OpenCV inpainting baselines (Telea Fast Marching and Navier-Stokes) alongside deep generative methods (Context Encoders, Partial Convolutions).

---

## B4: Section 3 (Methodology and Threat Model)
- **Section 3.1 (Threat Model):** Articulated the full Dolev-Yao attacker model $\mathcal{A}$; formalized assumptions (OS kernel integrity, physical memory/cold-boot out of boundary, MAC address attacker-readable, enrolment over trusted provisioning channel). Qualified GHASH forgery bounds per NIST SP 800-38D ($\approx 2^{-128}$ per attempt). Added the concealment security trade-off: forged blocks force concealment, mitigated by `concealed_block_mask` and rejection threshold $\tau$.
- **Section 3.2 (Record Framing):** Replaced "preliminary designs" phrasing with objective engineering rationale explaining why explicit sequence headers prevent stream desynchronization. Presented the \recordBytes\ record layout and 20-byte AAD binding formula.
- **Section 3.3 (Key Management):** Updated the session header to the verified \headerBytes\ structure; detailed the two-factor pipeline (X25519 + PBKDF2 600,000 rounds + HKDF-SHA256). Formally added the device binding disclaimer (MAC digest never transmitted; supplementary physical factor). Documented the strict receiver verification sequence: fingerprint lookup $\to$ DRL check $\to$ read-only epoch check $\to$ constant-time HMAC verify $\to$ atomic epoch persist $\to$ $K_{\text{AES}}$ derivation. Stated zeroization is best-effort in Python and confirmed no forward secrecy claim.
- **Section 3.4 (Nonce Handling):** Derived the exact union-bound nonce collision probability across $10^9$ sessions ($\approx 1.1 \times 10^{-13}$). Clarified counter overflow immunity and cited NIST SP 800-38D $2^{32}$ record invocation limits per key.
- **Section 3.5 (EPR Formulation):** Clarified EPR = 1.00 is an algebraic property of per-block CTR keystream independence under per-block AEAD, not a formal security proof. Defined $B_{\text{failed}}$ for tag-less ciphers via exact byte differences. Quantified CBC two-block damage (32 bytes spanning 1.00 to 2.00 image blocks).
- **Section 3.6 (Concealment & Receiver Actions):** Formalized the 5 receiver actions: `detected_and_quarantined`, `concealed`, `duplicate_ignored`, `rejected_over_threshold`, `session_rejected`. Clarified that concealed pixels are unauthenticated.

---

## B5: Section 4 (Experimental Results)
- **Section 4.1 (Setup):** Documented testbed hardware specifications from `results/environment.json`. Structured the six benchmark images into an unbroken numbered list with dimensions and grayscale conversion notes. Marked dataset licenses `TODO_USER`.
- **Section 4.2 (Randomness):** Sourced all entropy (`\cipherEntropyMin`--`\cipherEntropyMax`), NPCR, UACI, and chi-square metrics from macros. Explained the lower sample entropy of smaller images. Stated $|r| \le \maxCorrelation$.
- **Section 4.3 (Containment):** Updated Table 3 Submarine metrics. Stated 100.0% detection precision and recall. Qualified Fig. 2 caption to specific trial `submarine_K25_trial0` (seed 42). Noted that boundary interpolation performs within 0.5 dB of OpenCV Telea and Navier-Stokes without external C++ dependencies.
- **Section 4.4 (Overhead):** Updated Table 4 with the authoritative 5-run median benchmark metrics, presenting both Pure Crypto and End-to-End throughput columns. Discussed block-size selection trade-offs ($8\times 8$ vs $16\times 16$ vs $32\times 32$/$64\times 64$).
- **Section 4.5 (Hardware & Streaming):** Defined operational load as $(R / T) \times 100\%$. Formally evaluated 720p 60fps, 1080p 30fps, 1080p 60fps, and 4K 60fps under both Pure Crypto and End-to-End throughput definitions. Reported PBKDF2 time (`\pbkdfTime`) and session setup latency (`\handshakeTime`).
- **Section 4.6 (Security Matrix):** Sourced Table 6 metrics from macros: `\securityVectorsTested` (18 vectors), `\securityTrialsPerVector` (100 trials), `\securityTotalTrials` (1,800 trials), and `\securityDetectionRate` (100.0%). Aligned action text with Section 3.6 definitions.
- **Section 4.7 (Downstream ML):** Separated Scenario 1 (record loss) and Scenario 2 (in-place bit flips). Addressed the crucial security trade-off: unauthenticated CBC achieves higher agreement under bit flips because it lacks integrity tags, allowing tampered bytes to pass undetected into classifiers, whereas the proposed scheme enforces 100% tamper detection and cryptographic authenticity.

---

## B6: Sections 5 & 6 (Discussion, Limitations, Conclusion)
- **Section 5 (Limitations):** Expanded into a comprehensive 7-point limitations framework covering software MAC spoofing, unauthenticated concealment, lack of forward secrecy, image dimension leakage via padding, bit-flip accuracy trade-offs against CBC, single-host Python profiling, and texture inpainting boundaries.
- **Section 6 (Conclusion):** Sourced all summary metrics from macros. Added bounding statements regarding single-host software profiling.
- **Code & Data Availability:** Replaced hardcoded repository URL with `TODO_USER` placeholder. Clarified ImageNet images and MobileNetV2 weights are obtained from official torchvision sources. Documented reproduction commands.

---

## B7: Layout and Table Hygiene
- Verified all 7 LaTeX tables render cleanly without margin overruns.
- Ensured all LaTeX files pass `scripts/lint_latex.py` with zero errors.
- Verified all 67 project unit tests pass.

---

## K-Series Final Revision Pass (K1–K8)
- **K1 (Author Metadata):** Restored and verified corresponding author email `radhukr@am.amrita.edu` across `paper_icmlde/sw.tex`, `README.md`, and `CITATION.cff`.
- **K2 & K2b (15-Session Benchmark Protocol & Narrative):**
  - Executed 15 independent runs of `scripts/benchmark_portable.py` in one sitting with full pre-flight environment capture (Power Plan: Balanced, Battery: 73%, 12 logical threads on 13th Gen Intel Core i5-13420H). Sourced all timing numbers from 15-run medians and IQRs:
    - Monolithic GCM: Enc 0.84 ms, Dec 0.93 ms, Throughput 1964.7 MB/s.
    - Proposed $16\times 16$: Enc 2.91 ms, Dec 2.84 ms, Pure Crypto 569.2 MB/s (IQR 50.6 MB/s, range 482.9--660.7 MB/s), End-to-End 191.9 MB/s (IQR 21.4 MB/s, range 178.1--214.0 MB/s).
    - Session setup: PBKDF2 106.03 ms, Handshake 105.60 ms.
  - Video Streaming Feasibility classification strictly applied:
    - 720p 60fps (165.9 MB/s): Crypto 29.1% (range 25.1--34.4%, Supported) / E2E 86.5% (range 77.5--93.1%, Supported on this host).
    - 1080p 30fps (186.6 MB/s): Crypto 32.8% (range 28.2--38.6%, Supported) / E2E 97.2% (range 87.2--104.8%, At the limit of this host).
    - 1080p 60fps (373.2 MB/s): Crypto 65.6% (Supported) / E2E 194.5% (Not supported).
    - 4K 60fps (1493.0 MB/s): Crypto 262.3% / E2E 778.0% (Not supported).
- **K3 & K3b (Unrounded Differences in Narrative):** Sourced all percentage-point differences from unrounded values and rounded only at display:
  - Downstream ML S1 K=18: Proposed Concealed (83.78%) vs Unframed CBC (23.54%) gives $83.78 - 23.54 = 60.24 \implies \mathbf{+60.2}$ percentage points (`\mlGainOverCbcKEighteenRaw`), eliminating the stale +60.3 text.
  - Downstream ML S2 K=18: Unframed CBC (91.20%) vs Proposed Concealed (83.78%) gives $91.20 - 83.78 = 7.42 \implies \mathbf{+7.4}$ percentage points (`\mlSTwoCbcDeltaRaw`).
- **K4 (Inpainting Baseline Deltas):** Removed claims of avoiding external C++/solvers relative to OpenCV in Section 4.3; stated exact measured PSNR deltas against OpenCV Telea and Navier-Stokes on Submarine: within `\deltaOpenCvMinRaw`--`\deltaOpenCvMax` (0.21--0.62 dB).
- **K5 (Reference Verification):** Verified standard references (NIST SP 800-132, RFC 7748, RFC 8032, RFC 8018, OWASP iteration guidance, Hoang et al. CRYPTO 2015, Preishuber et al. IEEE TIFS 2018, Telea 2004, Bertalmio et al. 2001) and documented verification in `PAPER_OPEN_ITEMS.md`.
- **K6 & K8 (Validation & Hygiene):**
  - Zero stale numbers (414.8, 450.5, 450.0, 886.1, 541.2, 186.3, 138.7, 3.67, 60.3) in manuscript text.
  - Zero prohibited phrases.
  - All 67 project unit tests passing.
  - All 9 LaTeX files passing `scripts/lint_latex.py` with zero errors.


