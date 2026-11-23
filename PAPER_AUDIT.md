# PAPER_AUDIT.md: Baseline and Post-Revision Audit of Manuscript (paper_icmlde/sw.tex)

This audit documents every stale, inconsistent, unverified, or non-compliant item in `paper_icmlde/sw.tex` before revision, mapping each finding to its target fix ID (B1–B7, G1–G7, References).

---

## 1. Inventory of Baseline Discrepancies and Inconsistencies (Pre-Revision)

| Item ID | Section / Location in `sw.tex` | Description of Stale / Inconsistent Content | Root Cause & Resolution Plan | Target Fix ID |
|---|---|---|---|---|
| **A01** | Line 49–61 (Front matter) | Page-1 footer text overlaps in Procedia template (`\corref{cor1}` conflicts with default Elsevier journal footer line). | Standardize corresponding author notation per template rules. | **B1** |
| **A02** | Line 53–55 (Abstract) | Abstract contains implementation details (800-byte record, 20-byte AAD, 600,000 iterations); says "six benchmark datasets"; states 414.8 MB/s with 3.67 ms (stale); compares CBC under packet loss only; word count exceeds concise limits. | Replace with standardized ~165-word abstract loaded strictly from macros. Mention both packet loss and bit-flip detection trade-offs. | **B1** |
| **A03** | Lines 81–89 (Intro Contributions) | Contribution 1 claims "without expanding transmission bandwidth"; Contribution 2 cites NIST SP 800-132 for 600k iterations (NIST only generally recommends PBKDF2; 600k is OWASP guidance) and claims "strict replay rejection"; Contribution 5 says "+42.1% percentage-point" and "clean ground-truth predictions"; Contribution 6 claims "real-time support for 720p 60fps and 1080p 30fps" without end-to-end caveat; "authentic" used repeatedly. | Rephrase contributions per B2: state 32 bytes / 4.17% analytical overhead; cite RFC 8018 + OWASP; add "We make no forward-secrecy claim"; specify crypto-only vs end-to-end streaming limits; remove "authentic". | **B2** |
| **A04** | Lines 77, 103 (Intro & Sec 2.1) | CBC described as "catastrophic desynchronization ... corrupting all subsequent plaintext blocks" under record loss. | Clarify that in-place bit-flips recover after 2 blocks, while unannounced record loss causes spatial/byte misalignment unless explicitly framed. | **B2, B3** |
| **A05** | Line 105 (Sec 2.1) | Chaos encryption critique cites 2014 single-scheme paper [21] instead of broader survey, and claims errors "collapse" or go undetected. | Update to Preishuber survey (2018) and explain lack of ciphertext integrity authentication tags. | **B3** |
| **A06** | Line 114, Table 1 (`table2_chaotic.tex`) | "¡= 200.48" character encoding bug from bare `<` in text mode; footnote says "per audit ground rules"; CBC cell says "Cascading Loss (EPR <= 200.48)". Literature rows show `--*`. | Regenerate Table 1: use math mode `$\le$`; change CBC cell to "No integrity; misaligned under unframed loss"; show `TBD` where TODO_USER; neutral footnote without mentioning audit/ground rules. | **B3, G6c** |
| **A07** | Lines 133, 138, 139 (Sec 3.1) | "high-entropy secret passphrase"; forgery probabilities stated as "$\le 2^{-128}$" and "$1 - 2^{-128}$" without GCM message-length bound qualification. | Qualify forgery bounds per NIST SP 800-38D; state "passphrase subject to a minimum-strength policy". Add threat model assumptions and concealment trade-off. | **B4** |
| **A08** | Line 149 (Sec 3.2) | Mentions "In preliminary designs..." (internal project trajectory language). | Replace with objective technical rationale: explain why index is transmitted in record header and authenticated in AAD. | **B4** |
| **A09** | Lines 169–173 (Sec 3.3) | Header equation specifies obsolete 76-byte layout with `uint32(DeviceID)`; does not reflect the implemented 134-byte X25519 ephemeral-static header. | Replace equation with the 134-byte header structure ($magic \parallel ver \parallel flags \parallel epoch \parallel H \parallel W \parallel N \parallel S_{hkdf} \parallel S_{pbkdf2} \parallel eph\_pub \parallel rx\_fp \parallel HMAC$). Document two-factor key schedule. | **B4** |
| **A10** | Lines 201–206 (Sec 3.4) | Union bound formula for $10^9$ sessions stated informally ("$P < 10^{-13}$", "impossible"); limits stated in "blocks" instead of GCM invocations. | Formalize exact union bound; cite $2^{32}$ record invocations limit per key; remove "impossible". | **B4** |
| **A11** | Lines 217–220 (Sec 3.5) | Mentions "In early literature ... 'proving'"; defines $B_{failed}$ for tag-less ciphers via heuristic "$\text{PSNR} < 40\text{ dB}$". | State EPR = 1.00 is algebraic consequence of per-block CTR keystream independence. Replace heuristic with exact byte-difference definition. Report CBC bit-flip damage (2.0 AES blocks). | **B4** |
| **A12** | Line 234 (Sec 3.6) | Does not define the 5 standardized receiver actions; lacks explicit statement that concealed pixels are unauthenticated. | Add paragraph defining the 5 actions and stating the unauthenticated nature of concealed pixels + rejection threshold $\tau$. | **B4** |
| **A13** | Lines 242–250 (Sec 4.1) | Submarine listed as item 6 outside the numbered list environment or broken across figures; Cameraman and MRI grayscale conversions not noted; dataset licenses unflagged. | Place Submarine inside list environment; state dimensions, padding ($1200\times 464$), and channel conversions; mark sources `TODO_USER`. | **B5** |
| **A14** | Lines 257–260 (Sec 4.2) | Chi-square range in text ("218.5 to 278.8") disagrees with Table 2 ($213.91$ to $282.74$); correlation stated as "$|r| < 0.0304$" while $+0.0304$ is reached; UACI hardcoded. | Use macros for chi-square, NPCR, UACI, and max $|r|$. Write $|r| \le \maxCorrelation$. | **B5** |
| **A15** | Lines 280–286 (Sec 4.3) | Uses phrase "catastrophic desynchronization" and duplicated unit "dB dB"; reports all-$K$ concealment range instead of fraction-matched range. | Replace with fraction-matched six-image range; cite per-image gain table and CBC malleability experiment; fix typo. | **B5** |
| **A16** | Lines 290–300 (Sec 4.4, Table 4) | Table 4 displays stale values (3.67 ms / 450.5 MB/s / 2506.1 MB/s); does not show end-to-end throughput alongside crypto throughput. | Regenerate Table 4 with 5-run refreshed benchmark medians showing both Pure Crypto and End-to-End throughput columns. | **B5, G3** |
| **A17** | Lines 304–308 (Sec 4.5, Table 5) | Sec 4.5 text says "36.8% CPU utilization" and "41.4%" while Table 5 says 40.0% and 45.0% load; misses end-to-end load caveats (119.6% and 134.5%). | Report loads under both throughput definitions consistently. State achievable FPS end-to-end. | **B5, G3** |
| **A18** | Line 314 (Sec 4.6) | Sec 4.6 text says "12 adversarial attack vectors" across "1,200 attack instances", whereas Table 6 contains 18 rows ($1,800$ trials). | Update text to cite `\securityVectorsTested` (18) and `\securityTotalTrials` (1,800). | **B5** |
| **A19** | Lines 328–335 (Sec 4.7) | Sec 4.7 reports S1 only; claims deep learning models function "reliably under hostile channel conditions"; Fig 5 titled "Adversarial Channel". | Separate S1 (loss) and S2 (bit flips) into distinct analysis; state CBC preserves higher accuracy under bit flips because it lacks authentication; retitle Fig 5. | **B5** |
| **A20** | Lines 340–343 (Sec 5) | Limitations section is only 2 brief sentences; omits threat model limits, forward secrecy, unauthenticated concealment, and single-host hardware limits. | Expand Limitations into a comprehensive 7-point paragraph covering all real-world boundaries. | **B6** |
| **A21** | Lines 349–350 (Availability) | Code availability URL is an unverified placeholder; text states "pre-trained models" are included (models are downloaded from torchvision, not trained). | Update code availability text with `TODO_USER` placeholder; clarify models/weights come from torchvision sources. | **B6** |
| **A22** | Lines 355–435 (References) | Reference [2] is invented; [17] and [18] have corrupted titles/venues; [21] is wrong paper; citation numbers not in citation order; missing RFC 7748/8032 and Sensors 2026 citation. | Overhaul bibliography strictly adhering to PART 3: restore Sensors paper, update Chai and Hua, cite RFCs, reorder by first appearance. | **PART 3** |

---

## 2. Experimental Data Status (Post-Revision)

- **Fraction-matched concealment gains**: COMPLETED & VERIFIED (`results/containment_fraction_matched.json` generated and logged).
- **ML Downstream Scenario S2**: COMPLETED & VERIFIED (`results/ml_downstream.json` records all schemes with `availability_fraction`, `detected_corrupted_fraction`, and `output_produced`).
- **OpenCV Inpainting Baselines**: COMPLETED & VERIFIED (`results/concealment_baselines.json` populated with exact trial matching to Table 3).
- **CBC Malleability Experiment (`cbc_malleability.json`)**: COMPLETED & VERIFIED (`experiments/exp_cbc_malleability.py` confirms 100% undetected controlled modification for CBC, 0% for proposed GCM).
- **Multi-run Benchmark Refresh**: COMPLETED & VERIFIED (`scripts/benchmark_portable.py` executed across 15 independent runs in one sitting; median selected: pure crypto = 569.2 MB/s [IQR 50.6 MB/s, range 482.9--660.7 MB/s], E2E = 191.9 MB/s [IQR 21.4 MB/s, range 178.1--214.0 MB/s]).
- **Second Hardware Device**: NO (Single host only: `13th Gen Intel Core i5-13420H`; documented in `PAPER_OPEN_ITEMS.md`).

---

## 3. Post-Revision Audit and Resolution Matrix

| Item ID | Section / Location in `sw.tex` | Post-Revision Status | Verification Evidence / Macro | Target Fix ID |
|---|---|---|---|---|
| **A01** | Front matter | **RESOLVED** | Standardized `\cortext[cor1]{Corresponding author. E-mail address: radhukr@am.amrita.edu}`. Unified across `sw.tex`, `README.md`, and `CITATION.cff`. | **B1, K1** |
| **A02** | Abstract | **RESOLVED** | 167-word abstract citing `\eprValue`, `\cipherEntropyMin`--`\cipherEntropyMax`, `\psnrGainRestrictedMinRaw`--`\psnrGainRestrictedMax`, `\mlDatasetImages`, `\mlKEighteenPct`, `\mlAgreementKEighteen`, `\mlZeroKEighteen`, `\overheadPercentSixteen`, `\throughputSixteen`, `\throughputEndToEnd`. Mentions bit-flip detection trade-off. | **B1, K2b** |
| **A03** | Intro (Contributions 1–6) | **RESOLVED** | Contr. 1 states 32 bytes / `\analyticalOverheadPercent` overhead; Contr. 2 cites RFC 8018 + OWASP + "no forward-secrecy claim"; Contr. 3 scopes EPR = 1.00; Contr. 4 reports Submarine + fraction-matched gains; Contr. 5 reports +`\mlGainKEighteenRaw` percentage points over zero-fill and +`\mlGainOverCbcKEighteenRaw` percentage points over unframed CBC; Contr. 6 reports crypto vs E2E video loads on single host using 15-run medians. Zero instances of "authentic". | **B2, K2b, K3b** |
| **A04** | Intro & Sec 2.1 (CBC) | **RESOLVED** | Accurately describes CBC two-block recovery under bit-flips, zero integrity tags, bit malleability, and packet loss stream misalignment. | **B2, B3** |
| **A05** | Sec 2.1 (Chaos) | **RESOLVED** | Updated to Preishuber et al. (IEEE TIFS 2018 survey) and emphasizes absence of standardized AEAD integrity tags. | **B3** |
| **A06** | Table 2 (`table2_chaotic.tex`) | **RESOLVED** | Fixed bare `<` encoding bug; sanitized CBC label; shows `TBD` where TODO_USER; neutral footnote without internal audit jargon. | **B3, G6c** |
| **A07** | Sec 3.1 (Threat Model) | **RESOLVED** | Detailed Dolev-Yao attacker model, OS integrity assumptions, out-of-scope physical attacks, minimum-strength passphrase policy, qualified GCM bounds ($\approx 2^{-128}$), and concealment trade-off. | **B4** |
| **A08** | Sec 3.2 (Record Framing) | **RESOLVED** | Replaced preliminary design phrasing with objective engineering explanation of explicit sequence header preventing stream desynchronization. | **B4** |
| **A09** | Sec 3.3 (Key Management) | **RESOLVED** | Replaced 76-byte equation with 134-byte session header (`\headerBytes`). Fully documented X25519 + PBKDF2 (600,000 rounds) + HKDF-SHA256 pipeline, device binding disclaimer, strict receiver verification order, Ed25519 DRL, and best-effort zeroization. | **B4** |
| **A10** | Sec 3.4 (Nonce Handling) | **RESOLVED** | Derived exact union bound ($1.1 \times 10^{-13}$ across $10^9$ sessions). Explained counter overflow immunity and NIST SP 800-38D $2^{32}$ invocations limit. | **B4** |
| **A11** | Sec 3.5 (EPR Formulation) | **RESOLVED** | Stated EPR = 1.00 is algebraic consequence of per-block CTR keystream independence. Replaced heuristic PSNR rule with exact byte difference for tag-less ciphers. Quantified CBC two-block damage. | **B4** |
| **A12** | Sec 3.6 (Concealment Actions) | **RESOLVED** | Defined the 5 standardized receiver actions (`detected_and_quarantined`, `concealed`, `duplicate_ignored`, `rejected_over_threshold`, `session_rejected`). Clarified unauthenticated nature of concealed pixels. | **B4** |
| **A13** | Sec 4.1 (Setup) | **RESOLVED** | Submarine placed inside numbered list as item 6; dimensions, padding ($1200\times 464$), and grayscale conversions documented; marked `[TODO_USER: source/licence]`. | **B5** |
| **A14** | Sec 4.2 (Randomness) | **RESOLVED** | Sourced entropy, NPCR, UACI, and chi-square metrics from macros. Explains small image sample entropy. Uses $|r| \le \maxCorrelation$. | **B5** |
| **A15** | Sec 4.3 (Containment) | **RESOLVED** | Sourced Submarine metrics from Table 3. Reported fraction-matched six-image gains (`\psnrGainRestrictedMinRaw` to `\psnrGainRestrictedMax`). Fig. 2 caption tied to trial `submarine_K25_trial0` (seed 42). Noted parity with OpenCV Telea / Navier-Stokes within `\deltaOpenCvMinRaw`--`\deltaOpenCvMax` (0.21--0.62 dB). Removed external solver claims. | **B5, K4** |
| **A16** | Sec 4.4, Table 4 (Overhead) | **RESOLVED** | Table 4 displays refreshed 15-run medians: Monolithic (0.84 ms enc, 0.93 ms dec, 1964.7 MB/s); $16\times 16$ (2.91 ms enc, 2.84 ms dec, 569.2 MB/s crypto, 191.9 MB/s E2E). Justified $16\times 16$ block size trade-off. | **B5, K2** |
| **A17** | Sec 4.5, Table 5 (Hardware) | **RESOLVED** | Defined load as $(R / T) \times 100\%$. Evaluated 720p60, 1080p30, 1080p60, and 4K60 under both crypto and E2E definitions using 3-tier classification rule. Reported PBKDF2 time (`\pbkdfTime`) and handshake time (`\handshakeTime`). | **B5, K2, K2b** |
| **A18** | Sec 4.6 (Security Matrix) | **RESOLVED** | Text cites `\securityVectorsTested` (18 vectors) and `\securityTotalTrials` (1,800 trials) with `\securityDetectionRate` (100.0%). Table 6 contains all 18 rows. | **B5** |
| **A19** | Sec 4.7 (Downstream ML) | **RESOLVED** | Separated Scenario 1 (record loss) and Scenario 2 (in-place bit-flips). Unrounded percentage-point differences applied: +60.2 percentage points over unframed CBC (`\mlGainOverCbcKEighteenRaw`); +7.4 percentage points delta in S2 (`\mlSTwoCbcDeltaRaw`). Addressed the security trade-off: CBC achieves higher agreement under bit-flips only because it lacks authentication, whereas proposed scheme enforces 100% cryptographic authentication. Retitled Fig. 5. | **B5, K3, K3b** |
| **A20** | Sec 5 (Limitations) | **RESOLVED** | Expanded into a comprehensive 7-point limitations framework covering all physical, threat model, cryptographic, and computational boundaries. | **B6** |
| **A21** | Sec 6 (Availability) | **RESOLVED** | Updated code availability statement with `TODO_USER` placeholder; clarified model weights are sourced from torchvision without redistribution. | **B6** |
| **A22** | References | **RESOLVED** | Overhauled bibliography: verified SP 800-132, RFC 7748/8032/8018, OWASP guidance, Hoang et al. CRYPTO 2015, Preishuber et al. IEEE TIFS 2018, Telea 2004, Bertalmio et al. 2001; ordered all citations strictly by appearance. | **PART 3, K5** |

---

## 4. Automated Verification and Linter Logs

### 4.1 LaTeX Linter Output (`scripts/lint_latex.py`)
```
Loaded 145 defined macros from results_macros.tex.
Linting 9 LaTeX files...
[SUCCESS] All LaTeX files passed lint checks with zero errors.
```

### 4.2 Unit Test Suite Output (`tasks.py test`)
```
Ran 67 tests in 3.012s
OK

MALLEABILITY EXPERIMENT RESULTS:
  unframed_cbc     | Detected:   0.00% | Controlled Flip Success: 100.00% | Garbage Block: 100.00%
  framed_cbc       | Detected:   0.00% | Controlled Flip Success: 100.00% | Garbage Block: 100.00%
  cbc_hmac         | Detected: 100.00% | Controlled Flip Success:   0.00% | Garbage Block:   0.00%
  proposed_gcm     | Detected: 100.00% | Controlled Flip Success:   0.00% | Garbage Block:   0.00%
```

### 4.3 Stale Content and Prohibited Terms Scan
```
Scanning sw.tex and tables/*.tex for prohibited phrases...
Checked: forward secrecy, impossible, proves/proving, reviewer, preliminary designs,
in early literature, authentic, dB dB, ground-truth predictions, without expanding transmission bandwidth,
catastrophic desynchronization, CPU utilization, Multi-Hardware, 12 attack, 76-byte,
audit, ground rules, percentage-point, |r| <, high-entropy passphrase, Adversarial Channel.
Result: Zero prohibited occurrences found.
```


