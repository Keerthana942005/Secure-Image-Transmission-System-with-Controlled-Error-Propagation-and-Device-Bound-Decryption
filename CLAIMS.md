# CLAIMS.md: Quantitative and Comparative Claims Traceability Matrix

This document provides a complete audit trail for every numerical, quantitative, and comparative claim made in the manuscript (`paper_icmlde/sw.tex`), linking each statement to its authoritative results macro (`tables/results_macros.tex`), generated LaTeX table, and raw benchmark JSON file in `results/`.

---

## 1. Framing and Record Specifications

| Paper Claim | Manuscript Location | Macro / Symbol | Value | Source File & Field |
|---|---|---|---|---|
| Framed record size | Abstract, Sec 1, Sec 3.2 | `\recordBytes` | 800 bytes | `src/config.py` (`RECORD_SIZE = 800`), `src/record_format.py` |
| Analytical framing overhead | Sec 1 (Contr. 1), Sec 4.4, Sec 6 | `\analyticalOverheadPercent` | 4.17% | `(32 / 768) * 100%`, `results/overhead_metrics.json` |
| Total framing overhead (with padding) | Abstract, Sec 4.4, Sec 6 | `\overheadPercentSixteen` | 5.16% | `results/overhead_metrics.json` (`total_overhead_pct`) |
| Session establishment header size | Sec 3.3 | `\headerBytes` | 134 bytes | `src/config.py` (`SESSION_HEADER_SIZE = 134`), `src/session_protocol.py` |
| Multi-attribute AAD length | Sec 1, Sec 3.2 | -- | 20 bytes | `src/record_format.py` (`build_aad`: 5 $\times$ uint32) |
| Monolithic AES-GCM record size / overhead | Sec 4.4, Table 4 | `\overheadAnalyticalMono` | $<0.01$\% | `results/overhead_metrics.json` |

---

## 2. Cryptographic and Randomness Metrics

| Paper Claim | Manuscript Location | Macro / Symbol | Value | Source File & Field |
|---|---|---|---|---|
| Ciphertext Shannon Entropy (Range) | Abstract, Sec 4.2, Sec 6 | `\cipherEntropyMin`--`\cipherEntropyMax` | 7.9991--7.9999 bits | `results/crypto_metrics.json` (`cipher_entropy`) |
| Theoretical ideal entropy difference | Sec 4.2 | -- | $< 0.001$ bits | Relative to 8.0000 theoretical maximum |
| Block NPCR (Fresh nonces) | Sec 4.2 | `\npcrMin`--`\npcrMax` | 99.60%--99.62% | `results/crypto_metrics.json` (`block_npcr_rand_mean`) |
| Block UACI (Fresh nonces) | Sec 4.2 | `\uaciMin`--`\uaciMax` | 33.48%--33.51% | `results/crypto_metrics.json` (`block_uaci_rand_mean`) |
| Block NPCR (Fixed nonce CTR mode) | Sec 4.2 | -- | 0.1302% | Exactly $1/768 = 0.1302\%$ (bit flip isolation) |
| Max Adjacent Pixel Correlation $|r|$ | Sec 4.2, Sec 6 | `\maxCorrelation` | $\le 0.0304$ | `results/crypto_metrics.json` (`cipher_corr_h/v/d`) |
| Chi-Square Uniformity Range | Sec 4.2 | `\chiSquareMin`--`\chiSquareMax` | 213.91--282.74 | `results/crypto_metrics.json` (`chi_square_stat`) |
| Chi-Square Critical Threshold ($\alpha=0.05$) | Sec 4.2 | `\chiSquareCritical` | 293.25 | $\chi^2_{255, 0.05} = 293.25$ |

---

## 3. Error Containment, Concealment, and Inpainting

| Paper Claim | Manuscript Location | Macro / Symbol | Value | Source File & Field |
|---|---|---|---|---|
| Error Propagation Radius (EPR) | Abstract, Sec 1, Sec 3.5, Sec 6 | `\eprValue` | 1.00 | Algebraic consequence of per-block CTR keystream independence |
| Submarine Concealment Gain ($K > 0$) | Sec 1 (Contr. 4), Sec 4.3 | `\psnrGainMin`--`\psnrGainMax` | 10.78--11.55 dB | `results/containment_metrics.json` (`gcm_psnr_gain_mean`) |
| Fraction-Matched Concealment Gain (Restricted) | Abstract, Sec 1, Sec 4.3 | `\psnrGainRestrictedMin`--`\psnrGainRestrictedMax` | 10.78--26.64 dB | `results/containment_fraction_matched.json` |
| Six-Image Summary Concealment Gain (All tested $K$) | Sec 4.3 | `\psnrGainSixImageMin`--`\psnrGainSixImageMax` | 5.83--21.80 dB | `results/containment_summary.json` |
| Single Trial Visual Metrics (Fig. 2, $K=25$, Submarine) | Fig. 2 caption | `\figTwoRawPSNR`, `\figTwoConcPSNR`, `\figTwoCBCPSNR`, `\figTwoGain` | Raw: 30.62 dB, Conc: 44.38 dB, CBC: 11.03 dB, Gain: +13.76 dB | `results/fig2_metrics.json` (`trial_id: submarine_K25_trial0`, `seed: 42`) |
| Unframed CBC stream desynchronization ($K=10$) | Sec 4.3 | -- | 92.17% corrupted, EPR 200.48, PSNR 13.95 dB | `results/containment_metrics.json` (`cbc_loss_epr_mean`, `cbc_loss_psnr_mean`) |
| Detection Precision and Recall | Sec 4.3 | -- | 100.0% precision, 100.0% recall | `results/security_tests.json` |
| Concealment vs OpenCV Telea / Navier-Stokes | Sec 4.3 | `\deltaOpenCvMin`--`\deltaOpenCvMax` | Within 0.21--0.62 dB | `results/concealment_baselines.json` ($K=10$: 45.57 vs 45.25 / 44.98 dB; $K=200$: 31.48 vs 31.23 / 30.89 dB) |

---

## 4. Computational Latency, Throughput, and Streaming Feasibility

| Paper Claim | Manuscript Location | Macro / Symbol | Value | Source File & Field |
|---|---|---|---|---|
| Proposed $16\times 16$ Encryption Latency | Sec 1, Sec 4.4, Sec 6 | `\encTimeSixteen` | 2.91 ms (15-run median) | `results/bench_multi_runs.json`, `results/overhead_metrics.json` |
| Proposed $16\times 16$ Decryption Latency | Sec 4.4, Sec 6 | `\decTimeSixteen` | 2.84 ms (15-run median) | `results/bench_multi_runs.json`, `results/overhead_metrics.json` |
| Proposed $16\times 16$ Pure Crypto Throughput | Abstract, Sec 1, Sec 4.4, Sec 6 | `\throughputSixteen` | 569.2 MB/s (15-run median, IQR 50.6 MB/s, range 482.9--660.7 MB/s) | `results/bench_multi_runs.json`, `results/overhead_metrics.json` |
| Proposed $16\times 16$ End-to-End Throughput | Abstract, Sec 1, Sec 4.4, Sec 6 | `\throughputEndToEnd` | 191.9 MB/s (15-run median, IQR 21.4 MB/s, range 178.1--214.0 MB/s) | `results/bench_multi_runs.json`, `results/overhead_metrics.json` |
| Monolithic GCM Enc / Dec Latency | Sec 4.4, Table 4 | `\monoEncTime`, `\monoDecTime` | Enc: 0.84 ms, Dec: 0.93 ms (15-run median) | `results/bench_multi_runs.json`, `results/overhead_metrics.json` |
| Monolithic GCM Throughput | Sec 4.4, Table 4 | `\monoThroughput` | 1964.7 MB/s (15-run median) | `results/bench_multi_runs.json`, `results/overhead_metrics.json` |
| PBKDF2 Passphrase Derivation Latency | Sec 3.3, Sec 4.5, Table 5 | `\pbkdfTime` | 106.03 ms (600,000 iterations, 15-run median) | `results/overhead_metrics.json` (`pbkdf2_mean_ms`) |
| Session Transport / Handshake Latency | Sec 4.5, Table 5 | `\handshakeTime` | 105.60 ms (15-run median) | `results/overhead_metrics.json` (`session_setup_mean_ms`) |
| 720p 60fps Streaming Load (165.9 MB/s) | Sec 1, Sec 4.5, Table 5 | `\loadCryptoSevenTwenty`, `\loadEtoESevenTwenty` | 29.1% Crypto (25.1--34.4%, Supported) / 86.5% E2E (77.5--93.1%, Supported) | Calculated: $(165.9 / 569.2)\times 100\%$ and $(165.9 / 191.9)\times 100\%$ |
| 1080p 30fps Streaming Load (186.6 MB/s) | Sec 1, Sec 4.5, Table 5 | `\loadCryptoTenEighty`, `\loadEtoETenEighty` | 32.8% Crypto (28.2--38.6%, Supported) / 97.2% E2E (87.2--104.8%, At the limit of this host) | Calculated: $(186.6 / 569.2)\times 100\%$ and $(186.6 / 191.9)\times 100\%$ |
| 1080p 60fps Streaming Load (373.2 MB/s) | Sec 4.5, Table 5 | `\loadCryptoTenEightySixty`, `\loadEtoETenEightySixty` | 65.6% Crypto (56.5--77.3%, Supported) / 194.5% E2E (174.4--209.5%, Not supported) | Calculated: $(373.2 / 569.2)\times 100\%$ and $(373.2 / 191.9)\times 100\%$ |
| 4K 60fps Streaming Load (1.49 GB/s) | Sec 4.5, Table 5 | `\loadCryptoFourKSixty`, `\loadEtoEFourKSixty` | 262.3% Crypto (226.0--309.2%, Not supported) / 778.0% E2E (697.7--838.3%, Not supported) | Calculated: $(1493.0 / 569.2)\times 100\%$ and $(1493.0 / 191.9)\times 100\%$ |
| Benchmark Runs & Median Spread | Sec 4.5 | `\benchRunsCount`, `\benchCryptoSpread`, `\benchEtoESpread` | 15 runs; spread: 177.8 MB/s crypto (IQR 50.6 MB/s), 35.9 MB/s E2E (IQR 21.4 MB/s) | `results/bench_multi_runs.json` |

---

## 5. Adversarial Security and Tamper Resistance Matrix

| Paper Claim | Manuscript Location | Macro / Symbol | Value | Source File & Field |
|---|---|---|---|---|
| Attack vectors evaluated | Sec 4.6, Table 6 | `\securityVectorsTested` | 18 vectors | `results/security_tests.json` (18 distinct vectors) |
| Trials per vector | Sec 4.6, Table 6 | `\securityTrialsPerVector` | 100 trials | `results/security_tests.json` |
| Total adversarial trials | Sec 4.6, Table 6 | `\securityTotalTrials` | 1,800 trials | $18 \times 100 = 1,800$ trials |
| Empirical Detection Rate | Sec 4.6, Table 6 | `\securityDetectionRate` | 100.0% | `results/security_tests.json` (`detection_rate_pct`) |

---

## 6. Downstream Machine Learning Inference (MobileNetV2 on ImageNet)

| Paper Claim | Manuscript Location | Macro / Symbol | Value | Source File & Field |
|---|---|---|---|---|
| Validation images evaluated | Abstract, Sec 4.7 | `\mlDatasetImages` | 500 images | `results/ml_downstream.json` |
| Trials per corruption level | Sec 4.7 | `\mlTrialsPerLevel` | 10 trials | `results/ml_downstream.json` |
| Total inferences evaluated | Sec 4.7 | `\mlTotalInferences` | 100,500 inferences | $500\text{ images} \times 10\text{ trials} \times 5\text{ levels} \times 4\text{ schemes} + \text{clean}$ |
| Evaluated block loss levels ($K/196$) | Sec 4.7 | `\mlKOnePct` to `\mlKEighteenPct` | $K \in \{1, 2, 5, 9, 18\} \equiv \{0.51\%, 1.02\%, 2.55\%, 4.59\%, 9.18\%\}$ | `results/ml_downstream.json` |
| Scenario 1: Proposed Concealed Agreement ($K=1$) | Sec 4.7 | `\mlAgreementKOne` | 97.1% ($\pm 1.4\%$) | `results/ml_downstream.json` (`proposed_conc_agreement_mean_pct`) |
| Scenario 1: Proposed Concealed Agreement ($K=18$) | Abstract, Sec 1, Sec 4.7, Sec 6 | `\mlAgreementKEighteen` | 83.8% ($\pm 3.1\%$) | `results/ml_downstream.json` (`proposed_conc_agreement_mean_pct`) |
| Scenario 1: Proposed Zero-Fill Agreement ($K=18$) | Abstract, Sec 4.7 | `\mlZeroKEighteen` | 41.6% ($\pm 4.3\%$) | `results/ml_downstream.json` (`proposed_zero_agreement_mean_pct`) |
| Scenario 1: Unframed CBC Agreement ($K=18$) | Abstract, Sec 4.7 | `\mlCbcKEighteen` | 23.5% ($\pm 3.7\%$) | `results/ml_downstream.json` (`cbc_unframed_agreement_mean_pct`) |
| Scenario 1: Concealment Gain Over Zero-Fill ($K=18$) | Sec 1, Sec 4.7 | `\mlGainOverZeroKEighteenRaw` | +42.1 percentage points | $83.78\% - 41.64\% = +42.14$ percentage points (unrounded) |
| Scenario 1: Concealment Gain Over Unframed CBC ($K=18$) | Sec 1, Sec 4.7 | `\mlGainOverCbcKEighteenRaw` | +60.2 percentage points | $83.78\% - 23.54\% = +60.24$ percentage points (unrounded) |
| Scenario 1: Monolithic GCM Agreement | Abstract, Sec 1, Sec 4.7, Sec 6 | -- | 0.0% (total payload discard) | `results/ml_downstream.json` (`mono_gcm_output_produced = False`) |
| Scenario 2: Unframed CBC Agreement ($K=18$) | Sec 4.7 | `\mlSTwoUnframedCbc` | 91.2% | `results/ml_downstream.json` (`cbc_unframed_agreement_mean_pct`) |
| Scenario 2: Framed CBC Agreement ($K=18$) | Sec 4.7 | `\mlSTwoFramedCbc` | 91.3% | `results/ml_downstream.json` (`cbc_framed_agreement_mean_pct`) |
| Scenario 2: Proposed Concealed Agreement ($K=18$) | Sec 4.7 | `\mlSTwoProposedConc` | 83.8% | `results/ml_downstream.json` (`proposed_conc_agreement_mean_pct`) |
| Scenario 2: Unframed CBC vs Concealed Delta ($K=18$) | Sec 4.7 | `\mlSTwoCbcDeltaRaw` | +7.4 percentage points | $91.20\% - 83.78\% = +7.42$ percentage points (unrounded) |
| Scenario 2: Tamper Detection Rate (CBC vs Proposed) | Abstract, Sec 1, Sec 4.7 | -- | CBC: 0.0% (undetected); Proposed: 100.0% | `results/cbc_malleability.json`, `results/security_tests.json` |
| Scenario 2: Controlled Bit Modification Success | Sec 4.7 | -- | CBC: 100.0% success; Proposed: 0.0% success | `results/cbc_malleability.json` |

