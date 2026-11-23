# Cross-Platform Hardware Benchmarking Guide

This document describes how to execute and contribute portable hardware benchmarks for the Secure Image Transmission System (ICMLDE 5.0, Paper ID 1323).

---

## 1. Overview and Metric Definitions

The benchmark measures cryptographic performance across block sizes and monolithic baselines:

1. **Crypto-Only Latency & Throughput (`crypto_only`):**
   - Measures pure AES-256-GCM encryption/decryption latency over precomputed memory blocks with pre-allocated nonces and 20-byte AADs.
   - Measures raw cryptographic algorithm execution without framing, metadata handling, or array reshaping.

2. **End-to-End Latency & Throughput (`end_to_end`):**
   - Sender: `pad_image` $\to$ `split_into_blocks` $\to$ `pack_record` (4B index + 12B IV + 768B ciphertext + 16B tag) $\to$ AES-GCM encryption.
   - Receiver: `unpack_record` $\to$ AES-GCM decryption $\to$ `merge_blocks` $\to$ `unpad_image`.

3. **Throughput Definition:**
   $$\text{Throughput (MB/s)} = \frac{\text{Raw Image Bytes} / 10^6}{\text{Median Latency (ms)} / 1000.0}$$
   Computed in decimal megabytes per second ($10^6\text{ B/s}$) over raw unpadded image bytes to reflect usable payload transmission throughput.

4. **Feasibility Thresholds for Real-Time Streaming:**
   - **720p @ 60 fps** ($1280 \times 720 \times 3 \times 60$): $165.9\text{ MB/s}$ ($1.33\text{ Gbps}$)
   - **1080p @ 30 fps** ($1920 \times 1080 \times 3 \times 30$): $186.6\text{ MB/s}$ ($1.49\text{ Gbps}$)
   - **1080p @ 60 fps** ($1920 \times 1080 \times 3 \times 60$): $373.2\text{ MB/s}$ ($2.99\text{ Gbps}$)
   - **4K @ 60 fps** ($3840 \times 2160 \times 3 \times 60$): $1493.0\text{ MB/s}$ ($11.94\text{ Gbps}$)

---

## 2. Running on a New Machine

### Prerequisites
- Python 3.10+ (64-bit)
- Dependencies: `pip install numpy cryptography pillow`

### Execution Command
Run the portable benchmark script from the repository root:
```bash
python scripts/benchmark_portable.py
```

The script automatically:
- Detects the CPU model, core/thread count, OS, and AES-NI hardware instruction support.
- Runs 5 warm-up iterations followed by 15 (or 30) timed benchmark runs.
- Computes medians, min, and max ranges.
- Writes host-specific profiles:
  - `results/bench_<hostname>.json`
  - `results/bench_<hostname>_runs.json`
  - `results/environment.json` (host environment metadata)
  - `results/overhead_metrics.json` (source data for Table 4)

---

## 3. Contributing External Hardware Results

To contribute a run from another machine (e.g. Raspberry Pi 4/5, Jetson Orin, Apple M-series, or AMD Ryzen):
1. Copy the generated `results/bench_<hostname>.json` into `results/hardware_profiles/`.
2. Run the hardware aggregation script:
   ```bash
   python scripts/aggregate_hardware.py
   ```
3. This regenerates `tables/table5_multi_hardware.tex` incorporating all detected host profiles.

---

## 4. Current Primary Host Profile
- **Processor:** 13th Gen Intel Core i5-13420H (12 logical threads, x86_64)
- **OS:** Windows 11 (64-bit)
- **Acceleration:** AES-NI Enabled
- **Cryptographic Library:** `cryptography 50.0.2` (OpenSSL 4.0.3 backend)
- **Pure Crypto Throughput ($16\times 16$):** $569.2\text{ MB/s}$
- **End-to-End Throughput ($16\times 16$):** $191.9\text{ MB/s}$
- **Monolithic AES-GCM Baseline:** $1756.2\text{ MB/s}$
- **Monolithic / Block-GCM Overhead Ratio:** $\sim 3.08\times$ (due to $2175$ independent AES-GCM tag evaluations and record framing per frame).

