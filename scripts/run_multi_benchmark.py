"""Execute 5 benchmark runs of benchmark_portable.py, store all runs,
select the median run, and refresh overhead metrics.
"""

import os
import sys
import json
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import RESULTS_DIR
from scripts.benchmark_portable import run_portable_benchmark
from experiments.exp_overhead import run_overhead_benchmarks

def main():
    runs_dir = os.path.join(RESULTS_DIR, "bench_runs")
    os.makedirs(runs_dir, exist_ok=True)

    print("================================================================================")
    print("EXECUTING 5 PORTABLE BENCHMARK RUNS (G3)")
    print("================================================================================")

    runs = []
    seeds = [42, 43, 44, 45, 46]
    for idx, s in enumerate(seeds, start=1):
        print(f"\n--- BENCHMARK RUN {idx} / 5 (Seed {s}) ---")
        run_data = run_portable_benchmark(seed=s)
        run_file = os.path.join(runs_dir, f"run_{idx}.json")
        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(run_data, f, indent=2)
        runs.append(run_data)

    pure_ths = [r["pure_crypto"]["throughput_decimal_mbps"] for r in runs]
    e2e_ths = [r["end_to_end"]["throughput_decimal_mbps"] for r in runs]

    # Find median run index based on pure crypto throughput
    sorted_indices = np.argsort(pure_ths)
    median_idx = int(sorted_indices[len(runs) // 2])
    median_run = runs[median_idx]

    min_th = float(np.min(pure_ths))
    max_th = float(np.max(pure_ths))
    spread_th = round(max_th - min_th, 1)

    min_e2e = float(np.min(e2e_ths))
    max_e2e = float(np.max(e2e_ths))
    spread_e2e = round(max_e2e - min_e2e, 1)

    summary = {
        "runs_count": len(runs),
        "seeds": seeds,
        "pure_crypto_throughputs": pure_ths,
        "pure_crypto_median_mbps": pure_ths[median_idx],
        "pure_crypto_min_mbps": min_th,
        "pure_crypto_max_mbps": max_th,
        "pure_crypto_spread_mbps": spread_th,
        "end_to_end_throughputs": e2e_ths,
        "end_to_end_median_mbps": e2e_ths[median_idx],
        "end_to_end_min_mbps": min_e2e,
        "end_to_end_max_mbps": max_e2e,
        "end_to_end_spread_mbps": spread_e2e,
        "median_run_index": median_idx + 1,
        "median_run": median_run
    }

    multi_file = os.path.join(RESULTS_DIR, "bench_multi_runs.json")
    with open(multi_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved multi-run summary to {multi_file}")

    # Set environment.json to the median run
    env_file = os.path.join(RESULTS_DIR, "environment.json")
    with open(env_file, "w", encoding="utf-8") as f:
        json.dump(median_run, f, indent=2)
    print(f"Set {env_file} to median run {median_idx + 1} ({pure_ths[median_idx]} MB/s pure, {e2e_ths[median_idx]} MB/s e2e)")

    # Run overhead benchmarks to refresh granularities
    print("\nRefreshing overhead metrics across all granularities (Monolithic, 8x8, 16x16, 32x32, 64x64)...")
    run_overhead_benchmarks(seed=seeds[median_idx])
    print("Overhead metrics successfully refreshed.")

if __name__ == "__main__":
    main()

