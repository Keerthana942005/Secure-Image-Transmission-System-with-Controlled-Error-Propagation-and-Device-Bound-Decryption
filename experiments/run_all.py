"""Master experiment runner for Secure Image Transmission System.
Executes all benchmark experiments sequentially and verifies output integrity.
"""

import os
import sys
import time
import subprocess

def run_experiment(script_name: str):
    print(f"\n{'='*70}\n[RUNNING] {script_name}\n{'='*70}")
    t0 = time.time()
    result = subprocess.run([sys.executable, script_name], capture_output=False)
    elapsed = time.time() - t0
    if result.returncode != 0:
        print(f"[FAILED] {script_name} with return code {result.returncode} in {elapsed:.2f}s")
        sys.exit(result.returncode)
    else:
        print(f"[SUCCESS] {script_name} finished in {elapsed:.2f}s")

def main():
    start_time = time.time()
    print("======================================================================")
    print("STARTING COMPLETE BENCHMARK SUITE (Single Source of Truth)")
    print("======================================================================")

    experiments = [
        "experiments/exp_environment.py",
        "experiments/exp_crypto.py",
        "experiments/exp_containment.py",
        "experiments/exp_concealment.py",
        "experiments/exp_overhead.py",
        "experiments/exp_security.py",
        "experiments/exp_ml_downstream.py",
    ]

    for exp in experiments:
        run_experiment(exp)

    # Verify all expected artifacts exist
    expected_files = [
        "results/environment.json",
        "results/crypto_metrics.json",
        "results/crypto_metrics.csv",
        "results/containment_metrics.json",
        "results/containment_metrics.csv",
        "results/containment_multi_image.json",
        "results/fig2_metrics.json",
        "results/concealment_metrics.json",
        "results/concealment_metrics.csv",
        "results/overhead_metrics.json",
        "results/overhead_metrics.csv",
        "results/security_tests.json",
        "results/security_tests.csv",
        "results/ml_downstream.json",
        "results/ml_downstream.csv",
    ]

    print("\nVerifying output artifacts in results/...")
    all_ok = True
    for f in expected_files:
        if os.path.exists(f) and os.path.getsize(f) > 0:
            print(f"  [OK] {f} ({os.path.getsize(f)} bytes)")
        else:
            print(f"  [MISSING/EMPTY] {f}")
            all_ok = False

    total_time = time.time() - start_time
    print(f"\nAll experiments completed in {total_time:.2f}s.")
    if not all_ok:
        sys.exit(1)
    print("All results verified successfully.")

if __name__ == "__main__":
    main()

