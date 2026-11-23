"""Experiment: Benchmark Chaotic and Selective Image Encryption Baselines.
Evaluates Zhou et al. (2014) 1D Chaotic Map, Hua et al. (2015) 2D-SLMM,
and MSB Selective Encryption (AES-CTR on 4 MSBs) across all 6 benchmark images.
Measures:
- Shannon Information Entropy (H)
- NPCR (%) and UACI (%) under 1-bit plaintext perturbations
- Correlation coefficients (r_H, r_V, r_D)
- Encryption execution latency (ms)
Outputs: results/chaotic_baselines.json and updates data/literature_table.csv.
"""

import os
import sys
import json
import time
import random
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import GLOBAL_SEED, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image
from src.image_crypto_metrics import (
    calculate_entropy,
    calculate_npcr,
    calculate_uaci,
    calculate_correlation,
    calculate_chi_square
)
from src.chaotic_ciphers import (
    zhou_1d_encrypt,
    hua_2d_slmm_encrypt,
    msb_selective_encrypt
)

BENCHMARK_IMAGES = [
    ("cameraman_256.png", "cameraman_256"),
    ("baboon_texture_512.png", "baboon_512"),
    ("peppers_color_512.png", "peppers_512"),
    ("medical_mri_512.png", "medical_mri_512"),
    ("submarine.jpg", "submarine"),
    ("satellite_aerial_1024.png", "satellite_1024"),
]

NUM_PERTURBATIONS = 15  # Number of 1-bit perturbations for NPCR/UACI

def evaluate_scheme(name: str, encrypt_fn, image_arr: np.ndarray, seed: int = GLOBAL_SEED):
    rng = random.Random(seed)
    h, w = image_arr.shape[:2]
    channels = image_arr.shape[2] if image_arr.ndim == 3 else 1
    total_pixels = h * w * channels

    # Measure runtime (median of 5 runs)
    times = []
    for _ in range(5):
        t0 = time.perf_counter()
        _ = encrypt_fn(image_arr)
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)
    enc_time_ms = float(np.median(times))

    # Base encryption
    c1 = encrypt_fn(image_arr)
    ent_res = calculate_entropy(c1)
    entropy_val = ent_res['overall']
    corr_res = calculate_correlation(c1, seed=seed)
    chi2_val = calculate_chi_square(c1)

    # Differential metrics: flip 1 bit in plaintext
    npcrs = []
    uacis = []
    for _ in range(NUM_PERTURBATIONS):
        p2 = image_arr.copy()
        flat_p2 = p2.reshape(-1)
        # Select random byte and random bit
        byte_idx = rng.randint(0, total_pixels - 1)
        bit_idx = rng.randint(0, 7)
        flat_p2[byte_idx] ^= (1 << bit_idx)
        
        c2 = encrypt_fn(p2)
        npcrs.append(calculate_npcr(c1, c2))
        uacis.append(calculate_uaci(c1, c2))

    return {
        'scheme': name,
        'entropy': float(entropy_val),
        'npcr_mean': float(np.mean(npcrs)),
        'npcr_std': float(np.std(npcrs)),
        'uaci_mean': float(np.mean(uacis)),
        'uaci_std': float(np.std(uacis)),
        'corr_h': float(corr_res['horizontal']),
        'corr_v': float(corr_res['vertical']),
        'corr_d': float(corr_res['diagonal']),
        'chi_square': float(chi2_val),
        'enc_time_ms': round(enc_time_ms, 2)
    }

def main():
    print("=" * 80)
    print("BENCHMARKING CHAOTIC AND SELECTIVE ENCRYPTION BASELINES")
    print("=" * 80)

    # Use fixed key for AES-CTR MSB selective
    fixed_aes_key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                          0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                          0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5,
                          0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe])

    schemes = [
        ("Zhou et al. (2014) 1D Chaos", lambda img: zhou_1d_encrypt(img)),
        ("Hua et al. (2015) 2D-SLMM", lambda img: hua_2d_slmm_encrypt(img)),
        ("MSB Selective AES-CTR", lambda img: msb_selective_encrypt(img, fixed_aes_key))
    ]

    all_results = {}

    for fname, stem in BENCHMARK_IMAGES:
        fpath = os.path.join(INPUT_DIR, fname)
        if not os.path.exists(fpath):
            print(f"[SKIP] {fname} not found.")
            continue
        print(f"\nProcessing {fname} ({stem})...")
        arr = load_image(fpath)
        all_results[stem] = {}

        for s_name, s_fn in schemes:
            print(f"  Running {s_name}...")
            res = evaluate_scheme(s_name, s_fn, arr, seed=GLOBAL_SEED)
            all_results[stem][s_name] = res
            print(f"    H={res['entropy']:.4f} | NPCR={res['npcr_mean']:.2f}% | UACI={res['uaci_mean']:.2f}% | Latency={res['enc_time_ms']:.2f}ms")

    # Compute overall mean across the 6 images for each scheme
    overall_summary = {}
    for s_name, _ in schemes:
        entropies = [all_results[stem][s_name]['entropy'] for _, stem in BENCHMARK_IMAGES if stem in all_results]
        npcrs = [all_results[stem][s_name]['npcr_mean'] for _, stem in BENCHMARK_IMAGES if stem in all_results]
        uacis = [all_results[stem][s_name]['uaci_mean'] for _, stem in BENCHMARK_IMAGES if stem in all_results]
        times = [all_results[stem][s_name]['enc_time_ms'] for _, stem in BENCHMARK_IMAGES if stem in all_results]
        
        overall_summary[s_name] = {
            'entropy_mean': float(np.mean(entropies)),
            'npcr_mean': float(np.mean(npcrs)),
            'uaci_mean': float(np.mean(uacis)),
            'enc_time_ms_mean': float(np.mean(times)),
            'all_images_entropy': {stem: all_results[stem][s_name]['entropy'] for _, stem in BENCHMARK_IMAGES if stem in all_results}
        }

    output_payload = {
        'per_image_results': all_results,
        'overall_summary': overall_summary
    }

    out_file = os.path.join(RESULTS_DIR, "chaotic_baselines.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    print(f"\nSaved chaotic baselines to {out_file}")

    print("\nOVERALL SUMMARY ACROSS 6 BENCHMARK IMAGES:")
    for s_name, summary in overall_summary.items():
        print(f"  {s_name:<30}: H={summary['entropy_mean']:.4f}, NPCR={summary['npcr_mean']:.2f}%, UACI={summary['uaci_mean']:.2f}%, Mean Latency={summary['enc_time_ms_mean']:.2f}ms")

if __name__ == "__main__":
    main()
