"""Experiment: Fraction-Matched Error Containment & Concealment (G4).
Evaluates boundary-directed spatial concealment across all 6 benchmark images
at matched corrupted area fractions:
f in [0.46%, 1.15%, 2.30%, 4.60%, 9.20%] (where K = round(f * N) <= 0.092 * N).
Generates results/containment_fraction_matched.json and computes restricted
min/max concealment gains and per-image gain summary table.
"""

import os
import sys
import json
import random
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, split_into_blocks, merge_blocks, unpad_image
from src.error_concealment import conceal_failed_blocks
from src.image_crypto_metrics import calculate_psnr, calculate_ssim

IMAGES = [
    ("cameraman_256.png", "cameraman", 256),
    ("baboon_texture_512.png", "baboon", 512),
    ("peppers_color_512.png", "peppers", 512),
    ("medical_mri_512.png", "medical_mri", 512),
    ("submarine.jpg", "submarine", None),
    ("satellite_aerial_1024.png", "satellite", 1024),
]

FRACTIONS = [0.0046, 0.0115, 0.0230, 0.0460, 0.0920]
NUM_TRIALS = 30

def run_fraction_matched_experiment(seed=GLOBAL_SEED):
    print("=" * 80)
    print("RUNNING FRACTION-MATCHED CONCEALMENT EXPERIMENT (G4)")
    print(f"Fractions: {[f'{f*100:.2f}%' for f in FRACTIONS]} (Max fraction: 9.20%)")
    print("=" * 80)

    summary_per_image = {}
    detailed_results = {}
    all_restricted_gains = []

    for fn, stem, target_dim in IMAGES:
        fp = os.path.join(INPUT_DIR, fn)
        if not os.path.exists(fp):
            print(f"Warning: File not found {fp}")
            continue

        arr = load_image(fp)
        raw_h, raw_w, channels = arr.shape
        padded, orig_shape = pad_image(arr, BLOCK_SIZE)
        blocks = split_into_blocks(padded, BLOCK_SIZE)
        total_blocks = len(blocks)
        pad_h, pad_w = padded.shape[0], padded.shape[1]
        grid_rows = pad_h // BLOCK_SIZE
        grid_cols = pad_w // BLOCK_SIZE
        block_shape = (BLOCK_SIZE, BLOCK_SIZE, channels)

        image_entries = []
        image_gains = []

        print(f"\nEvaluating {stem} (Dimensions: {raw_w}x{raw_h}, Total Blocks: {total_blocks:,})...")

        for f_target in FRACTIONS:
            K = max(1, int(round(f_target * total_blocks)))
            actual_pct = (K / float(total_blocks)) * 100.0

            raw_psnrs = []
            conc_psnrs = []
            raw_ssims = []
            conc_ssims = []
            gains = []

            for t in range(NUM_TRIALS):
                trial_seed = seed + K * 1000 + t
                t_rng = random.Random(trial_seed)
                corr_indices = sorted(t_rng.sample(range(total_blocks), K))
                corr_set = set(corr_indices)

                # Zero-fill
                zero_blocks = [
                    b.copy() if i not in corr_set else np.zeros(block_shape, dtype=np.uint8)
                    for i, b in enumerate(blocks)
                ]
                recon_zero = unpad_image(merge_blocks(zero_blocks, padded.shape), orig_shape)
                psnr_zero = calculate_psnr(arr, recon_zero)
                ssim_zero = calculate_ssim(arr, recon_zero)
                raw_psnrs.append(psnr_zero)
                raw_ssims.append(ssim_zero)

                # Boundary-directed spatial interpolation
                conc_blocks = conceal_failed_blocks(zero_blocks, corr_indices, (grid_rows, grid_cols), block_shape)
                recon_conc = unpad_image(merge_blocks(conc_blocks, padded.shape), orig_shape)
                psnr_conc = calculate_psnr(arr, recon_conc)
                ssim_conc = calculate_ssim(arr, recon_conc)
                conc_psnrs.append(psnr_conc)
                conc_ssims.append(ssim_conc)

                gains.append(psnr_conc - psnr_zero)

            mean_raw = float(np.mean(raw_psnrs))
            mean_conc = float(np.mean(conc_psnrs))
            mean_gain = float(np.mean(gains))
            image_gains.append(mean_gain)
            all_restricted_gains.append(mean_gain)

            entry = {
                "fraction_target_pct": round(f_target * 100.0, 2),
                "corrupted_blocks": K,
                "actual_fraction_pct": round(actual_pct, 2),
                "raw_psnr_mean": round(mean_raw, 2),
                "raw_psnr_std": round(float(np.std(raw_psnrs)), 2),
                "conc_psnr_mean": round(mean_conc, 2),
                "conc_psnr_std": round(float(np.std(conc_psnrs)), 2),
                "gain_mean_db": round(mean_gain, 2),
                "gain_std_db": round(float(np.std(gains)), 2),
                "raw_ssim_mean": round(float(np.mean(raw_ssims)), 4),
                "conc_ssim_mean": round(float(np.mean(conc_ssims)), 4)
            }
            image_entries.append(entry)
            print(f"  actual f={actual_pct:>5.2f}% (K={K:>3}, target={f_target*100:.2f}%): Raw={mean_raw:.2f} dB -> Conc={mean_conc:.2f} dB | Gain = +{mean_gain:.2f} dB")

        detailed_results[stem] = image_entries
        summary_per_image[stem] = {
            "dimensions": f"{raw_w}x{raw_h}",
            "total_blocks": total_blocks,
            "min_gain_db": round(min(image_gains), 2),
            "max_gain_db": round(max(image_gains), 2),
            "mean_gain_db": round(float(np.mean(image_gains)), 2),
            "actual_k_min": image_entries[0]["corrupted_blocks"],
            "actual_fraction_min_pct": image_entries[0]["actual_fraction_pct"],
            "gain_at_min_fraction": round(image_entries[0]["gain_mean_db"], 2),
            "actual_k_max": image_entries[-1]["corrupted_blocks"],
            "actual_fraction_max_pct": image_entries[-1]["actual_fraction_pct"],
            "gain_at_max_fraction": round(image_entries[-1]["gain_mean_db"], 2)
        }

    output_data = {
        "description": "Fraction-matched error containment evaluation across 6 benchmark images at equal corrupted fractions (K/N <= 0.092)",
        "fractions_tested": FRACTIONS,
        "trials_per_level": NUM_TRIALS,
        "restricted_gain_min_db": round(min(all_restricted_gains), 2),
        "restricted_gain_max_db": round(max(all_restricted_gains), 2),
        "summary_per_image": summary_per_image,
        "detailed_results": detailed_results
    }

    out_file = os.path.join(RESULTS_DIR, "containment_fraction_matched.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print("\n" + "=" * 80)
    print("FRACTION-MATCHED GAIN SUMMARY (K/N <= 9.20%):")
    print("=" * 80)
    for stem, s in summary_per_image.items():
        print(f"  {stem:<18}: {s['min_gain_db']:>5.2f} dB to {s['max_gain_db']:>5.2f} dB (Mean: {s['mean_gain_db']:.2f} dB)")
    print(f"\nOverall Restricted Six-Image Gain Range: {output_data['restricted_gain_min_db']:.2f} dB to {output_data['restricted_gain_max_db']:.2f} dB")
    print(f"Saved results to {out_file}")
    return output_data

if __name__ == "__main__":
    run_fraction_matched_experiment()

