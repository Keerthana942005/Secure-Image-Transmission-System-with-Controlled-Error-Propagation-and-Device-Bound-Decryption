"""Experiment: Advanced Inpainting Baselines vs Proposed Boundary Interpolation.
Evaluates Mean-Color Fill, OpenCV Telea Fast Marching, OpenCV Navier-Stokes,
and Proposed Vectorized Boundary-Directed Spatial Interpolation across
corruption levels K in {10, 25, 50, 100, 200}.

Crucially reuses the exact same corrupted block sets (same seed, K, and trial schedule)
as exp_containment.py (30 trials/level) so that Zero-Fill and Proposed PSNR values
match Table 3 (tab:containment_metrics) exactly.
"""

import os
import sys
import json
import csv
import random
import time
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, split_into_blocks, merge_blocks, unpad_image
from src.error_concealment import conceal_failed_blocks, mean_color_fill, inpaint_telea, inpaint_navier_stokes, HAS_CV2
from src.image_crypto_metrics import calculate_psnr, calculate_ssim

BENCHMARK_IMAGES = [
    ('submarine.jpg', 'submarine'),
    ('peppers_color_512.png', 'peppers_512'),
    ('baboon_texture_512.png', 'baboon_512')
]
CORRUPTION_LEVELS = [10, 25, 50, 100, 200]
NUM_TRIALS = 30

def load_containment_trials_map(stem: str) -> dict:
    """Loads pre-generated trial records from exp_containment.py if available."""
    trials_path = os.path.join(RESULTS_DIR, f"containment_trials_{stem}.json")
    trials_map = {}
    if os.path.exists(trials_path):
        try:
            with open(trials_path, "r", encoding="utf-8") as f:
                records = json.load(f)
            for r in records:
                k = r.get('K')
                t = r.get('trial')
                if k is not None and t is not None:
                    trials_map[(k, t)] = r.get('corrupted_indices', [])
        except Exception:
            pass
    return trials_map

def run_concealment_baselines(seed=GLOBAL_SEED):
    print("=" * 80)
    print("RUNNING ADVANCED CONCEALMENT BASELINES EXPERIMENT (TASK 10.1)")
    print(f"OpenCV inpainting available: {HAS_CV2} | Trials per level: {NUM_TRIALS}")
    print("=" * 80)
    
    all_results = []
    
    for fn, stem in BENCHMARK_IMAGES:
        fp = os.path.join(INPUT_DIR, fn)
        if not os.path.exists(fp):
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
        
        trials_map = load_containment_trials_map(stem)
        print(f"\n--- Benchmark Image: {fn} ({total_blocks} blocks) | Stored trial sets: {len(trials_map)} ---")
        
        for K in CORRUPTION_LEVELS:
            if K > total_blocks:
                continue
                
            raw_psnrs = []
            mean_fill_psnrs = []
            mean_fill_ssims = []
            prop_psnrs = []
            prop_ssims = []
            telea_psnrs = []
            ns_psnrs = []
            
            for t in range(NUM_TRIALS):
                # 1. Use stored corrupted block indices from containment experiment if present;
                # otherwise derive using identical deterministic seed formula
                if (K, t) in trials_map and len(trials_map[(K, t)]) == K:
                    corr_indices = trials_map[(K, t)]
                else:
                    trial_seed = seed + K * 1000 + t
                    t_rng = random.Random(trial_seed)
                    corr_indices = sorted(t_rng.sample(range(total_blocks), K))
                corr_set = set(corr_indices)
                
                # 1. Zero-fill
                zero_blocks = [b.copy() if i not in corr_set else np.zeros(block_shape, dtype=np.uint8)
                               for i, b in enumerate(blocks)]
                recon_zero = unpad_image(merge_blocks(zero_blocks, padded.shape), orig_shape)
                psnr_zero = calculate_psnr(arr, recon_zero)
                raw_psnrs.append(psnr_zero)
                
                # 2. Mean-color fill baseline
                mf_blocks = mean_color_fill(zero_blocks, corr_indices, (grid_rows, grid_cols), block_shape)
                recon_mf = unpad_image(merge_blocks(mf_blocks, padded.shape), orig_shape)
                mean_fill_psnrs.append(calculate_psnr(arr, recon_mf))
                mean_fill_ssims.append(calculate_ssim(arr, recon_mf))
                
                # 3. Proposed boundary-directed spatial interpolation (Eq. 10/11)
                prop_blocks = conceal_failed_blocks(zero_blocks, corr_indices, (grid_rows, grid_cols), block_shape)
                recon_prop = unpad_image(merge_blocks(prop_blocks, padded.shape), orig_shape)
                prop_psnrs.append(calculate_psnr(arr, recon_prop))
                prop_ssims.append(calculate_ssim(arr, recon_prop))
                
                # 4. OpenCV baselines if cv2 is installed
                if HAS_CV2:
                    mask = np.zeros((pad_h, pad_w), dtype=np.uint8)
                    for idx in corr_indices:
                        r = (idx // grid_cols) * BLOCK_SIZE
                        c = (idx % grid_cols) * BLOCK_SIZE
                        mask[r:r+BLOCK_SIZE, c:c+BLOCK_SIZE] = 1
                    
                    recon_telea = inpaint_telea(merge_blocks(zero_blocks, padded.shape), mask)
                    telea_psnrs.append(calculate_psnr(arr, unpad_image(recon_telea, orig_shape)))
                    
                    recon_ns = inpaint_navier_stokes(merge_blocks(zero_blocks, padded.shape), mask)
                    ns_psnrs.append(calculate_psnr(arr, unpad_image(recon_ns, orig_shape)))

            entry = {
                'image': stem,
                'total_blocks': total_blocks,
                'corrupted_blocks': K,
                'corrupted_pct': round((K / float(total_blocks)) * 100.0, 2),
                'zero_fill_psnr': round(float(np.mean(raw_psnrs)), 2),
                'mean_fill_psnr': round(float(np.mean(mean_fill_psnrs)), 2),
                'mean_fill_ssim': round(float(np.mean(mean_fill_ssims)), 4),
                'proposed_psnr': round(float(np.mean(prop_psnrs)), 2),
                'proposed_ssim': round(float(np.mean(prop_ssims)), 4),
                'proposed_vs_zero_gain_db': round(float(np.mean(prop_psnrs)) - float(np.mean(raw_psnrs)), 2),
                'proposed_vs_meanfill_gain_db': round(float(np.mean(prop_psnrs)) - float(np.mean(mean_fill_psnrs)), 2),
                'telea_psnr': round(float(np.mean(telea_psnrs)), 2) if telea_psnrs else None,
                'navier_stokes_psnr': round(float(np.mean(ns_psnrs)), 2) if ns_psnrs else None
            }
            all_results.append(entry)
            print(f"  K={K:>3} ({entry['corrupted_pct']:>5.2f}%): Zero={entry['zero_fill_psnr']} dB | Proposed={entry['proposed_psnr']} dB | Telea={entry['telea_psnr']} dB | NS={entry['navier_stokes_psnr']} dB (Gain: +{entry['proposed_vs_zero_gain_db']} dB)")

    out_json = os.path.join(RESULTS_DIR, "concealment_baselines.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nSaved concealment baselines JSON to {out_json}")
    
    out_csv = os.path.join(RESULTS_DIR, "concealment_baselines.csv")
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_results[0].keys()))
        writer.writeheader()
        writer.writerows(all_results)
    print(f"Saved concealment baselines CSV to {out_csv}")
    return all_results

if __name__ == "__main__":
    run_concealment_baselines()
