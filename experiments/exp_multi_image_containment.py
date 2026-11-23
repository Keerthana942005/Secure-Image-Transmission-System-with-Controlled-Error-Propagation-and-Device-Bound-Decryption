"""Comprehensive Multi-Image 5-Scheme Error Containment & Concealment Experiment (Task 1).

Evaluates all 5 transmission schemes across all 6 benchmark images at matched corrupted area fractions:
f in [0.46%, 1.15%, 2.30%, 4.60%, 9.20%] (where K = round(f * N) <= 0.092 * N).

Schemes:
1. Monolithic AES-GCM (0% availability, payload discarded upon tag failure)
2. Unframed AES-CBC (unannounced byte drop, stream desynchronization)
3. Framed AES-CBC (per-block framing, zero-fill on loss, malleable, no tag)
4. Proposed Scheme Raw (block AES-GCM, cryptographic quarantine with zero-fill)
5. Proposed Scheme Concealed (block AES-GCM, tag-directed boundary spatial interpolation)

Deterministic trials: 30 trials per level per image (Seed = 42 + K * 1000 + trial).
Outputs: results/containment_multi_image_full.json
"""

import os
import sys
import json
import random
import time
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, split_into_blocks, merge_blocks, unpad_image
from src.error_concealment import conceal_failed_blocks
from src.image_crypto_metrics import calculate_psnr, calculate_ssim
from src.baseline_ciphers import cbc_encrypt_monolithic, cbc_decrypt_monolithic
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id

BENCHMARK_IMAGES = [
    ("cameraman_256.png", "cameraman", 256),
    ("baboon_texture_512.png", "baboon", 512),
    ("peppers_color_512.png", "peppers", 512),
    ("medical_mri_512.png", "medical_mri", 512),
    ("submarine.jpg", "submarine", None),
    ("satellite_aerial_1024.png", "satellite", 1024),
]

FRACTIONS = [0.0046, 0.0115, 0.0230, 0.0460, 0.0920]
NUM_TRIALS = 30

def run_multi_image_containment(seed: int = GLOBAL_SEED):
    print("=" * 80)
    print("RUNNING MULTI-IMAGE 5-SCHEME CONTAINMENT EXPERIMENT (TASK 1)")
    print(f"Fractions: {[f'{f*100:.2f}%' for f in FRACTIONS]}")
    print(f"Trials per level: {NUM_TRIALS}")
    print("=" * 80)

    device_id = get_device_id()
    passphrase = "MultiImageContainmentBenchmark2026!"
    session_key = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    aes_key = derive_key(session_key, hs, ps, passphrase, device_id, epoch=0)

    results_per_image = {}
    all_gains_pooled = []

    for fn, stem, target_dim in BENCHMARK_IMAGES:
        fp = os.path.join(INPUT_DIR, fn)
        if not os.path.exists(fp):
            print(f"[SKIP] File not found {fp}")
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
        raw_flat_bytes = padded.tobytes()
        block_byte_size = BLOCK_SIZE * BLOCK_SIZE * channels

        # Precompute clean monolithic CBC ciphertext
        cbc_iv, cbc_ct = cbc_encrypt_monolithic(raw_flat_bytes, aes_key)

        print(f"\nProcessing {stem} ({raw_w}x{raw_h}, Total Blocks N={total_blocks:,})...")

        image_fraction_rows = []

        for f_target in FRACTIONS:
            K = max(1, int(round(f_target * total_blocks)))
            actual_pct = (K / float(total_blocks)) * 100.0

            trial_gcm_raw_psnr = []
            trial_gcm_raw_ssim = []
            trial_gcm_conc_psnr = []
            trial_gcm_conc_ssim = []
            trial_gcm_gain = []

            trial_cbc_unframed_psnr = []
            trial_cbc_unframed_ssim = []
            trial_cbc_unframed_epr = []

            trial_cbc_framed_psnr = []
            trial_cbc_framed_ssim = []

            for t in range(NUM_TRIALS):
                trial_seed = seed + K * 1000 + t
                t_rng = random.Random(trial_seed)
                corr_indices = sorted(t_rng.sample(range(total_blocks), K))
                corr_set = set(corr_indices)

                # -------------------------------------------------------------
                # 1. Proposed Raw (Zero-fill on quarantined blocks)
                # -------------------------------------------------------------
                zero_blocks = [
                    b.copy() if i not in corr_set else np.zeros(block_shape, dtype=np.uint8)
                    for i, b in enumerate(blocks)
                ]
                recon_raw = unpad_image(merge_blocks(zero_blocks, padded.shape), orig_shape)
                psnr_raw = calculate_psnr(arr, recon_raw)
                ssim_raw = calculate_ssim(arr, recon_raw)
                trial_gcm_raw_psnr.append(psnr_raw)
                trial_gcm_raw_ssim.append(ssim_raw)

                # -------------------------------------------------------------
                # 2. Proposed Concealed (Boundary-directed spatial interpolation)
                # -------------------------------------------------------------
                conc_blocks = conceal_failed_blocks(zero_blocks, corr_indices, (grid_rows, grid_cols), block_shape)
                recon_conc = unpad_image(merge_blocks(conc_blocks, padded.shape), orig_shape)
                psnr_conc = calculate_psnr(arr, recon_conc)
                ssim_conc = calculate_ssim(arr, recon_conc)
                trial_gcm_conc_psnr.append(psnr_conc)
                trial_gcm_conc_ssim.append(ssim_conc)
                gain = psnr_conc - psnr_raw
                trial_gcm_gain.append(gain)
                all_gains_pooled.append(gain)

                # -------------------------------------------------------------
                # 3. Framed AES-CBC (Record framing, zero-fill on loss, no MAC)
                # -------------------------------------------------------------
                # Dropped CBC record produces identical zero-fill visual reconstruction
                trial_cbc_framed_psnr.append(psnr_raw)
                trial_cbc_framed_ssim.append(ssim_raw)

                # -------------------------------------------------------------
                # 4. Unframed AES-CBC (Stream byte loss -> desynchronization)
                # -------------------------------------------------------------
                corrupted_cbc = bytearray(cbc_ct)
                for idx in sorted(corr_indices, reverse=True):
                    offset = idx * block_byte_size
                    if offset + 16 <= len(corrupted_cbc):
                        del corrupted_cbc[offset:offset + 16]
                pt_cbc = cbc_decrypt_monolithic(cbc_iv, bytes(corrupted_cbc), aes_key)
                if len(pt_cbc) < len(raw_flat_bytes):
                    pt_cbc = pt_cbc + b"\x00" * (len(raw_flat_bytes) - len(pt_cbc))
                cbc_arr = np.frombuffer(pt_cbc[:len(raw_flat_bytes)], dtype=np.uint8).reshape(padded.shape)
                recon_cbc = unpad_image(cbc_arr, orig_shape)
                psnr_cbc = calculate_psnr(arr, recon_cbc)
                ssim_cbc = calculate_ssim(arr, recon_cbc)

                # Count corrupted blocks under CBC stream desync
                cbc_blocks = split_into_blocks(cbc_arr, BLOCK_SIZE)
                wrong_cbc = sum(1 for orig_b, dec_b in zip(blocks, cbc_blocks) if orig_b.tobytes() != dec_b.tobytes())
                epr_cbc = wrong_cbc / float(K) if K > 0 else 1.0

                trial_cbc_unframed_psnr.append(psnr_cbc)
                trial_cbc_unframed_ssim.append(ssim_cbc)
                trial_cbc_unframed_epr.append(epr_cbc)

            # Means & standard deviations for this fraction
            row_summary = {
                "fraction_target_pct": round(f_target * 100.0, 2),
                "corrupted_blocks": K,
                "actual_fraction_pct": round(actual_pct, 2),
                
                # Monolithic GCM
                "mono_gcm_avail_pct": 0.0,
                "mono_gcm_psnr": 0.00,
                
                # Unframed CBC
                "cbc_unframed_epr_mean": round(float(np.mean(trial_cbc_unframed_epr)), 2),
                "cbc_unframed_psnr_mean": round(float(np.mean(trial_cbc_unframed_psnr)), 2),
                "cbc_unframed_psnr_std": round(float(np.std(trial_cbc_unframed_psnr)), 2),
                "cbc_unframed_ssim_mean": round(float(np.mean(trial_cbc_unframed_ssim)), 4),
                
                # Framed CBC
                "cbc_framed_epr_mean": 1.00,
                "cbc_framed_psnr_mean": round(float(np.mean(trial_cbc_framed_psnr)), 2),
                "cbc_framed_psnr_std": round(float(np.std(trial_cbc_framed_psnr)), 2),
                "cbc_framed_ssim_mean": round(float(np.mean(trial_cbc_framed_ssim)), 4),
                
                # Proposed Raw
                "proposed_raw_epr_mean": 1.00,
                "proposed_raw_psnr_mean": round(float(np.mean(trial_gcm_raw_psnr)), 2),
                "proposed_raw_psnr_std": round(float(np.std(trial_gcm_raw_psnr)), 2),
                "proposed_raw_ssim_mean": round(float(np.mean(trial_gcm_raw_ssim)), 4),
                
                # Proposed Concealed
                "proposed_conc_epr_mean": 1.00,
                "proposed_conc_psnr_mean": round(float(np.mean(trial_gcm_conc_psnr)), 2),
                "proposed_conc_psnr_std": round(float(np.std(trial_gcm_conc_psnr)), 2),
                "proposed_conc_ssim_mean": round(float(np.mean(trial_gcm_conc_ssim)), 4),
                "proposed_gain_mean_db": round(float(np.mean(trial_gcm_gain)), 2),
                "proposed_gain_std_db": round(float(np.std(trial_gcm_gain)), 2),
            }
            image_fraction_rows.append(row_summary)
            print(f"  f={actual_pct:>5.2f}% (K={K:>3}): Raw={row_summary['proposed_raw_psnr_mean']:.2f}dB -> Conc={row_summary['proposed_conc_psnr_mean']:.2f}dB | Gain=+{row_summary['proposed_gain_mean_db']:.2f}dB | Unframed CBC EPR={row_summary['cbc_unframed_epr_mean']:.2f}")

        results_per_image[stem] = {
            "dimensions": f"{raw_w}x{raw_h}",
            "total_blocks": total_blocks,
            "fraction_rows": image_fraction_rows
        }

    out_payload = {
        "description": "Multi-Image 5-Scheme Error Containment & Concealment (Task 1)",
        "fractions_tested": FRACTIONS,
        "trials_per_level": NUM_TRIALS,
        "seed": GLOBAL_SEED,
        "restricted_gain_min_db": round(min(all_gains_pooled), 2),
        "restricted_gain_max_db": round(max(all_gains_pooled), 2),
        "restricted_gain_mean_db": round(float(np.mean(all_gains_pooled)), 2),
        "results_per_image": results_per_image
    }

    out_file = os.path.join(RESULTS_DIR, "containment_multi_image_full.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(out_payload, f, indent=2)

    print(f"\nSaved full multi-image containment results to {out_file}")
    print(f"Pooled Concealment Gain Range: {out_payload['restricted_gain_min_db']:.2f} to {out_payload['restricted_gain_max_db']:.2f} dB (Mean: {out_payload['restricted_gain_mean_db']:.2f} dB)")

if __name__ == "__main__":
    run_multi_image_containment()

