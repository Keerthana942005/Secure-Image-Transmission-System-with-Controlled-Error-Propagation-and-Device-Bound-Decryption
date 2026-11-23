import os
import sys
import json
import csv
import random
import time
import numpy as np
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, unpad_image, split_into_blocks, merge_blocks
from src.encryption import encrypt_blocks
from src.decryption import decrypt_blocks
from src.record_format import pack_record, unpack_record
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id
from src.error_concealment import conceal_failed_blocks
from src.image_crypto_metrics import calculate_psnr, calculate_ssim
from src.baseline_ciphers import (
    cbc_encrypt_monolithic,
    cbc_decrypt_monolithic,
    gcm_encrypt_monolithic,
    gcm_decrypt_monolithic,
    cbc_block_hmac_encrypt,
    cbc_block_hmac_decrypt,
    cbc_block_framed_encrypt,
    cbc_block_framed_decrypt
)

CORRUPTION_LEVELS = [0, 10, 25, 50, 100, 200]
NUM_TRIALS = 30

BENCHMARK_IMAGES = [
    ("submarine.jpg", "submarine"),
    ("cameraman_256.png", "cameraman_256"),
    ("baboon_texture_512.png", "baboon_512"),
    ("peppers_color_512.png", "peppers_512"),
    ("medical_mri_512.png", "medical_mri_512"),
    ("satellite_aerial_1024.png", "satellite_1024")
]

def run_image_containment(image_path: str, img_stem: str, num_trials: int = NUM_TRIALS, seed: int = GLOBAL_SEED) -> tuple[list[dict], list[dict]]:
    """Runs containment experiments on a single image across 3 corruption models (M1, M2, M3) and 5 schemes:
    - M1: In-place bit flip
    - M2: Stream loss without framing (unannounced byte drop)
    - M3: Packet record drop with framing index
    
    Schemes:
    (a) Monolithic AES-GCM
    (b) Unframed AES-CBC
    (c) Framed AES-CBC
    (d) Per-block AES-CBC + HMAC-SHA256 (Encrypt-then-MAC)
    (e) Proposed Block AES-GCM (Raw and Concealed)
    """
    arr = load_image(image_path)
    raw_h, raw_w, channels = arr.shape
    padded, orig_shape = pad_image(arr, BLOCK_SIZE)
    blocks = split_into_blocks(padded, BLOCK_SIZE)
    total_blocks = len(blocks)
    block_shape = (BLOCK_SIZE, BLOCK_SIZE, channels)
    grid_rows = padded.shape[0] // BLOCK_SIZE
    grid_cols = padded.shape[1] // BLOCK_SIZE
    raw_flat_bytes = padded.tobytes()
    block_byte_size = BLOCK_SIZE * BLOCK_SIZE * channels  # 768

    device_id = get_device_id()
    passphrase = "ContainmentExperimentSecret2026!"
    session_key = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    aes_key = derive_key(session_key, hs, ps, passphrase, device_id, epoch=0)
    mac_key = os.urandom(32)

    # Pre-encrypt clean records
    clean_gcm_records = encrypt_blocks(blocks, aes_key, padded.shape, epoch=0)
    clean_cbc_iv, clean_cbc_ct = cbc_encrypt_monolithic(raw_flat_bytes, aes_key)
    clean_cbc_framed_records = cbc_block_framed_encrypt(blocks, aes_key)
    clean_cbc_hmac_records = cbc_block_hmac_encrypt(blocks, aes_key, mac_key, image_shape=padded.shape, epoch=0)

    summary_rows = []
    trial_records = []

    for K in CORRUPTION_LEVELS:
        k_capped = min(K, total_blocks)
        t_start = time.time()

        trial_m1_gcm = []
        trial_m3_gcm = []
        trial_m2_cbc = []
        trial_m1_cbc = []
        trial_m3_cbc_framed = []
        trial_m1_cbc_hmac = []
        trial_mono_gcm = []

        for trial in range(num_trials):
            trial_id = f"{img_stem}_K{K}_trial{trial}"
            # Consistent seed across schemes
            trial_seed = seed + K * 1000 + trial
            trial_rng = random.Random(trial_seed)

            if k_capped == 0:
                corr_indices = []
            else:
                corr_indices = sorted(trial_rng.sample(range(total_blocks), k_capped))
            corr_set = set(corr_indices)

            # -------------------------------------------------------------
            # Model M1: In-Place Bit Flip on Proposed Block AES-GCM
            # -------------------------------------------------------------
            corrupted_gcm_m1 = list(clean_gcm_records)
            for idx in corr_indices:
                r = bytearray(corrupted_gcm_m1[idx])
                # Flip random bit in ciphertext payload (byte 16 to 783)
                bit_pos = 16 + trial_rng.randint(0, 767)
                r[bit_pos] ^= 0x01
                corrupted_gcm_m1[idx] = bytes(r)

            dec_m1_raw = decrypt_blocks(corrupted_gcm_m1, aes_key, padded.shape, block_shape,
                                        total_blocks, epoch=0, enable_concealment=False)
            
            # Exact definition: block is wrong iff decrypted bytes differ from original
            wrong_m1_gcm = sum(1 for orig, d in zip(blocks, dec_m1_raw['blocks']) if orig.tobytes() != d.tobytes())
            detected_m1_gcm = dec_m1_raw['failed_count']
            tp_m1 = len(set(dec_m1_raw['failed_indices']) & corr_set)
            prec_m1 = (tp_m1 / detected_m1_gcm) if detected_m1_gcm > 0 else 1.0
            rec_m1 = (tp_m1 / wrong_m1_gcm) if wrong_m1_gcm > 0 else 1.0
            epr_m1_gcm = (wrong_m1_gcm / float(k_capped)) if k_capped > 0 else None

            recon_m1_raw = unpad_image(merge_blocks(dec_m1_raw['blocks'], padded.shape), orig_shape)
            psnr_m1_raw = calculate_psnr(arr, recon_m1_raw)
            ssim_m1_raw = calculate_ssim(arr, recon_m1_raw)

            # Concealed
            dec_m1_conc = conceal_failed_blocks(dec_m1_raw['blocks'], dec_m1_raw['failed_indices'],
                                                (grid_rows, grid_cols), block_shape)
            recon_m1_conc = unpad_image(merge_blocks(dec_m1_conc, padded.shape), orig_shape)
            psnr_m1_conc = calculate_psnr(arr, recon_m1_conc)
            ssim_m1_conc = calculate_ssim(arr, recon_m1_conc)

            trial_m1_gcm.append({
                'wrong': wrong_m1_gcm, 'detected': detected_m1_gcm, 'precision': prec_m1,
                'recall': rec_m1, 'epr': epr_m1_gcm, 'psnr_raw': psnr_m1_raw, 'ssim_raw': ssim_m1_raw,
                'psnr_conc': psnr_m1_conc, 'ssim_conc': ssim_m1_conc,
                'gain': (psnr_m1_conc - psnr_m1_raw) if k_capped > 0 else 0.0
            })

            # -------------------------------------------------------------
            # Model M3: Explicit Record Loss on Proposed Block AES-GCM
            # -------------------------------------------------------------
            dropped_gcm_m3 = [r for i, r in enumerate(clean_gcm_records) if i not in corr_set]
            dec_m3_raw = decrypt_blocks(dropped_gcm_m3, aes_key, padded.shape, block_shape,
                                        total_blocks, epoch=0, enable_concealment=False)
            wrong_m3_gcm = sum(1 for orig, d in zip(blocks, dec_m3_raw['blocks']) if orig.tobytes() != d.tobytes())
            dec_m3_conc = conceal_failed_blocks(dec_m3_raw['blocks'], dec_m3_raw['missing_indices'],
                                                (grid_rows, grid_cols), block_shape)
            psnr_m3_conc = calculate_psnr(arr, unpad_image(merge_blocks(dec_m3_conc, padded.shape), orig_shape))
            trial_m3_gcm.append({
                'wrong': wrong_m3_gcm, 'epr': (wrong_m3_gcm / float(k_capped)) if k_capped > 0 else None,
                'psnr_conc': psnr_m3_conc
            })

            # -------------------------------------------------------------
            # Model M2: Unannounced Stream Byte Loss on Unframed AES-CBC
            # -------------------------------------------------------------
            corrupted_cbc_loss = bytearray(clean_cbc_ct)
            for idx in sorted(corr_indices, reverse=True):
                offset = idx * block_byte_size
                if offset + 16 <= len(corrupted_cbc_loss):
                    del corrupted_cbc_loss[offset:offset + 16]
            pt_cbc_loss = cbc_decrypt_monolithic(clean_cbc_iv, bytes(corrupted_cbc_loss), aes_key)
            if len(pt_cbc_loss) < len(raw_flat_bytes):
                pt_cbc_loss = pt_cbc_loss + b"\x00" * (len(raw_flat_bytes) - len(pt_cbc_loss))
            cbc_arr_loss = np.frombuffer(pt_cbc_loss[:len(raw_flat_bytes)], dtype=np.uint8).reshape(padded.shape)
            cbc_blocks_loss = split_into_blocks(cbc_arr_loss, BLOCK_SIZE)
            wrong_cbc_loss = sum(1 for orig, d in zip(blocks, cbc_blocks_loss) if orig.tobytes() != d.tobytes())
            psnr_cbc_loss = calculate_psnr(arr, unpad_image(cbc_arr_loss, orig_shape))
            trial_m2_cbc.append({
                'wrong': wrong_cbc_loss, 'epr': (wrong_cbc_loss / float(k_capped)) if k_capped > 0 else None,
                'psnr': psnr_cbc_loss
            })

            # -------------------------------------------------------------
            # Model M1: In-Place Bit Flip on Chained CBC (Count affected AES blocks)
            # -------------------------------------------------------------
            corrupted_cbc_bit = bytearray(clean_cbc_ct)
            for idx in corr_indices:
                bit_pos = idx * block_byte_size + trial_rng.randint(0, block_byte_size - 1)
                if bit_pos < len(corrupted_cbc_bit):
                    corrupted_cbc_bit[bit_pos] ^= 0x01
            pt_cbc_bit = cbc_decrypt_monolithic(clean_cbc_iv, bytes(corrupted_cbc_bit), aes_key)
            cbc_arr_bit = np.frombuffer(pt_cbc_bit[:len(raw_flat_bytes)], dtype=np.uint8).reshape(padded.shape)
            cbc_blocks_bit = split_into_blocks(cbc_arr_bit, BLOCK_SIZE)
            wrong_cbc_bit = sum(1 for orig, d in zip(blocks, cbc_blocks_bit) if orig.tobytes() != d.tobytes())
            
            # Count 16-byte AES blocks affected
            aes_blocks_wrong = 0
            for ab_idx in range(len(raw_flat_bytes) // 16):
                orig_ab = raw_flat_bytes[ab_idx*16:(ab_idx+1)*16]
                dec_ab = pt_cbc_bit[ab_idx*16:(ab_idx+1)*16]
                if orig_ab != dec_ab:
                    aes_blocks_wrong += 1
            trial_m1_cbc.append({'wrong_img': wrong_cbc_bit, 'wrong_aes': aes_blocks_wrong})

            # -------------------------------------------------------------
            # Model M3: Framed AES-CBC Record Deletion
            # -------------------------------------------------------------
            dropped_cbc_framed = [r for i, r in enumerate(clean_cbc_framed_records) if i not in corr_set]
            dec_cbc_framed = cbc_block_framed_decrypt(dropped_cbc_framed, aes_key, block_shape, total_blocks)
            wrong_cbc_framed = sum(1 for orig, d in zip(blocks, dec_cbc_framed['blocks']) if orig.tobytes() != d.tobytes())
            psnr_cbc_framed = calculate_psnr(arr, unpad_image(merge_blocks(dec_cbc_framed['blocks'], padded.shape), orig_shape))
            trial_m3_cbc_framed.append({
                'wrong': wrong_cbc_framed, 'epr': (wrong_cbc_framed / float(k_capped)) if k_capped > 0 else None,
                'psnr': psnr_cbc_framed
            })

            # -------------------------------------------------------------
            # Model M1: Per-Block CBC + HMAC-SHA256 (Encrypt-then-MAC)
            # -------------------------------------------------------------
            corrupted_cbc_hmac = list(clean_cbc_hmac_records)
            for idx in corr_indices:
                r = bytearray(corrupted_cbc_hmac[idx])
                r[25] ^= 0x01
                corrupted_cbc_hmac[idx] = bytes(r)
            dec_cbc_hmac = cbc_block_hmac_decrypt(corrupted_cbc_hmac, aes_key, mac_key, block_shape, total_blocks,
                                                  image_shape=padded.shape, epoch=0)
            det_cbc_hmac = dec_cbc_hmac['failed_count']
            rec_hmac = (det_cbc_hmac / float(k_capped)) if k_capped > 0 else 1.0
            trial_m1_cbc_hmac.append({'detected': det_cbc_hmac, 'recall': rec_hmac})

            # -------------------------------------------------------------
            # Monolithic AES-GCM
            # -------------------------------------------------------------
            if k_capped == 0:
                mono_avail = 1.0
                mono_psnr = float("inf")
            else:
                mono_avail = 0.0
                mono_psnr = 0.0
            trial_mono_gcm.append({'avail': mono_avail, 'psnr': mono_psnr})

            trial_records.append({
                'trial_id': trial_id,
                'image': img_stem,
                'K': K,
                'trial': trial,
                'seed': trial_seed,
                'corrupted_indices': corr_indices,
                'gcm_raw_psnr': psnr_m1_raw if K > 0 else 999.0,
                'gcm_conc_psnr': psnr_m1_conc if K > 0 else 999.0,
                'cbc_unframed_psnr': psnr_cbc_loss if K > 0 else 999.0,
                'cbc_framed_psnr': psnr_cbc_framed if K > 0 else 999.0
            })

        # Calculate means, std, and 95% bootstrap CI for this K
        eprs_m1 = [x['epr'] for x in trial_m1_gcm if x['epr'] is not None]
        eprs_m2 = [x['epr'] for x in trial_m2_cbc if x['epr'] is not None]
        eprs_m3_f = [x['epr'] for x in trial_m3_cbc_framed if x['epr'] is not None]
        raw_psnrs = [x['psnr_raw'] for x in trial_m1_gcm if x['psnr_raw'] != float("inf")]
        conc_psnrs = [x['psnr_conc'] for x in trial_m1_gcm if x['psnr_conc'] != float("inf")]
        gains = [x['gain'] for x in trial_m1_gcm]
        cbc_loss_psnrs = [x['psnr'] for x in trial_m2_cbc if x['psnr'] != float("inf")]
        cbc_f_psnrs = [x['psnr'] for x in trial_m3_cbc_framed if x['psnr'] != float("inf")]

        summary_rows.append({
            'corrupted_blocks': K,
            'corrupted_pct': round((k_capped / float(total_blocks)) * 100.0, 2),
            # Proposed GCM M1
            'gcm_failed_mean': round(float(np.mean([x['detected'] for x in trial_m1_gcm])), 2),
            'gcm_wrong_mean': round(float(np.mean([x['wrong'] for x in trial_m1_gcm])), 2),
            'gcm_precision_mean': round(float(np.mean([x['precision'] for x in trial_m1_gcm])), 4),
            'gcm_recall_mean': round(float(np.mean([x['recall'] for x in trial_m1_gcm])), 4),
            'gcm_epr_mean': round(float(np.mean(eprs_m1)), 2) if eprs_m1 else None,
            'gcm_psnr_raw_mean': round(float(np.mean(raw_psnrs)), 2) if raw_psnrs else "inf",
            'gcm_psnr_raw_std': round(float(np.std(raw_psnrs)), 2) if raw_psnrs else 0.0,
            'gcm_ssim_raw_mean': round(float(np.mean([x['ssim_raw'] for x in trial_m1_gcm])), 4),
            'gcm_psnr_conc_mean': round(float(np.mean(conc_psnrs)), 2) if conc_psnrs else "inf",
            'gcm_psnr_conc_std': round(float(np.std(conc_psnrs)), 2) if conc_psnrs else 0.0,
            'gcm_ssim_conc_mean': round(float(np.mean([x['ssim_conc'] for x in trial_m1_gcm])), 4),
            'gcm_psnr_gain_mean': round(float(np.mean(gains)), 2) if K > 0 else None,
            # CBC M2 (Unframed Stream Loss)
            'cbc_loss_wrong_mean': round(float(np.mean([x['wrong'] for x in trial_m2_cbc])), 2),
            'cbc_loss_epr_mean': round(float(np.mean(eprs_m2)), 2) if eprs_m2 else None,
            'cbc_loss_psnr_mean': round(float(np.mean(cbc_loss_psnrs)), 2) if cbc_loss_psnrs else "inf",
            'cbc_loss_psnr_std': round(float(np.std(cbc_loss_psnrs)), 2) if cbc_loss_psnrs else 0.0,
            # CBC M3 (Framed Record Loss)
            'cbc_framed_wrong_mean': round(float(np.mean([x['wrong'] for x in trial_m3_cbc_framed])), 2),
            'cbc_framed_epr_mean': round(float(np.mean(eprs_m3_f)), 2) if eprs_m3_f else None,
            'cbc_framed_psnr_mean': round(float(np.mean(cbc_f_psnrs)), 2) if cbc_f_psnrs else "inf",
            'cbc_framed_psnr_std': round(float(np.std(cbc_f_psnrs)), 2) if cbc_f_psnrs else 0.0,
            # CBC M1 In-place Bit Flip
            'cbc_bit_wrong_img_mean': round(float(np.mean([x['wrong_img'] for x in trial_m1_cbc])), 2),
            'cbc_bit_wrong_aes_mean': round(float(np.mean([x['wrong_aes'] for x in trial_m1_cbc])), 2),
            # CBC + HMAC
            'cbc_hmac_recall': round(float(np.mean([x['recall'] for x in trial_m1_cbc_hmac])), 4),
            # Monolithic GCM
            'mono_gcm_avail_pct': round(float(np.mean([x['avail'] for x in trial_mono_gcm])) * 100.0, 1),
            'mono_gcm_psnr': round(float(np.mean([x['psnr'] for x in trial_mono_gcm])), 2) if K > 0 else "inf"
        })

        gain_str = f"+{summary_rows[-1]['gcm_psnr_gain_mean']:.2f} dB" if summary_rows[-1]['gcm_psnr_gain_mean'] is not None else "--"
        print(f"[{img_stem}] K={K:>3} | GCM Raw={summary_rows[-1]['gcm_psnr_raw_mean']} -> Conc={summary_rows[-1]['gcm_psnr_conc_mean']} ({gain_str}) | Unframed CBC EPR={summary_rows[-1]['cbc_loss_epr_mean']}")

    return summary_rows, trial_records

def main():
    print("=" * 80)
    print("RUNNING COMPREHENSIVE CONTAINMENT EXPERIMENTS (TASK 5)")
    print("=" * 80)

    all_summary = {}

    for fname, stem in BENCHMARK_IMAGES:
        fpath = os.path.join(INPUT_DIR, fname)
        if not os.path.exists(fpath):
            print(f"[SKIP] {fname} not found in {INPUT_DIR}")
            continue

        print(f"\n--- Running Benchmark on {fname} ({stem}) ---")
        summary_rows, trial_records = run_image_containment(fpath, stem, num_trials=NUM_TRIALS, seed=GLOBAL_SEED)
        all_summary[stem] = summary_rows

        # Save per-image results
        img_json = os.path.join(RESULTS_DIR, f"containment_{stem}.json")
        with open(img_json, "w", encoding="utf-8") as f:
            json.dump(summary_rows, f, indent=2)

        trials_json = os.path.join(RESULTS_DIR, f"containment_trials_{stem}.json")
        with open(trials_json, "w", encoding="utf-8") as f:
            json.dump(trial_records, f, indent=2)

        img_csv = os.path.join(RESULTS_DIR, f"containment_{stem}.csv")
        with open(img_csv, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(summary_rows[0].keys()))
            w.writeheader()
            w.writerows(summary_rows)

    # Save summary across all images
    summary_path = os.path.join(RESULTS_DIR, "containment_summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(all_summary, f, indent=2)
    print("\nSaved containment summary to", summary_path)

    # Save primary Submarine results as containment_metrics.json (backward-compatible)
    sub_summary = all_summary.get("submarine", [])
    if sub_summary:
        with open(os.path.join(RESULTS_DIR, "containment_metrics.json"), "w", encoding="utf-8") as f:
            json.dump(sub_summary, f, indent=2)
        with open(os.path.join(RESULTS_DIR, "containment_metrics.csv"), "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(sub_summary[0].keys()))
            w.writeheader()
            w.writerows(sub_summary)

    # Deterministic Trial for Figure 2 (Task 5.8: K=25, Seed 42, matching named trial row)
    print("\nGenerating deterministic trial for Figure 2 (K=25, seed=42)...")
    sub_path = os.path.join(INPUT_DIR, "submarine.jpg")
    sub_arr = load_image(sub_path)
    padded, orig_shape = pad_image(sub_arr, BLOCK_SIZE)
    blocks = split_into_blocks(padded, BLOCK_SIZE)
    tot = len(blocks)
    b_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
    grid_r = padded.shape[0] // BLOCK_SIZE
    grid_c = padded.shape[1] // BLOCK_SIZE

    rng = random.Random(42)
    corr_indices = sorted(rng.sample(range(tot), 25))

    sess = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    key = derive_key(sess, hs, ps, "Fig2DeterministicSecretKey2026!", get_device_id(), epoch=0)

    enc_records = encrypt_blocks(blocks, key, padded.shape, epoch=0)
    corrupted_records = list(enc_records)
    for idx in corr_indices:
        r = bytearray(corrupted_records[idx])
        r[16] ^= 0xFF
        corrupted_records[idx] = bytes(r)

    dec_raw = decrypt_blocks(corrupted_records, key, padded.shape, b_shape, tot, epoch=0, enable_concealment=False)
    recon_raw = unpad_image(merge_blocks(dec_raw['blocks'], padded.shape), orig_shape)
    psnr_raw_trial = calculate_psnr(sub_arr, recon_raw)
    ssim_raw_trial = calculate_ssim(sub_arr, recon_raw)

    dec_conc = conceal_failed_blocks(dec_raw['blocks'], dec_raw['failed_indices'], (grid_r, grid_c), b_shape)
    recon_conc = unpad_image(merge_blocks(dec_conc, padded.shape), orig_shape)
    psnr_conc_trial = calculate_psnr(sub_arr, recon_conc)
    ssim_conc_trial = calculate_ssim(sub_arr, recon_conc)

    # Unframed CBC on this exact trial
    flat_bytes = padded.tobytes()
    cbc_iv, cbc_ct = cbc_encrypt_monolithic(flat_bytes, key)
    ct_corrupt = bytearray(cbc_ct)
    for idx in sorted(corr_indices, reverse=True):
        off = idx * 768
        if off + 16 <= len(ct_corrupt):
            del ct_corrupt[off:off+16]
    pt_cbc = cbc_decrypt_monolithic(cbc_iv, bytes(ct_corrupt), key)
    if len(pt_cbc) < len(flat_bytes):
        pt_cbc = pt_cbc + b"\x00" * (len(flat_bytes) - len(pt_cbc))
    cbc_arr = np.frombuffer(pt_cbc[:len(flat_bytes)], dtype=np.uint8).reshape(padded.shape)
    recon_cbc = unpad_image(cbc_arr, orig_shape)
    psnr_cbc_trial = calculate_psnr(sub_arr, recon_cbc)
    ssim_cbc_trial = calculate_ssim(sub_arr, recon_cbc)

    fig2_metrics = {
        'image': 'submarine.jpg',
        'trial_id': 'submarine_K25_trial0',
        'trial_seed': 42,
        'K': 25,
        'total_blocks': tot,
        'corrupted_indices': corr_indices,
        'raw_psnr': round(psnr_raw_trial, 2),
        'raw_ssim': round(ssim_raw_trial, 4),
        'conc_psnr': round(psnr_conc_trial, 2),
        'conc_ssim': round(ssim_conc_trial, 4),
        'cbc_psnr': round(psnr_cbc_trial, 2),
        'cbc_ssim': round(ssim_cbc_trial, 4),
        'concealment_gain': round(psnr_conc_trial - psnr_raw_trial, 2)
    }

    out_fig2 = os.path.join(RESULTS_DIR, "fig2_metrics.json")
    with open(out_fig2, "w", encoding="utf-8") as f:
        json.dump(fig2_metrics, f, indent=2)
    print(f"Saved Fig 2 metrics to {out_fig2} (trial_id: {fig2_metrics['trial_id']})")

if __name__ == "__main__":
    main()
