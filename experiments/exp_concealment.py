import os
import sys
import json
import csv
import random
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, unpad_image, split_into_blocks, merge_blocks
from src.encryption import encrypt_blocks
from src.decryption import decrypt_blocks
from src.record_format import pack_record, unpack_record
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id
from src.error_concealment import conceal_failed_blocks, mean_color_fill
from src.image_crypto_metrics import calculate_psnr, calculate_ssim

CORRUPTION_LEVELS = [10, 25, 50, 100, 200]
NUM_TRIALS = 30

def run_concealment_evaluation(seed=GLOBAL_SEED):
    np.random.seed(seed)
    image_names = [
        'cameraman_256.png',
        'baboon_texture_512.png',
        'peppers_color_512.png',
        'medical_mri_512.png',
        'satellite_aerial_1024.png',
        'submarine.jpg'
    ]
    
    device_id = get_device_id()
    passphrase = "ConcealmentEvaluationPassphrase2026!"
    session_key = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    aes_key = derive_key(session_key, hs, ps, passphrase, device_id, epoch=0)
    
    results = []
    
    print("=" * 80)
    print("RUNNING CONCEALMENT BENCHMARK ACROSS 6 IMAGES (30 TRIALS PER LEVEL)")
    print("=" * 80)
    
    for filename in image_names:
        img_path = os.path.join(INPUT_DIR, filename)
        if not os.path.exists(img_path):
            continue
            
        arr = load_image(img_path)
        orig_h, orig_w, channels = arr.shape
        padded, orig_shape = pad_image(arr, BLOCK_SIZE)
        blocks = split_into_blocks(padded, BLOCK_SIZE)
        total_blocks = len(blocks)
        grid_rows = padded.shape[0] // BLOCK_SIZE
        grid_cols = padded.shape[1] // BLOCK_SIZE
        block_shape = (BLOCK_SIZE, BLOCK_SIZE, channels)
        
        clean_records = encrypt_blocks(blocks, aes_key, padded.shape, epoch=0)
        
        for K in CORRUPTION_LEVELS:
            k_capped = min(K, total_blocks)
            
            psnr_zero_list = []
            ssim_zero_list = []
            psnr_mean_list = []
            ssim_mean_list = []
            psnr_conc_list = []
            ssim_conc_list = []
            
            for t in range(NUM_TRIALS):
                trial_seed = seed + K * 500 + t
                trial_rng = random.Random(trial_seed)
                corr_indices = sorted(trial_rng.sample(range(total_blocks), k_capped))
                
                corrupted_records = list(clean_records)
                for idx in corr_indices:
                    r = bytearray(corrupted_records[idx])
                    r[16] ^= 0xFF
                    corrupted_records[idx] = bytes(r)
                    
                dec_res = decrypt_blocks(corrupted_records, aes_key, padded.shape, block_shape,
                                         total_blocks, epoch=0, enable_concealment=False)
                
                # 1. Zero-mask
                recon_zero = unpad_image(merge_blocks(dec_res['blocks'], padded.shape), orig_shape)
                psnr_zero = calculate_psnr(arr, recon_zero)
                ssim_zero = calculate_ssim(arr, recon_zero)
                psnr_zero_list.append(psnr_zero)
                ssim_zero_list.append(ssim_zero)
                
                # 2. Mean fill
                mean_blocks = mean_color_fill(dec_res['blocks'], dec_res['failed_indices'],
                                              (grid_rows, grid_cols), block_shape)
                recon_mean = unpad_image(merge_blocks(mean_blocks, padded.shape), orig_shape)
                psnr_mean = calculate_psnr(arr, recon_mean)
                ssim_mean = calculate_ssim(arr, recon_mean)
                psnr_mean_list.append(psnr_mean)
                ssim_mean_list.append(ssim_mean)
                
                # 3. Proposed boundary interpolation
                conc_blocks, mask = conceal_failed_blocks(dec_res['blocks'], dec_res['failed_indices'],
                                                          (grid_rows, grid_cols), block_shape, return_mask=True)
                recon_conc = unpad_image(merge_blocks(conc_blocks, padded.shape), orig_shape)
                psnr_conc = calculate_psnr(arr, recon_conc)
                ssim_conc = calculate_ssim(arr, recon_conc)
                psnr_conc_list.append(psnr_conc)
                ssim_conc_list.append(ssim_conc)
                
            entry = {
                'image': filename,
                'dimensions': f"{orig_w}x{orig_h}",
                'total_blocks': total_blocks,
                'K': k_capped,
                'corruption_pct': round((k_capped / float(total_blocks)) * 100.0, 2),
                'psnr_zero_mean': round(float(np.mean(psnr_zero_list)), 2),
                'psnr_zero_std': round(float(np.std(psnr_zero_list)), 2),
                'ssim_zero_mean': round(float(np.mean(ssim_zero_list)), 4),
                'psnr_mean_fill_mean': round(float(np.mean(psnr_mean_list)), 2),
                'psnr_mean_fill_std': round(float(np.std(psnr_mean_list)), 2),
                'ssim_mean_fill_mean': round(float(np.mean(ssim_mean_list)), 4),
                'psnr_conc_mean': round(float(np.mean(psnr_conc_list)), 2),
                'psnr_conc_std': round(float(np.std(psnr_conc_list)), 2),
                'ssim_conc_mean': round(float(np.mean(ssim_conc_list)), 4),
                'psnr_gain_mean': round(float(np.mean(np.array(psnr_conc_list) - np.array(psnr_zero_list))), 2)
            }
            results.append(entry)
            print(f"[{filename:<26}] K = {k_capped:>3} ({entry['corruption_pct']:>5.2f}%) | Zero: {entry['psnr_zero_mean']} dB -> Mean: {entry['psnr_mean_fill_mean']} dB -> Proposed Conc: {entry['psnr_conc_mean']} dB (+{entry['psnr_gain_mean']} dB)")
            
    out_json = os.path.join(RESULTS_DIR, "concealment_metrics.json")
    with open(out_json, "w") as f:
        json.dump(results, f, indent=2)
    print("\nSaved concealment metrics to", out_json)
    
    out_csv = os.path.join(RESULTS_DIR, "concealment_metrics.csv")
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print("Saved concealment CSV to", out_csv)
    return results

if __name__ == "__main__":
    run_concealment_evaluation()

