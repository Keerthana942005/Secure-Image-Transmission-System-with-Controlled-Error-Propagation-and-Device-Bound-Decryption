import os
import sys
import time
import json
import csv
import random
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, split_into_blocks, merge_blocks, unpad_image
from src.record_format import pack_record, unpack_record, build_aad
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id
from src.error_concealment import conceal_failed_blocks
from src.image_crypto_metrics import calculate_psnr, calculate_ssim
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BLOCK_SIZES = [8, 16, 32, 64]
AREA_FRACTIONS = [
    {'label': '1.0%', 'fraction': 0.010},
    {'label': '2.3%', 'fraction': 0.023},
    {'label': '4.6%', 'fraction': 0.046},
    {'label': '9.2%', 'fraction': 0.092}
]
NUM_TRIALS = 15

def run_blocksize_tradeoff_experiment(seed=GLOBAL_SEED):
    print("=" * 80)
    print("RUNNING BLOCK-SIZE TRADE-OFF EXPERIMENT (TASK 9.1)")
    print("Block Sizes: [8, 16, 32, 64] | Area Fractions: [1.0%, 2.3%, 4.6%, 9.2%]")
    print("=" * 80)
    
    sub_path = os.path.join(INPUT_DIR, 'submarine.jpg')
    sub_arr = load_image(sub_path)
    raw_h, raw_w, channels = sub_arr.shape
    raw_bytes = sub_arr.nbytes
    
    device_id = get_device_id()
    passphrase = "BlockSizeTradeoffPassphrase2026!"
    sess = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    aes_key = derive_key(sess, hs, ps, passphrase, device_id, epoch=0)
    aesgcm = AESGCM(aes_key)
    
    tradeoff_rows = []
    
    for bs in BLOCK_SIZES:
        padded, orig_shape = pad_image(sub_arr, bs)
        blocks = split_into_blocks(padded, bs)
        n_blocks = len(blocks)
        pad_h, pad_w = padded.shape[0], padded.shape[1]
        grid_rows = pad_h // bs
        grid_cols = pad_w // bs
        block_bytes = bs * bs * channels
        block_shape = (bs, bs, channels)
        
        # Overhead calculations
        framing_per_block = 32  # 4 index + 12 IV + 16 tag
        analytical_overhead_pct = (framing_per_block / float(block_bytes)) * 100.0
        total_framing_bytes = n_blocks * framing_per_block
        total_payload_bytes = padded.nbytes + total_framing_bytes
        total_overhead_pct = ((total_payload_bytes - raw_bytes) / float(raw_bytes)) * 100.0
        
        # Benchmark throughput for this block size
        enc_times = []
        for _ in range(10):
            t0 = time.perf_counter()
            for idx, b in enumerate(blocks):
                nonce = os.urandom(12)
                aad = build_aad(idx, pad_h, pad_w, n_blocks, 0)
                _ = aesgcm.encrypt(nonce, b.tobytes(), aad)
            enc_times.append((time.perf_counter() - t0) * 1000.0)
        throughput_mbps = round((raw_bytes / 1e6) / (np.mean(enc_times) / 1000.0), 1)
        
        print(f"\nEvaluating Block Size: {bs}x{bs} ({n_blocks} blocks, {analytical_overhead_pct:.2f}% framing, {throughput_mbps} MB/s)...")
        
        for af_cfg in AREA_FRACTIONS:
            af_label = af_cfg['label']
            af = af_cfg['fraction']
            k_blocks = max(1, int(round(n_blocks * af)))
            actual_pct = round((k_blocks / float(n_blocks)) * 100.0, 2)
            
            raw_psnrs = []
            conc_psnrs = []
            conc_ssims = []
            
            for t in range(NUM_TRIALS):
                trial_seed = seed + bs * 1000 + int(af * 10000) + t
                t_rng = random.Random(trial_seed)
                corr_indices = sorted(t_rng.sample(range(n_blocks), k_blocks))
                corr_set = set(corr_indices)
                
                # Zero-mask failed blocks
                zero_blocks = [b.copy() if i not in corr_set else np.zeros(block_shape, dtype=np.uint8)
                               for i, b in enumerate(blocks)]
                recon_zero = unpad_image(merge_blocks(zero_blocks, padded.shape, block_size=bs), orig_shape)
                psnr_raw = calculate_psnr(sub_arr, recon_zero)
                raw_psnrs.append(psnr_raw)
                
                # Spatial boundary concealment adapted to block size bs
                conc_blocks = conceal_failed_blocks(zero_blocks, corr_indices, (grid_rows, grid_cols), block_shape)
                recon_conc = unpad_image(merge_blocks(conc_blocks, padded.shape, block_size=bs), orig_shape)
                psnr_conc = calculate_psnr(sub_arr, recon_conc)
                ssim_conc = calculate_ssim(sub_arr, recon_conc)
                
                conc_psnrs.append(psnr_conc)
                conc_ssims.append(ssim_conc)
                
            mean_raw_psnr = round(float(np.mean(raw_psnrs)), 2)
            mean_conc_psnr = round(float(np.mean(conc_psnrs)), 2)
            mean_conc_ssim = round(float(np.mean(conc_ssims)), 4)
            gain = round(mean_conc_psnr - mean_raw_psnr, 2)
            
            entry = {
                'block_size': f"{bs}x{bs}",
                'block_dimension': bs,
                'total_blocks': n_blocks,
                'area_fraction_label': af_label,
                'area_fraction': af,
                'corrupted_blocks': k_blocks,
                'corrupted_fraction_pct': actual_pct,
                'analytical_overhead_pct': round(analytical_overhead_pct, 2),
                'total_overhead_pct': round(total_overhead_pct, 2),
                'throughput_decimal_mbps': throughput_mbps,
                'psnr_raw_mean': mean_raw_psnr,
                'psnr_conc_mean': mean_conc_psnr,
                'ssim_conc_mean': mean_conc_ssim,
                'concealment_gain_db': gain
            }
            tradeoff_rows.append(entry)
            print(f"  Area {af_label:<5} (K={k_blocks:>4} blocks, {actual_pct:>5.2f}%): Raw PSNR = {mean_raw_psnr:>5.2f} dB -> Conc = {mean_conc_psnr:>5.2f} dB (+{gain:>5.2f} dB) | SSIM = {mean_conc_ssim:.4f}")
            
    out_json = os.path.join(RESULTS_DIR, "blocksize_tradeoff.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(tradeoff_rows, f, indent=2)
    print(f"\nSaved block size trade-off JSON to {out_json}")
    
    out_csv = os.path.join(RESULTS_DIR, "blocksize_tradeoff.csv")
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(tradeoff_rows[0].keys()))
        writer.writeheader()
        writer.writerows(tradeoff_rows)
    print(f"Saved block size trade-off CSV to {out_csv}")
    return tradeoff_rows

if __name__ == "__main__":
    run_blocksize_tradeoff_experiment()

