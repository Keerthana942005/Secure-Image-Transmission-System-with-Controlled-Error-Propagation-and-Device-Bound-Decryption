import os
import sys
import json
import csv
import hashlib
import numpy as np
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, split_into_blocks
from src.encryption import encrypt_blocks
from src.record_format import unpack_record, build_aad
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id
from src.image_crypto_metrics import (
    calculate_entropy,
    calculate_npcr,
    calculate_uaci,
    calculate_correlation,
    calculate_chi_square
)
from src.baseline_ciphers import (
    cbc_encrypt_monolithic
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

BENCHMARK_IMAGES = [
    'submarine.jpg',
    'cameraman_256.png',
    'baboon_texture_512.png',
    'peppers_color_512.png',
    'medical_mri_512.png',
    'satellite_aerial_1024.png'
]

def generate_dataset_manifest() -> list[dict]:
    """Generates results/dataset_manifest.json for all 6 benchmark images with size,
    SHA-256, dimensions, colour mode, block counts, and TODO_USER fields.
    """
    manifest = []
    for fn in BENCHMARK_IMAGES:
        fp = os.path.join(INPUT_DIR, fn)
        if not os.path.exists(fp):
            continue
            
        with open(fp, 'rb') as f:
            data = f.read()
            digest = hashlib.sha256(data).hexdigest()
            size_bytes = len(data)
            
        im = Image.open(fp)
        w, h = im.size
        mode = im.mode
        
        arr = load_image(fp)
        padded, _ = pad_image(arr, BLOCK_SIZE)
        pad_h, pad_w = padded.shape[0], padded.shape[1]
        blocks = split_into_blocks(padded, BLOCK_SIZE)
        
        entry = {
            'filename': fn,
            'dimensions': f"{w}x{h}",
            'width': w,
            'height': h,
            'channels': arr.shape[2] if arr.ndim == 3 else 1,
            'color_mode': mode,
            'size_bytes': size_bytes,
            'sha256': digest,
            'padded_dimensions': f"{pad_w}x{pad_h}",
            'total_blocks': len(blocks),
            'source': 'TODO_USER',
            'license': 'TODO_USER'
        }
        manifest.append(entry)
        
    out_manifest = os.path.join(RESULTS_DIR, "dataset_manifest.json")
    with open(out_manifest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"Generated dataset manifest at {out_manifest} ({len(manifest)} images)")
    return manifest

def run_crypto_evaluation(num_perturbations=1000, seed=GLOBAL_SEED):
    print("=" * 80)
    print("RUNNING CRYPTOGRAPHIC & STATISTICAL RANDOMNESS EXPERIMENTS (TASK 8)")
    print("=" * 80)
    
    # 1. Dataset Manifest
    generate_dataset_manifest()
    
    device_id = get_device_id()
    passphrase = "EvaluationSecretPassphrase2026!"
    session_key = generate_session_key()
    hkdf_salt = generate_salt()
    pw_salt = generate_salt()
    aes_key = derive_key(session_key, hkdf_salt, pw_salt, passphrase, device_id, epoch=0)
    aesgcm = AESGCM(aes_key)
    
    # 1-bit flipped key for key sensitivity tests
    key_flipped = bytearray(aes_key)
    key_flipped[0] ^= 0x01
    aesgcm_flipped = AESGCM(bytes(key_flipped))
    
    gcm_results = []
    cbc_results = []
    
    for filename in BENCHMARK_IMAGES:
        img_path = os.path.join(INPUT_DIR, filename)
        if not os.path.exists(img_path):
            print(f"Skipping {filename}: not found")
            continue
            
        arr = load_image(img_path)
        orig_h, orig_w, channels = arr.shape
        padded, orig_shape = pad_image(arr, BLOCK_SIZE)
        blocks = split_into_blocks(padded, BLOCK_SIZE)
        total_blocks = len(blocks)
        pad_h, pad_w = padded.shape[0], padded.shape[1]
        grid_cols = pad_w // BLOCK_SIZE
        total_image_pixels = orig_h * orig_w * channels
        block_pixels = BLOCK_SIZE * BLOCK_SIZE * channels
        raw_flat_bytes = padded.tobytes()
        
        # -------------------------------------------------------------
        # 1. Plaintext Metrics
        # -------------------------------------------------------------
        plain_entropy = calculate_entropy(arr)
        plain_corr = calculate_correlation(arr, seed=seed, num_samples=4000)
        max_plain_corr = max(abs(plain_corr['horizontal']), abs(plain_corr['vertical']), abs(plain_corr['diagonal']))
        
        # -------------------------------------------------------------
        # 2. Proposed Block AES-GCM Ciphertext Metrics
        # -------------------------------------------------------------
        enc_records = encrypt_blocks(blocks, aes_key, padded.shape, epoch=0, deterministic_nonce=False)
        ct_payloads = [unpack_record(r)[2] for r in enc_records]
        ct_bytes = b"".join(ct_payloads)
        ct_arr = np.frombuffer(ct_bytes[:orig_h * orig_w * channels], dtype=np.uint8).reshape((orig_h, orig_w, channels))
        
        cipher_entropy = calculate_entropy(ct_arr)
        cipher_corr = calculate_correlation(ct_arr, seed=seed, num_samples=4000)
        max_cipher_corr = max(abs(cipher_corr['horizontal']), abs(cipher_corr['vertical']), abs(cipher_corr['diagonal']))
        chi_sq = calculate_chi_square(ct_arr)
        
        # Key sensitivity on proposed GCM
        enc_records_flipped = encrypt_blocks(blocks, bytes(key_flipped), padded.shape, epoch=0, deterministic_nonce=False)
        ct_flipped_bytes = b"".join([unpack_record(r)[2] for r in enc_records_flipped])
        ct_flipped_arr = np.frombuffer(ct_flipped_bytes[:orig_h * orig_w * channels], dtype=np.uint8).reshape((orig_h, orig_w, channels))
        key_sens_npcr_gcm = calculate_npcr(ct_arr, ct_flipped_arr)
        key_sens_uaci_gcm = calculate_uaci(ct_arr, ct_flipped_arr)
        
        # -------------------------------------------------------------
        # 3. Fast Exact NPCR/UACI Evaluation Across num_perturbations (GCM)
        # -------------------------------------------------------------
        rng = np.random.RandomState(seed)
        block_npcrs_rand = []
        block_uacis_rand = []
        image_npcrs_rand = []
        image_uacis_rand = []
        
        block_npcrs_fixed = []
        block_uacis_fixed = []
        image_npcrs_fixed = []
        image_uacis_fixed = []
        
        sample_ys = rng.randint(0, orig_h, size=num_perturbations)
        sample_xs = rng.randint(0, orig_w, size=num_perturbations)
        sample_cs = rng.randint(0, channels, size=num_perturbations)
        sample_bits = rng.randint(0, 8, size=num_perturbations)
        
        for i in range(num_perturbations):
            y, x, c, bit = sample_ys[i], sample_xs[i], sample_cs[i], sample_bits[i]
            by = y // BLOCK_SIZE
            bx = x // BLOCK_SIZE
            target_block_idx = by * grid_cols + bx
            
            ly = y % BLOCK_SIZE
            lx = x % BLOCK_SIZE
            
            target_block = blocks[target_block_idx].copy()
            target_block[ly, lx, c] ^= (1 << bit)
            
            aad = build_aad(target_block_idx, pad_h, pad_w, total_blocks, 0)
            orig_rec = enc_records[target_block_idx]
            _, orig_nonce, orig_ct, orig_tag = unpack_record(orig_rec)
            c1_block = np.frombuffer(orig_ct, dtype=np.uint8)
            
            # (a) Random-nonce encryption (Transmission setting)
            new_nonce = os.urandom(12)
            c2_rand_bytes = aesgcm.encrypt(new_nonce, target_block.tobytes(), aad)[:-16]
            c2_block_rand = np.frombuffer(c2_rand_bytes, dtype=np.uint8)
            
            diff_rand = (c1_block != c2_block_rand).astype(np.float64)
            diff_abs_rand = np.abs(c1_block.astype(np.float64) - c2_block_rand.astype(np.float64))
            
            b_npcr_r = (np.sum(diff_rand) / float(block_pixels)) * 100.0
            b_uaci_r = (np.sum(diff_abs_rand) / (float(block_pixels) * 255.0)) * 100.0
            block_npcrs_rand.append(b_npcr_r)
            block_uacis_rand.append(b_uaci_r)
            
            img_npcr_r = (np.sum(diff_rand) / float(total_image_pixels)) * 100.0
            img_uaci_r = (np.sum(diff_abs_rand) / (float(total_image_pixels) * 255.0)) * 100.0
            image_npcrs_rand.append(img_npcr_r)
            image_uacis_rand.append(img_uaci_r)
            
            # (b) Fixed-nonce encryption (CTR counter mode property)
            c2_fixed_bytes = aesgcm.encrypt(orig_nonce, target_block.tobytes(), aad)[:-16]
            c2_block_fixed = np.frombuffer(c2_fixed_bytes, dtype=np.uint8)
            
            diff_fixed = (c1_block != c2_block_fixed).astype(np.float64)
            diff_abs_fixed = np.abs(c1_block.astype(np.float64) - c2_block_fixed.astype(np.float64))
            
            b_npcr_f = (np.sum(diff_fixed) / float(block_pixels)) * 100.0
            b_uaci_f = (np.sum(diff_abs_fixed) / (float(block_pixels) * 255.0)) * 100.0
            block_npcrs_fixed.append(b_npcr_f)
            block_uacis_fixed.append(b_uaci_f)
            
            img_npcr_f = (np.sum(diff_fixed) / float(total_image_pixels)) * 100.0
            img_uaci_f = (np.sum(diff_abs_fixed) / (float(total_image_pixels) * 255.0)) * 100.0
            image_npcrs_fixed.append(img_npcr_f)
            image_uacis_fixed.append(img_uaci_f)
            
        gcm_entry = {
            'image': filename,
            'dimensions': f"{orig_w}x{orig_h}",
            'total_blocks': total_blocks,
            'plain_entropy_overall': round(plain_entropy['overall'], 4),
            'plain_entropy_channels': [round(x, 4) for x in plain_entropy['channels']],
            'cipher_entropy_overall': round(cipher_entropy['overall'], 4),
            'cipher_entropy_channels': [round(x, 4) for x in cipher_entropy['channels']],
            'max_theoretical_entropy': round(cipher_entropy['max_theoretical'], 4),
            'chi_square_stat': round(chi_sq, 2),
            'plain_corr_h': round(plain_corr['horizontal'], 4),
            'plain_corr_v': round(plain_corr['vertical'], 4),
            'plain_corr_d': round(plain_corr['diagonal'], 4),
            'plain_corr_max': round(max_plain_corr, 4),
            'cipher_corr_h': round(cipher_corr['horizontal'], 4),
            'cipher_corr_v': round(cipher_corr['vertical'], 4),
            'cipher_corr_d': round(cipher_corr['diagonal'], 4),
            'cipher_corr_max': round(max_cipher_corr, 4),
            # Random-nonce setting
            'block_npcr_rand_mean': round(float(np.mean(block_npcrs_rand)), 2),
            'block_npcr_rand_std': round(float(np.std(block_npcrs_rand)), 2),
            'block_uaci_rand_mean': round(float(np.mean(block_uacis_rand)), 2),
            'block_uaci_rand_std': round(float(np.std(block_uacis_rand)), 2),
            'image_npcr_rand_mean': round(float(np.mean(image_npcrs_rand)), 4),
            'image_uaci_rand_mean': round(float(np.mean(image_uacis_rand)), 4),
            # Fixed-nonce setting (CTR mode property)
            'block_npcr_fixed_mean': round(float(np.mean(block_npcrs_fixed)), 4),
            'block_uaci_fixed_mean': round(float(np.mean(block_uacis_fixed)), 4),
            'image_npcr_fixed_mean': round(float(np.mean(image_npcrs_fixed)), 6),
            'image_uaci_fixed_mean': round(float(np.mean(image_uacis_fixed)), 6),
            # Key sensitivity
            'key_sensitivity_npcr': round(float(key_sens_npcr_gcm), 2),
            'key_sensitivity_uaci': round(float(key_sens_uaci_gcm), 2)
        }
        gcm_results.append(gcm_entry)
        
        # -------------------------------------------------------------
        # 4. Standard AES-CBC Baseline Metrics
        # -------------------------------------------------------------
        cbc_iv, cbc_ct = cbc_encrypt_monolithic(raw_flat_bytes, aes_key)
        cbc_ct_img = np.frombuffer(cbc_ct[:orig_h * orig_w * channels], dtype=np.uint8).reshape((orig_h, orig_w, channels))
        
        cbc_ent = calculate_entropy(cbc_ct_img)
        cbc_corr = calculate_correlation(cbc_ct_img, seed=seed, num_samples=4000)
        max_cbc_corr = max(abs(cbc_corr['horizontal']), abs(cbc_corr['vertical']), abs(cbc_corr['diagonal']))
        cbc_chi_sq = calculate_chi_square(cbc_ct_img)
        
        # Key sensitivity on CBC
        _, cbc_ct_flipped = cbc_encrypt_monolithic(raw_flat_bytes, bytes(key_flipped))
        cbc_ct_flipped_img = np.frombuffer(cbc_ct_flipped[:orig_h * orig_w * channels], dtype=np.uint8).reshape((orig_h, orig_w, channels))
        cbc_key_sens_npcr = calculate_npcr(cbc_ct_img, cbc_ct_flipped_img)
        cbc_key_sens_uaci = calculate_uaci(cbc_ct_img, cbc_ct_flipped_img)
        
        # CBC NPCR/UACI under 1-bit plaintext perturbations (random IV)
        cbc_npcrs = []
        cbc_uacis = []
        for i in range(min(num_perturbations, 200)):  # 200 perturbations for monolithic CBC
            y, x, c, bit = sample_ys[i], sample_xs[i], sample_cs[i], sample_bits[i]
            perturbed_raw = bytearray(raw_flat_bytes)
            idx = (y * pad_w + x) * channels + c
            if idx < len(perturbed_raw):
                perturbed_raw[idx] ^= (1 << bit)
            _, cbc_ct_p = cbc_encrypt_monolithic(bytes(perturbed_raw), aes_key)
            cbc_p_img = np.frombuffer(cbc_ct_p[:orig_h * orig_w * channels], dtype=np.uint8).reshape((orig_h, orig_w, channels))
            cbc_npcrs.append(calculate_npcr(cbc_ct_img, cbc_p_img))
            cbc_uacis.append(calculate_uaci(cbc_ct_img, cbc_p_img))
            
        cbc_entry = {
            'image': filename,
            'dimensions': f"{orig_w}x{orig_h}",
            'plain_entropy_overall': round(plain_entropy['overall'], 4),
            'cipher_entropy_overall': round(cbc_ent['overall'], 4),
            'cipher_entropy_channels': [round(x, 4) for x in cbc_ent['channels']],
            'chi_square_stat': round(cbc_chi_sq, 2),
            'cipher_corr_h': round(cbc_corr['horizontal'], 4),
            'cipher_corr_v': round(cbc_corr['vertical'], 4),
            'cipher_corr_d': round(cbc_corr['diagonal'], 4),
            'cipher_corr_max': round(max_cbc_corr, 4),
            'npcr_mean': round(float(np.mean(cbc_npcrs)), 2),
            'uaci_mean': round(float(np.mean(cbc_uacis)), 2),
            'key_sensitivity_npcr': round(float(cbc_key_sens_npcr), 2),
            'key_sensitivity_uaci': round(float(cbc_key_sens_uaci), 2)
        }
        cbc_results.append(cbc_entry)
        
        print(f"[{filename:<26}] GCM Entropy={gcm_entry['cipher_entropy_overall']:.4f} | Max|r|={gcm_entry['cipher_corr_max']:.4f} | ChiSq={gcm_entry['chi_square_stat']:.1f} | KeySens NPCR={gcm_entry['key_sensitivity_npcr']}%")

    # Save GCM metrics
    out_json = os.path.join(RESULTS_DIR, "crypto_metrics.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(gcm_results, f, indent=2)
    print("\nSaved crypto metrics to", out_json)
    
    out_csv = os.path.join(RESULTS_DIR, "crypto_metrics.csv")
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(gcm_results[0].keys()))
        writer.writeheader()
        writer.writerows(gcm_results)
    print("Saved crypto CSV to", out_csv)
    
    # Save CBC baseline metrics
    cbc_json = os.path.join(RESULTS_DIR, "crypto_metrics_cbc.json")
    with open(cbc_json, "w", encoding="utf-8") as f:
        json.dump(cbc_results, f, indent=2)
    print("Saved CBC crypto metrics to", cbc_json)
    
    cbc_csv = os.path.join(RESULTS_DIR, "crypto_metrics_cbc.csv")
    with open(cbc_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(cbc_results[0].keys()))
        writer.writeheader()
        writer.writerows(cbc_results)
    print("Saved CBC crypto CSV to", cbc_csv)
    
    return gcm_results, cbc_results

if __name__ == "__main__":
    run_crypto_evaluation(num_perturbations=1000)
