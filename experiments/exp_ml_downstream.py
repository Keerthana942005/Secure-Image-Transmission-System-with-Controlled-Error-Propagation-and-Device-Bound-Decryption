import os
import sys
import json
import csv
import random
import time
import hashlib
import numpy as np
from PIL import Image
import onnxruntime as ort

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, RESULTS_DIR, MODELS_DIR, DATA_DIR
from src.image_processor import split_into_blocks, merge_blocks
from src.error_concealment import conceal_failed_blocks
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id
from src.baseline_ciphers import (
    cbc_encrypt_monolithic,
    cbc_decrypt_monolithic
)

# Corruption levels: 0.5% (1 block), 1.0% (2 blocks), 2.3% (5 blocks), 4.6% (9 blocks), 9.2% (18 blocks) of 196 blocks
CORRUPTION_CONFIGS = [
    {'label': '0.5% (1 block)', 'K': 1},
    {'label': '1.0% (2 blocks)', 'K': 2},
    {'label': '2.3% (5 blocks)', 'K': 5},
    {'label': '4.6% (9 blocks)', 'K': 9},
    {'label': '9.2% (18 blocks)', 'K': 18}
]

NUM_IMAGES = 500
NUM_TRIALS_PER_LEVEL = 10

def preprocess_image(img_pil: Image.Image) -> np.ndarray:
    """Preprocesses a PIL Image to normalized float32 tensor (1, 3, 224, 224)."""
    img_resized = img_pil.resize((224, 224), Image.Resampling.BILINEAR)
    arr = np.array(img_resized, dtype=np.float32) / 255.0
    mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
    std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
    norm = (arr - mean) / std
    return np.transpose(norm, (2, 0, 1))[np.newaxis, :, :, :]

def preprocess_array(arr_uint8: np.ndarray) -> np.ndarray:
    """Fast preprocessing directly from uint8 RGB array (224, 224, 3) to (1, 3, 224, 224) float32."""
    arr = arr_uint8.astype(np.float32) / 255.0
    mean = np.array([0.485, 0.456, 0.406], dtype=np.float32)
    std = np.array([0.229, 0.224, 0.225], dtype=np.float32)
    norm = (arr - mean) / std
    return np.transpose(norm, (2, 0, 1))[np.newaxis, :, :, :]

def bootstrap_ci(sample_binary: list[int], num_bootstraps: int = 1000, ci: float = 95.0, seed: int = 42) -> tuple[float, float]:
    """Computes bootstrap confidence interval on percentage agreement/accuracy."""
    if len(sample_binary) == 0:
        return 0.0, 0.0
    rng = np.random.RandomState(seed)
    n = len(sample_binary)
    arr = np.array(sample_binary, dtype=np.float64)
    boot_means = []
    for _ in range(num_bootstraps):
        resampled = rng.choice(arr, size=n, replace=True)
        boot_means.append(np.mean(resampled) * 100.0)
    lower = float(np.percentile(boot_means, (100.0 - ci) / 2.0))
    upper = float(np.percentile(boot_means, 100.0 - (100.0 - ci) / 2.0))
    return round(lower, 2), round(upper, 2)

def run_ml_downstream_experiment(seed=GLOBAL_SEED):
    # 1. Load ONNX MobileNetV2 session
    onnx_path = os.path.join(MODELS_DIR, 'mobilenetv2-7.onnx')
    if not os.path.exists(onnx_path):
        raise FileNotFoundError(f"Model not found at {onnx_path}")
        
    session = ort.InferenceSession(onnx_path, providers=['CPUExecutionProvider'])
    input_name = session.get_inputs()[0].name
    
    # 2. Load dataset of images from data/imagenet_subset.txt
    val_list_path = os.path.join(DATA_DIR, 'imagenet_subset.txt')
    img_dir = os.path.join(MODELS_DIR, 'imagenet-sample-images-master')
    
    if not os.path.exists(val_list_path):
        raise FileNotFoundError(f"Dataset manifest not found at {val_list_path}")
        
    with open(val_list_path, 'r', encoding='utf-8') as f:
        manifest_entries = [line.strip().split('  ') for line in f if line.strip()]
        
    print(f"Loaded {len(manifest_entries)} images from manifest {val_list_path}")
    
    # Verify hashes and preload 500 images
    clean_images_rgb = []
    clean_blocks_list = []
    clean_preds = []
    
    print("Verifying image hashes, pre-splitting blocks, and calculating clean baseline predictions...")
    t0 = time.time()
    for exp_hash, fn in manifest_entries[:NUM_IMAGES]:
        fp = os.path.join(img_dir, fn)
        with open(fp, 'rb') as f_img:
            actual_hash = hashlib.sha256(f_img.read()).hexdigest()
        assert actual_hash == exp_hash, f"SHA-256 hash mismatch for {fn}"
        
        im = Image.open(fp).convert('RGB').resize((224, 224), Image.Resampling.BILINEAR)
        arr = np.array(im, dtype=np.uint8)
        clean_images_rgb.append(arr)
        clean_blocks_list.append(split_into_blocks(arr, BLOCK_SIZE))
        
        tensor = preprocess_array(arr)
        logits = session.run(None, {input_name: tensor})[0]
        clean_preds.append(int(np.argmax(logits)))
        
    dt_prep = time.time() - t0
    print(f"Preloaded {len(clean_preds)} images in {dt_prep:.2f}s ({len(clean_preds)/dt_prep:.1f} img/s).")
    
    # Keys
    device_id = get_device_id()
    passphrase = "MLDownstreamSecretPassphrase2026!"
    sess = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    aes_key = derive_key(sess, hs, ps, passphrase, device_id, epoch=0)
    
    total_blocks = (224 // 16) * (224 // 16)  # 14 * 14 = 196
    block_shape = (16, 16, 3)
    grid_shape = (14, 14)
    img_shape = (224, 224, 3)
    block_byte_size = 16 * 16 * 3  # 768
    
    total_inferences = len(clean_preds)
    
    print("\n" + "=" * 80)
    print("EVALUATING DOWNSTREAM ML INFERENCE ACROSS TRANSMISSION CORRUPTION SCENARIOS")
    print(f"Scenarios: S1 (Record Loss) and S2 (In-Place Bit Flips)")
    print(f"Dataset: {len(clean_images_rgb)} images x {NUM_TRIALS_PER_LEVEL} trials x {len(CORRUPTION_CONFIGS)} levels")
    print("=" * 80)
    
    results_s1 = []
    results_s2 = []
    
    for cfg in CORRUPTION_CONFIGS:
        label = cfg['label']
        K = cfg['K']
        pct = round((K / float(total_blocks)) * 100.0, 2)
        print(f"\n--- Testing Corruption Level: {label} (K = {K} blocks, {pct}%) ---")
        
        # --- SCENARIO S1: RECORD LOSS ---
        s1_trial_cbc_u = []
        s1_trial_cbc_f = []
        s1_trial_cbc_hmac = []
        s1_trial_zero = []
        s1_trial_conc = []
        
        s1_bin_cbc_u = []
        s1_bin_cbc_f = []
        s1_bin_cbc_hmac = []
        s1_bin_zero = []
        s1_bin_conc = []
        
        # --- SCENARIO S2: IN-PLACE BIT FLIPS ---
        s2_trial_cbc_u = []
        s2_trial_cbc_hmac = []
        s2_trial_zero = []
        s2_trial_conc = []
        
        s2_bin_cbc_u = []
        s2_bin_cbc_hmac = []
        s2_bin_zero = []
        s2_bin_conc = []
        
        for t in range(NUM_TRIALS_PER_LEVEL):
            t_seed = seed + K * 500 + t
            t_rng = random.Random(t_seed)
            corr_indices = sorted(t_rng.sample(range(total_blocks), K))
            corr_set = set(corr_indices)
            
            s1_corr_u = 0
            s1_corr_f = 0
            s1_corr_hmac = 0
            s1_corr_z = 0
            s1_corr_c = 0
            
            s2_corr_u = 0
            s2_corr_hmac = 0
            s2_corr_z = 0
            s2_corr_c = 0
            
            n_eval = len(clean_images_rgb)
            
            for idx_img in range(n_eval):
                orig_arr = clean_images_rgb[idx_img]
                clean_target = clean_preds[idx_img]
                blocks = clean_blocks_list[idx_img]
                
                # -------------------------------------------------------------
                # SCENARIO S1: Record Loss
                # -------------------------------------------------------------
                # Proposed GCM Zero-Fill / Framed CBC / CBC+HMAC
                zero_blocks = [b.copy() if i not in corr_set else np.zeros(block_shape, dtype=np.uint8) 
                               for i, b in enumerate(blocks)]
                recon_zero = merge_blocks(zero_blocks, img_shape)
                tensor_zero = preprocess_array(recon_zero)
                pred_zero = int(np.argmax(session.run(None, {input_name: tensor_zero})[0]))
                is_correct_zero = 1 if pred_zero == clean_target else 0
                
                s1_corr_z += is_correct_zero
                s1_corr_f += is_correct_zero
                s1_corr_hmac += is_correct_zero
                s1_bin_zero.append(is_correct_zero)
                s1_bin_cbc_f.append(is_correct_zero)
                s1_bin_cbc_hmac.append(is_correct_zero)
                total_inferences += 1
                
                # Proposed GCM Concealed
                recon_conc_blocks = conceal_failed_blocks(zero_blocks, corr_indices, grid_shape, block_shape)
                recon_conc = merge_blocks(recon_conc_blocks, img_shape)
                tensor_conc = preprocess_array(recon_conc)
                pred_conc = int(np.argmax(session.run(None, {input_name: tensor_conc})[0]))
                is_correct_conc = 1 if pred_conc == clean_target else 0
                
                s1_corr_c += is_correct_conc
                s1_bin_conc.append(is_correct_conc)
                total_inferences += 1
                
                # Unframed CBC (stream loss: 16-byte unannounced drop per record)
                flat_bytes = orig_arr.tobytes()
                cbc_iv, cbc_ct = cbc_encrypt_monolithic(flat_bytes, aes_key)
                corrupted_cbc = bytearray(cbc_ct)
                for c_idx in sorted(corr_indices, reverse=True):
                    off = c_idx * block_byte_size
                    if off + 16 <= len(corrupted_cbc):
                        del corrupted_cbc[off:off+16]
                pt_cbc = cbc_decrypt_monolithic(cbc_iv, bytes(corrupted_cbc), aes_key)
                if len(pt_cbc) < len(flat_bytes):
                    pt_cbc = pt_cbc + b"\x00" * (len(flat_bytes) - len(pt_cbc))
                recon_cbc_unframed = np.frombuffer(pt_cbc[:len(flat_bytes)], dtype=np.uint8).reshape(img_shape)
                tensor_cbc_u = preprocess_array(recon_cbc_unframed)
                pred_cbc_u = int(np.argmax(session.run(None, {input_name: tensor_cbc_u})[0]))
                is_correct_cbc_u = 1 if pred_cbc_u == clean_target else 0
                
                s1_corr_u += is_correct_cbc_u
                s1_bin_cbc_u.append(is_correct_cbc_u)
                total_inferences += 1
                
                # -------------------------------------------------------------
                # SCENARIO S2: In-Place Bit Flips
                # -------------------------------------------------------------
                # In GCM and CBC+HMAC, bit-flip triggers tag verification failure -> quarantined / concealed
                # S2 zero-fill and concealed results match S1 zero-fill and concealed because
                # authenticated containment quarantines the failed block regardless of drop vs corruption
                s2_corr_z += is_correct_zero
                s2_corr_hmac += is_correct_zero
                s2_bin_zero.append(is_correct_zero)
                s2_bin_cbc_hmac.append(is_correct_zero)
                
                s2_corr_c += is_correct_conc
                s2_bin_conc.append(is_correct_conc)
                
                # Unframed CBC under In-Place Bit Flips (M1)
                # Bit flip in block affects that block and the subsequent 16-byte block
                corrupted_cbc_bit = bytearray(cbc_ct)
                for c_idx in corr_indices:
                    bit_off = c_idx * block_byte_size + 24
                    if bit_off < len(corrupted_cbc_bit):
                        corrupted_cbc_bit[bit_off] ^= 0x01
                pt_cbc_bit = cbc_decrypt_monolithic(cbc_iv, bytes(corrupted_cbc_bit), aes_key)
                recon_cbc_bit = np.frombuffer(pt_cbc_bit[:len(flat_bytes)], dtype=np.uint8).reshape(img_shape)
                tensor_cbc_bit = preprocess_array(recon_cbc_bit)
                pred_cbc_bit = int(np.argmax(session.run(None, {input_name: tensor_cbc_bit})[0]))
                is_correct_cbc_bit = 1 if pred_cbc_bit == clean_target else 0
                
                s2_corr_u += is_correct_cbc_bit
                s2_bin_cbc_u.append(is_correct_cbc_bit)
                total_inferences += 1

            s1_trial_cbc_u.append((s1_corr_u / float(n_eval)) * 100.0)
            s1_trial_cbc_f.append((s1_corr_f / float(n_eval)) * 100.0)
            s1_trial_cbc_hmac.append((s1_corr_hmac / float(n_eval)) * 100.0)
            s1_trial_zero.append((s1_corr_z / float(n_eval)) * 100.0)
            s1_trial_conc.append((s1_corr_c / float(n_eval)) * 100.0)
            
            s2_trial_cbc_u.append((s2_corr_u / float(n_eval)) * 100.0)
            s2_trial_cbc_hmac.append((s2_corr_hmac / float(n_eval)) * 100.0)
            s2_trial_zero.append((s2_corr_z / float(n_eval)) * 100.0)
            s2_trial_conc.append((s2_corr_c / float(n_eval)) * 100.0)

        # CIs for S1
        ci_s1_cbc_u = bootstrap_ci(s1_bin_cbc_u, seed=seed)
        ci_s1_cbc_f = bootstrap_ci(s1_bin_cbc_f, seed=seed)
        ci_s1_cbc_hmac = bootstrap_ci(s1_bin_cbc_hmac, seed=seed)
        ci_s1_zero = bootstrap_ci(s1_bin_zero, seed=seed)
        ci_s1_conc = bootstrap_ci(s1_bin_conc, seed=seed)
        
        # CIs for S2
        ci_s2_cbc_u = bootstrap_ci(s2_bin_cbc_u, seed=seed)
        ci_s2_cbc_hmac = bootstrap_ci(s2_bin_cbc_hmac, seed=seed)
        ci_s2_zero = bootstrap_ci(s2_bin_zero, seed=seed)
        ci_s2_conc = bootstrap_ci(s2_bin_conc, seed=seed)
        
        entry_s1 = {
            'scenario': 'S1_record_loss',
            'corruption_level': label,
            'corrupted_blocks': K,
            'corrupted_fraction_pct': pct,
            'mono_gcm_availability_pct': 0.0,
            'mono_gcm_agreement_pct': 0.0,
            'cbc_unframed_availability_pct': 100.0,
            'cbc_unframed_agreement_mean_pct': round(float(np.mean(s1_trial_cbc_u)), 2),
            'cbc_unframed_agreement_std_pct': round(float(np.std(s1_trial_cbc_u)), 2),
            'cbc_unframed_ci95': ci_s1_cbc_u,
            'cbc_framed_availability_pct': round(((total_blocks - K) / float(total_blocks)) * 100.0, 2),
            'cbc_framed_agreement_mean_pct': round(float(np.mean(s1_trial_cbc_f)), 2),
            'cbc_framed_agreement_std_pct': round(float(np.std(s1_trial_cbc_f)), 2),
            'cbc_framed_ci95': ci_s1_cbc_f,
            'cbc_hmac_availability_pct': round(((total_blocks - K) / float(total_blocks)) * 100.0, 2),
            'cbc_hmac_agreement_mean_pct': round(float(np.mean(s1_trial_cbc_hmac)), 2),
            'cbc_hmac_agreement_std_pct': round(float(np.std(s1_trial_cbc_hmac)), 2),
            'cbc_hmac_ci95': ci_s1_cbc_hmac,
            'proposed_zero_availability_pct': round(((total_blocks - K) / float(total_blocks)) * 100.0, 2),
            'proposed_zero_agreement_mean_pct': round(float(np.mean(s1_trial_zero)), 2),
            'proposed_zero_agreement_std_pct': round(float(np.std(s1_trial_zero)), 2),
            'proposed_zero_ci95': ci_s1_zero,
            'proposed_conc_availability_pct': 100.0,
            'proposed_conc_agreement_mean_pct': round(float(np.mean(s1_trial_conc)), 2),
            'proposed_conc_agreement_std_pct': round(float(np.std(s1_trial_conc)), 2),
            'proposed_conc_ci95': ci_s1_conc,
            'concealment_gain_pct': round(float(np.mean(s1_trial_conc)) - float(np.mean(s1_trial_zero)), 2)
        }
        results_s1.append(entry_s1)
        
        entry_s2 = {
            'scenario': 'S2_inplace_bitflip',
            'corruption_level': label,
            'corrupted_blocks': K,
            'corrupted_fraction_pct': pct,
            'mono_gcm_availability_pct': 0.0,
            'mono_gcm_agreement_pct': 0.0,
            'cbc_unframed_availability_pct': 100.0,
            'cbc_unframed_agreement_mean_pct': round(float(np.mean(s2_trial_cbc_u)), 2),
            'cbc_unframed_agreement_std_pct': round(float(np.std(s2_trial_cbc_u)), 2),
            'cbc_unframed_ci95': ci_s2_cbc_u,
            'cbc_framed_availability_pct': round(((total_blocks - K) / float(total_blocks)) * 100.0, 2),
            'cbc_framed_agreement_mean_pct': round(float(np.mean(s2_trial_zero)), 2),
            'cbc_framed_agreement_std_pct': round(float(np.std(s2_trial_zero)), 2),
            'cbc_framed_ci95': ci_s2_zero,
            'cbc_hmac_availability_pct': round(((total_blocks - K) / float(total_blocks)) * 100.0, 2),
            'cbc_hmac_agreement_mean_pct': round(float(np.mean(s2_trial_cbc_hmac)), 2),
            'cbc_hmac_agreement_std_pct': round(float(np.std(s2_trial_cbc_hmac)), 2),
            'cbc_hmac_ci95': ci_s2_cbc_hmac,
            'proposed_zero_availability_pct': round(((total_blocks - K) / float(total_blocks)) * 100.0, 2),
            'proposed_zero_agreement_mean_pct': round(float(np.mean(s2_trial_zero)), 2),
            'proposed_zero_agreement_std_pct': round(float(np.std(s2_trial_zero)), 2),
            'proposed_zero_ci95': ci_s2_zero,
            'proposed_conc_availability_pct': 100.0,
            'proposed_conc_agreement_mean_pct': round(float(np.mean(s2_trial_conc)), 2),
            'proposed_conc_agreement_std_pct': round(float(np.std(s2_trial_conc)), 2),
            'proposed_conc_ci95': ci_s2_conc,
            'concealment_gain_pct': round(float(np.mean(s2_trial_conc)) - float(np.mean(s2_trial_zero)), 2)
        }
        results_s2.append(entry_s2)
        
        print(f"S1 (Loss):  Unframed CBC={entry_s1['cbc_unframed_agreement_mean_pct']}% | Zero={entry_s1['proposed_zero_agreement_mean_pct']}% | Conc={entry_s1['proposed_conc_agreement_mean_pct']}% (+{entry_s1['concealment_gain_pct']} pp)")
        print(f"S2 (Flips): Unframed CBC={entry_s2['cbc_unframed_agreement_mean_pct']}% | Zero={entry_s2['proposed_zero_agreement_mean_pct']}% | Conc={entry_s2['proposed_conc_agreement_mean_pct']}% (+{entry_s2['concealment_gain_pct']} pp)")

    metadata = {
        'num_images': len(clean_images_rgb),
        'num_trials_per_level': NUM_TRIALS_PER_LEVEL,
        'num_levels': len(CORRUPTION_CONFIGS),
        'evaluations_per_level_per_scheme': len(clean_images_rgb) * NUM_TRIALS_PER_LEVEL,
        'num_schemes_inferred': 4,
        'schemes_inferred': [
            "Proposed Scheme (Concealed, S1)",
            "Proposed Scheme (Zero-Fill) / Framed CBC (S1)",
            "Unframed CBC (S1 Record Loss)",
            "Unframed CBC (S2 Bit-Flips)"
        ],
        'scenarios': ["S1_record_loss", "S2_bit_flips"],
        'clean_baseline_inferences': len(clean_images_rgb),
        'total_evaluations': len(clean_images_rgb) * NUM_TRIALS_PER_LEVEL * len(CORRUPTION_CONFIGS),
        'total_inferences': total_inferences,
        'inference_breakdown_formula': (
            f"{len(clean_images_rgb)} clean baseline + "
            f"({len(clean_images_rgb)} images * {NUM_TRIALS_PER_LEVEL} trials * "
            f"{len(CORRUPTION_CONFIGS)} levels * 4 schemes) = "
            f"{len(clean_images_rgb)} + {len(clean_images_rgb) * NUM_TRIALS_PER_LEVEL * len(CORRUPTION_CONFIGS) * 4:,} = "
            f"{total_inferences:,} MobileNetV2 inferences"
        ),
        'results': results_s1,  # Primary S1 results for Table 7 and Figure 5
        'results_s1_record_loss': results_s1,
        'results_s2_bit_flips': results_s2
    }
    
    out_json = os.path.join(RESULTS_DIR, "ml_downstream.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"\nSaved ML downstream JSON to {out_json}")
    
    # Save combined CSV with scenario column
    all_csv_rows = results_s1 + results_s2
    out_csv = os.path.join(RESULTS_DIR, "ml_downstream.csv")
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_csv_rows[0].keys()))
        writer.writeheader()
        writer.writerows(all_csv_rows)
    print(f"Saved ML downstream CSV to {out_csv}")
    return metadata

if __name__ == "__main__":
    run_ml_downstream_experiment()
