import os
import sys
import time
import json
import csv
import struct
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, split_into_blocks, merge_blocks, unpad_image
from src.record_format import (
    pack_record, unpack_record, build_aad,
    create_session_header, parse_session_header_fields, verify_session_header_hmac
)
from src.key_manager import (
    generate_session_key,
    generate_salt,
    derive_key,
    derive_pbkdf2,
    derive_session_keys,
    generate_receiver_static_keypair,
    get_key_fingerprint,
    get_device_id,
    PBKDF2_ITERATIONS
)
DEFAULT_PBKDF2_ITERATIONS = PBKDF2_ITERATIONS
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NUM_RUNS = 30
WARMUP_RUNS = 5

def run_overhead_benchmarks(seed=GLOBAL_SEED):
    np.random.seed(seed)
    
    # Load Submarine test image
    sub_path = os.path.join(INPUT_DIR, 'submarine.jpg')
    sub_arr = load_image(sub_path)
    raw_h, raw_w, channels = sub_arr.shape
    raw_bytes_len = sub_arr.nbytes  # 460 * 1199 * 3 = 1,654,620 bytes
    
    device_id = get_device_id()
    passphrase = "BenchmarkPassphrase2026!"
    sess = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    aes_key = derive_key(sess, hs, ps, passphrase, device_id, epoch=0)
    aesgcm = AESGCM(aes_key)
    
    print("=" * 80)
    print("BENCHMARKING MONOLITHIC VS BLOCK-LEVEL AES-GCM (30 RUNS EACH)")
    print(f"Raw Image: {raw_w}x{raw_h} ({raw_bytes_len:,} bytes)")
    print("=" * 80)
    
    # -------------------------------------------------------------------------
    # 0. Benchmark PBKDF2 & Session Key Derivation
    # -------------------------------------------------------------------------
    print(f"\nBenchmarking PBKDF2-HMAC-SHA256 ({DEFAULT_PBKDF2_ITERATIONS:,} iterations)...")
    pbkdf2_times = []
    for _ in range(3):
        _ = derive_pbkdf2(passphrase, ps, iterations=DEFAULT_PBKDF2_ITERATIONS)
    for _ in range(10):
        t0 = time.perf_counter()
        _ = derive_pbkdf2(passphrase, ps, iterations=DEFAULT_PBKDF2_ITERATIONS)
        pbkdf2_times.append((time.perf_counter() - t0) * 1000.0)
    pbkdf2_mean_ms = float(np.mean(pbkdf2_times))
    pbkdf2_std_ms = float(np.std(pbkdf2_times))
    print(f"PBKDF2 Derivation Time: {pbkdf2_mean_ms:.2f} +/- {pbkdf2_std_ms:.2f} ms")
    
    # Session setup latency
    setup_times = []
    rx_priv, rx_pub = generate_receiver_static_keypair()
    rx_pub_bytes = rx_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    rx_fp = get_key_fingerprint(rx_pub)

    for _ in range(10):
        t0 = time.perf_counter()
        tx_eph_priv = x25519.X25519PrivateKey.generate()
        tx_eph_pub = tx_eph_priv.public_key()
        eph_pub_bytes = tx_eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared_secret = tx_eph_priv.exchange(rx_pub)
        k_aes, k_hdr, _ = derive_session_keys(
            shared_secret, eph_pub_bytes, rx_pub_bytes,
            hs, ps, passphrase, device_id, epoch=0
        )
        hdr = create_session_header(0, raw_h, raw_w, 2175, hs, ps, eph_pub_bytes, rx_fp, k_hdr)
        fields = parse_session_header_fields(hdr)
        verify_session_header_hmac(fields['header_body'], fields['hmac_tag'], k_hdr)
        setup_times.append((time.perf_counter() - t0) * 1000.0)
    setup_mean_ms = float(np.mean(setup_times))
    setup_std_ms = float(np.std(setup_times))
    print(f"Total Session Setup Latency: {setup_mean_ms:.2f} +/- {setup_std_ms:.2f} ms")

    results = []
    
    # -------------------------------------------------------------------------
    # 1. Monolithic Whole-Image AES-GCM
    # -------------------------------------------------------------------------
    flat_raw = sub_arr.tobytes()
    mono_iv = os.urandom(12)
    mono_ct_and_tag = aesgcm.encrypt(mono_iv, flat_raw, None)
    mono_ct = mono_ct_and_tag[:-16]
    mono_tag = mono_ct_and_tag[-16:]
    mono_payload = mono_iv + mono_ct + mono_tag
    mono_payload_len = len(mono_payload)
    mono_overhead_bytes = mono_payload_len - raw_bytes_len
    mono_overhead_pct = (mono_overhead_bytes / float(raw_bytes_len)) * 100.0
    
    # Warm-up
    for _ in range(WARMUP_RUNS):
        _ = aesgcm.encrypt(mono_iv, flat_raw, None)
        _ = aesgcm.decrypt(mono_iv, mono_ct_and_tag, None)
        
    mono_enc_times = []
    mono_dec_times = []
    for _ in range(NUM_RUNS):
        t0 = time.perf_counter()
        _ = aesgcm.encrypt(mono_iv, flat_raw, None)
        mono_enc_times.append((time.perf_counter() - t0) * 1000.0)
        
        t0 = time.perf_counter()
        _ = aesgcm.decrypt(mono_iv, mono_ct_and_tag, None)
        mono_dec_times.append((time.perf_counter() - t0) * 1000.0)
        
    mono_enc_mean = float(np.mean(mono_enc_times))
    mono_enc_std = float(np.std(mono_enc_times))
    mono_dec_mean = float(np.mean(mono_dec_times))
    mono_dec_std = float(np.std(mono_dec_times))
    
    # Standard decimal MB/s = (bytes / 1e6) / (time_ms / 1000.0)
    throughput_mono_mbps = (raw_bytes_len / 1e6) / (mono_enc_mean / 1000.0)
    
    entry_mono = {
        'configuration': 'Monolithic (Whole Image)',
        'block_size': 'N/A',
        'num_blocks': 1,
        'enc_time_mean_ms': round(mono_enc_mean, 2),
        'enc_time_std_ms': round(mono_enc_std, 2),
        'enc_time_median_ms': round(float(np.median(mono_enc_times)), 2),
        'dec_time_mean_ms': round(mono_dec_mean, 2),
        'dec_time_std_ms': round(mono_dec_std, 2),
        'dec_time_median_ms': round(float(np.median(mono_dec_times)), 2),
        'e2e_enc_time_mean_ms': round(mono_enc_mean, 2),
        'e2e_enc_time_std_ms': round(mono_enc_std, 2),
        'e2e_dec_time_mean_ms': round(mono_dec_mean, 2),
        'e2e_dec_time_std_ms': round(mono_dec_std, 2),
        'payload_bytes': mono_payload_len,
        'tag_iv_header_bytes': 28,
        'padding_bytes': 0,
        'total_overhead_bytes': mono_overhead_bytes,
        'total_overhead_pct': round(mono_overhead_pct, 4),
        'analytical_tag_overhead_pct': round((28.0 / raw_bytes_len) * 100.0, 4),
        'throughput_mbps': round(throughput_mono_mbps, 1),
        'e2e_throughput_mbps': round(throughput_mono_mbps, 1),
        'error_resilience': 'Catastrophic Abort (0% Availability)'
    }
    results.append(entry_mono)
    print(f"Monolithic Whole-Image: Enc = {entry_mono['enc_time_mean_ms']} +/- {entry_mono['enc_time_std_ms']} ms | Dec = {entry_mono['dec_time_mean_ms']} ms | Throughput = {entry_mono['throughput_mbps']} MB/s")
    
    # -------------------------------------------------------------------------
    # 2. Block-Level AES-GCM across Block Sizes (8x8, 16x16, 32x32, 64x64)
    # -------------------------------------------------------------------------
    block_sizes = [8, 16, 32, 64]
    
    for bs in block_sizes:
        padded, orig_shape = pad_image(sub_arr, bs)
        blocks = split_into_blocks(padded, bs)
        n_blocks = len(blocks)
        pad_h, pad_w = padded.shape[0], padded.shape[1]
        block_bytes = bs * bs * channels
        
        # Exact overhead breakdown
        tag_iv_header_per_block = 4 + 12 + 16  # 32 bytes (index + nonce + tag)
        total_framing_bytes = n_blocks * tag_iv_header_per_block
        padding_bytes = padded.nbytes - raw_bytes_len
        total_payload_bytes = padded.nbytes + total_framing_bytes
        total_overhead_bytes = total_payload_bytes - raw_bytes_len
        total_overhead_pct = (total_overhead_bytes / float(raw_bytes_len)) * 100.0
        analytical_framing_pct = (tag_iv_header_per_block / float(block_bytes)) * 100.0
        
        # Warmup
        for _ in range(WARMUP_RUNS):
            enc_b = []
            for idx, b in enumerate(blocks):
                nonce = os.urandom(12)
                aad = build_aad(idx, pad_h, pad_w, n_blocks, 0)
                ct_tag = aesgcm.encrypt(nonce, b.tobytes(), aad)
                enc_b.append(pack_record(idx, nonce, ct_tag[:-16], ct_tag[-16:]))
            dec_b = []
            for rec in enc_b:
                idx, nonce, ct, tag = unpack_record(rec)
                aad = build_aad(idx, pad_h, pad_w, n_blocks, 0)
                pt = aesgcm.decrypt(nonce, ct + tag, aad)
                dec_b.append(pt)
                
        # Benchmark runs
        enc_times = []
        dec_times = []
        e2e_enc_times = []
        e2e_dec_times = []
        
        for _ in range(NUM_RUNS):
            # Pure crypto encryption
            t0 = time.perf_counter()
            enc_b = []
            for idx, b in enumerate(blocks):
                nonce = os.urandom(12)
                aad = build_aad(idx, pad_h, pad_w, n_blocks, 0)
                ct_tag = aesgcm.encrypt(nonce, b.tobytes(), aad)
                enc_b.append(pack_record(idx, nonce, ct_tag[:-16], ct_tag[-16:]))
            enc_times.append((time.perf_counter() - t0) * 1000.0)
            
            # Pure crypto decryption
            t0 = time.perf_counter()
            dec_b = []
            for rec in enc_b:
                idx, nonce, ct, tag = unpack_record(rec)
                aad = build_aad(idx, pad_h, pad_w, n_blocks, 0)
                pt = aesgcm.decrypt(nonce, ct + tag, aad)
                dec_b.append(pt)
            dec_times.append((time.perf_counter() - t0) * 1000.0)
            
            # End-to-end encryption (pad + split + crypto)
            t0 = time.perf_counter()
            p_img, _ = pad_image(sub_arr, bs)
            b_list = split_into_blocks(p_img, bs)
            rec_list = []
            for idx, b in enumerate(b_list):
                nonce = os.urandom(12)
                aad = build_aad(idx, pad_h, pad_w, n_blocks, 0)
                ct_tag = aesgcm.encrypt(nonce, b.tobytes(), aad)
                rec_list.append(pack_record(idx, nonce, ct_tag[:-16], ct_tag[-16:]))
            e2e_enc_times.append((time.perf_counter() - t0) * 1000.0)
            
            # End-to-end decryption (crypto + merge + unpad)
            t0 = time.perf_counter()
            d_blocks = []
            for rec in rec_list:
                idx, nonce, ct, tag = unpack_record(rec)
                aad = build_aad(idx, pad_h, pad_w, n_blocks, 0)
                pt = aesgcm.decrypt(nonce, ct + tag, aad)
                d_blocks.append(np.frombuffer(pt, dtype=np.uint8).reshape((bs, bs, channels)))
            merged = merge_blocks(d_blocks, padded.shape, block_size=bs)
            _ = unpad_image(merged, orig_shape)
            e2e_dec_times.append((time.perf_counter() - t0) * 1000.0)
            
        enc_mean = float(np.mean(enc_times))
        enc_std = float(np.std(enc_times))
        dec_mean = float(np.mean(dec_times))
        dec_std = float(np.std(dec_times))
        
        e2e_enc_mean = float(np.mean(e2e_enc_times))
        e2e_enc_std = float(np.std(e2e_enc_times))
        e2e_dec_mean = float(np.mean(e2e_dec_times))
        e2e_dec_std = float(np.std(e2e_dec_times))
        
        # Standard decimal MB/s = (bytes / 1e6) / (time_ms / 1000.0)
        throughput_mbps = (raw_bytes_len / 1e6) / (enc_mean / 1000.0)
        e2e_throughput_mbps = (raw_bytes_len / 1e6) / (e2e_enc_mean / 1000.0)
        
        entry = {
            'configuration': f'Block-Level {bs}x{bs}' + (' (Proposed)' if bs == 16 else ''),
            'block_size': f'{bs}x{bs}',
            'num_blocks': n_blocks,
            'enc_time_mean_ms': round(enc_mean, 2),
            'enc_time_std_ms': round(enc_std, 2),
            'enc_time_median_ms': round(float(np.median(enc_times)), 2),
            'dec_time_mean_ms': round(dec_mean, 2),
            'dec_time_std_ms': round(dec_std, 2),
            'dec_time_median_ms': round(float(np.median(dec_times)), 2),
            'e2e_enc_time_mean_ms': round(e2e_enc_mean, 2),
            'e2e_enc_time_std_ms': round(e2e_enc_std, 2),
            'e2e_dec_time_mean_ms': round(e2e_dec_mean, 2),
            'e2e_dec_time_std_ms': round(e2e_dec_std, 2),
            'payload_bytes': total_payload_bytes,
            'tag_iv_header_bytes': total_framing_bytes,
            'padding_bytes': padding_bytes,
            'total_overhead_bytes': total_overhead_bytes,
            'total_overhead_pct': round(total_overhead_pct, 2),
            'analytical_tag_overhead_pct': round(analytical_framing_pct, 2),
            'throughput_mbps': round(throughput_mbps, 1),
            'e2e_throughput_mbps': round(e2e_throughput_mbps, 1),
            'error_resilience': 'Strictly Bounded (EPR = 1.0)'
        }
        results.append(entry)
        print(f"Block {bs}x{bs:>2} ({n_blocks:>5} blocks): Enc = {entry['enc_time_mean_ms']:>5.2f} +/- {entry['enc_time_std_ms']:.2f} ms | Dec = {entry['dec_time_mean_ms']:>5.2f} ms | Throughput = {entry['throughput_mbps']} MB/s (E2E: {entry['e2e_throughput_mbps']} MB/s)")

    # Record setup benchmark metadata
    overhead_metadata = {
        'image': 'submarine.jpg',
        'raw_dimensions': f"{raw_w}x{raw_h}",
        'padded_dimensions': f"{padded.shape[1]}x{padded.shape[0]}",
        'raw_bytes': raw_bytes_len,
        'pbkdf2_mean_ms': round(pbkdf2_mean_ms, 2),
        'pbkdf2_std_ms': round(pbkdf2_std_ms, 2),
        'pbkdf2_iterations': DEFAULT_PBKDF2_ITERATIONS,
        'session_setup_mean_ms': round(setup_mean_ms, 2),
        'session_setup_std_ms': round(setup_std_ms, 2),
        'num_runs': NUM_RUNS,
        'benchmark_results': results
    }
    
    out_json = os.path.join(RESULTS_DIR, "overhead_metrics.json")
    with open(out_json, "w") as f:
        json.dump(overhead_metadata, f, indent=2)
    print("\nSaved overhead results to", out_json)
    
    out_csv = os.path.join(RESULTS_DIR, "overhead_metrics.csv")
    with open(out_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print("Saved overhead CSV to", out_csv)
    return overhead_metadata

if __name__ == "__main__":
    run_overhead_benchmarks()
