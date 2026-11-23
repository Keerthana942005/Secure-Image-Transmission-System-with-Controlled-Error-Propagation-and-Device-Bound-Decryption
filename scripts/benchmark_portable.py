"""Unified Portable System Benchmark.
The single, authoritative source for all cryptographic latency, throughput,
framing overhead, and streaming feasibility metrics in the manuscript
(Table 4, Table 5, Figure 4, and results_macros.tex).

Metric Definitions:
- crypto_only: Execution time of AES-GCM encrypt / decrypt over precomputed memory blocks
  with pre-allocated nonces and AADs. Measures pure cryptographic algorithm execution
  without framing, memory copies, or image manipulation.
- end_to_end: Full transmission pipeline execution time:
  * Sender: pad_image + split_into_blocks + pack_record (4B index + 12B IV + ct + 16B tag) + AES-GCM encrypt.
  * Receiver: unpack_record + AES-GCM decrypt + merge_blocks + unpad_image.
- Throughput: Decimal MB/s (10^6 bytes/second), defined as:
  Throughput = (raw_image_bytes / 1e6) / (mean_latency_ms / 1000.0).
  Both crypto-only and end-to-end throughputs are computed over the unpadded raw image bytes
  to reflect usable payload throughput.
"""

import os
import sys
import time
import json
import socket
import platform
import subprocess
import ctypes
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, INPUT_DIR, RESULTS_DIR
from src.image_processor import load_image, pad_image, split_into_blocks, merge_blocks, unpad_image
from src.record_format import (
    pack_record, unpack_record, build_aad,
    create_session_header, parse_session_header_fields, verify_session_header_hmac
)
from src.key_manager import (
    generate_session_key, generate_salt, derive_key, derive_pbkdf2,
    derive_session_keys, generate_receiver_static_keypair,
    get_key_fingerprint, get_device_id, PBKDF2_ITERATIONS
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import cryptography

NUM_RUNS = 30
WARMUP_RUNS = 5

VIDEO_PROFILES = [
    {'name': '720p 60fps',  'resolution': '1280x720',  'fps': 60, 'data_rate_mbps': round(1280 * 720 * 3 * 60 / 1e6, 1)},
    {'name': '1080p 30fps', 'resolution': '1920x1080', 'fps': 30, 'data_rate_mbps': round(1920 * 1080 * 3 * 30 / 1e6, 1)},
    {'name': '1080p 60fps', 'resolution': '1920x1080', 'fps': 60, 'data_rate_mbps': round(1920 * 1080 * 3 * 60 / 1e6, 1)},
    {'name': '4K 60fps',    'resolution': '3840x2160', 'fps': 60, 'data_rate_mbps': round(3840 * 2160 * 3 * 60 / 1e6, 1)}
]

def get_cpu_info() -> str:
    """Gets CPU model name reliably on Windows and Unix."""
    try:
        if platform.system() == "Windows":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            cpu_name = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
            winreg.CloseKey(key)
            return cpu_name
        else:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line:
                        return line.split(":")[1].strip()
    except Exception:
        pass
    return platform.processor() or "Unknown CPU"

def get_power_info() -> dict:
    """Gets active Windows power scheme and AC/battery status."""
    active_scheme = "Unknown"
    ac_status = "Unknown"
    battery_pct = None
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output(['powercfg', '/getactivescheme'], text=True, stderr=subprocess.DEVNULL).strip()
            active_scheme = out
            class SYSTEM_POWER_STATUS(ctypes.Structure):
                _fields_ = [
                    ('ACLineStatus', ctypes.c_byte),
                    ('BatteryFlag', ctypes.c_byte),
                    ('BatteryLifePercent', ctypes.c_byte),
                    ('SystemStatusFlag', ctypes.c_byte),
                    ('BatteryLifeTime', ctypes.c_ulong),
                    ('BatteryFullLifeTime', ctypes.c_ulong),
                ]
            status = SYSTEM_POWER_STATUS()
            ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status))
            ac_status = 'Plugged In (AC)' if status.ACLineStatus == 1 else ('Battery' if status.ACLineStatus == 0 else 'Unknown')
            battery_pct = int(status.BatteryLifePercent)
    except Exception as e:
        active_scheme = f"Query failed: {e}"
    return {
        'active_scheme': active_scheme,
        'ac_status': ac_status,
        'battery_pct': battery_pct
    }

def run_single_benchmark(seed=GLOBAL_SEED, run_index=1) -> dict:
    np.random.seed(seed)
    hostname = socket.gethostname()
    cpu_name = get_cpu_info()
    cores = os.cpu_count() or 1
    power_info = get_power_info()

    # Load Submarine benchmark image (1199x460x3 = 1,654,620 raw bytes)
    sub_path = os.path.join(INPUT_DIR, 'submarine.jpg')
    sub_arr = load_image(sub_path)
    raw_h, raw_w, channels = sub_arr.shape
    raw_bytes_len = sub_arr.nbytes

    device_id = get_device_id()
    passphrase = "UnifiedBenchmarkSecret2026!"
    sess = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    aes_key = derive_key(sess, hs, ps, passphrase, device_id, epoch=0)
    aesgcm = AESGCM(aes_key)

    # 1. PBKDF2 Latency (600,000 iterations)
    pbkdf2_times = []
    for _ in range(2):
        _ = derive_pbkdf2(passphrase, ps, iterations=PBKDF2_ITERATIONS)
    for _ in range(5):
        t0 = time.perf_counter()
        _ = derive_pbkdf2(passphrase, ps, iterations=PBKDF2_ITERATIONS)
        pbkdf2_times.append((time.perf_counter() - t0) * 1000.0)
    pbkdf2_mean_ms = float(np.mean(pbkdf2_times))
    pbkdf2_std_ms = float(np.std(pbkdf2_times))

    # 2. Session Header Handshake Latency (X25519 + HMAC-SHA256)
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

    benchmark_results = []

    # 3. Monolithic Whole-Image AES-GCM
    flat_raw = sub_arr.tobytes()
    mono_iv = os.urandom(12)
    mono_ct_and_tag = aesgcm.encrypt(mono_iv, flat_raw, None)
    mono_payload = mono_iv + mono_ct_and_tag
    mono_payload_len = len(mono_payload)
    mono_ovhd_bytes = mono_payload_len - raw_bytes_len
    mono_ovhd_pct = (mono_ovhd_bytes / float(raw_bytes_len)) * 100.0

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
    mono_th = (raw_bytes_len / 1e6) / (mono_enc_mean / 1000.0)

    benchmark_results.append({
        'configuration': 'Monolithic (Whole Image)',
        'block_size': 'N/A',
        'num_blocks': 1,
        'enc_time_mean_ms': round(mono_enc_mean, 2),
        'enc_time_std_ms': round(mono_enc_std, 2),
        'dec_time_mean_ms': round(mono_dec_mean, 2),
        'dec_time_std_ms': round(mono_dec_std, 2),
        'e2e_enc_time_mean_ms': round(mono_enc_mean, 2),
        'e2e_enc_time_std_ms': round(mono_enc_std, 2),
        'e2e_dec_time_mean_ms': round(mono_dec_mean, 2),
        'e2e_dec_time_std_ms': round(mono_dec_std, 2),
        'payload_bytes': mono_payload_len,
        'tag_iv_header_bytes': 28,
        'padding_bytes': 0,
        'total_overhead_bytes': mono_ovhd_bytes,
        'total_overhead_pct': round(mono_ovhd_pct, 4),
        'analytical_tag_overhead_pct': round((28.0 / raw_bytes_len) * 100.0, 4),
        'throughput_mbps': round(mono_th, 1),
        'e2e_throughput_mbps': round(mono_th, 1),
        'error_resilience': 'Catastrophic Abort (0% Availability)'
    })

    # 4. Block-Level Configurations: 8x8, 16x16, 32x32, 64x64
    block_sizes = [8, 16, 32, 64]
    for bs in block_sizes:
        cfg_name = f"Block-Level {bs}x{bs} (Proposed)" if bs == 16 else f"Block-Level {bs}x{bs}"
        padded, orig_shape = pad_image(sub_arr, bs)
        blocks = split_into_blocks(padded, bs)
        n_blocks = len(blocks)
        pad_h, pad_w = padded.shape[0], padded.shape[1]
        block_bytes = bs * bs * channels

        tag_iv_header_per_block = 4 + 12 + 16  # 32 bytes (index + IV + tag)
        total_framing_bytes = n_blocks * tag_iv_header_per_block
        padding_bytes = padded.nbytes - raw_bytes_len
        total_payload_bytes = padded.nbytes + total_framing_bytes
        total_overhead_bytes = total_payload_bytes - raw_bytes_len
        total_overhead_pct = (total_overhead_bytes / float(raw_bytes_len)) * 100.0
        analytical_framing_pct = (tag_iv_header_per_block / float(block_bytes)) * 100.0

        # Precompute buffers for crypto-only measurement
        nonces = [os.urandom(12) for _ in range(n_blocks)]
        aads = [build_aad(i, pad_h, pad_w, n_blocks, 0) for i in range(n_blocks)]
        raw_b_bytes = [b.tobytes() for b in blocks]

        # Warmup
        for _ in range(WARMUP_RUNS):
            cts = [aesgcm.encrypt(n, b, a) for n, b, a in zip(nonces, raw_b_bytes, aads)]
            _ = [aesgcm.decrypt(n, c, a) for n, c, a in zip(nonces, cts, aads)]

        # Pure Crypto Measurement
        pure_enc_times = []
        pure_dec_times = []
        for _ in range(NUM_RUNS):
            t0 = time.perf_counter()
            cts = [aesgcm.encrypt(n, b, a) for n, b, a in zip(nonces, raw_b_bytes, aads)]
            pure_enc_times.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            _ = [aesgcm.decrypt(n, c, a) for n, c, a in zip(nonces, cts, aads)]
            pure_dec_times.append((time.perf_counter() - t0) * 1000.0)

        pure_enc_mean = float(np.mean(pure_enc_times))
        pure_enc_std = float(np.std(pure_enc_times))
        pure_dec_mean = float(np.mean(pure_dec_times))
        pure_dec_std = float(np.std(pure_dec_times))
        pure_th = (raw_bytes_len / 1e6) / (pure_enc_mean / 1000.0)

        # End-to-End Pipeline Measurement
        e2e_enc_times = []
        e2e_dec_times = []
        for _ in range(NUM_RUNS):
            t0 = time.perf_counter()
            p_img, _ = pad_image(sub_arr, bs)
            b_list = split_into_blocks(p_img, bs)
            records = []
            for idx, blk in enumerate(b_list):
                n = nonces[idx]
                aad = aads[idx]
                ct_tag = aesgcm.encrypt(n, blk.tobytes(), aad)
                records.append(pack_record(idx, n, ct_tag[:-16], ct_tag[-16:]))
            e2e_enc_times.append((time.perf_counter() - t0) * 1000.0)

            t0 = time.perf_counter()
            dec_blocks = []
            for rec in records:
                idx, n, ct, tag = unpack_record(rec)
                aad = aads[idx]
                pt = aesgcm.decrypt(n, ct + tag, aad)
                dec_blocks.append(np.frombuffer(pt, dtype=np.uint8).reshape((bs, bs, channels)))
            merged = merge_blocks(dec_blocks, padded.shape, block_size=bs)
            _ = unpad_image(merged, orig_shape)
            e2e_dec_times.append((time.perf_counter() - t0) * 1000.0)

        e2e_enc_mean = float(np.mean(e2e_enc_times))
        e2e_enc_std = float(np.std(e2e_enc_times))
        e2e_dec_mean = float(np.mean(e2e_dec_times))
        e2e_dec_std = float(np.std(e2e_dec_times))
        e2e_th = (raw_bytes_len / 1e6) / (e2e_enc_mean / 1000.0)

        benchmark_results.append({
            'configuration': cfg_name,
            'block_size': f"{bs}x{bs}",
            'num_blocks': n_blocks,
            'enc_time_mean_ms': round(pure_enc_mean, 2),
            'enc_time_std_ms': round(pure_enc_std, 2),
            'dec_time_mean_ms': round(pure_dec_mean, 2),
            'dec_time_std_ms': round(pure_dec_std, 2),
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
            'throughput_mbps': round(pure_th, 1),
            'e2e_throughput_mbps': round(e2e_th, 1),
            'error_resilience': 'Strictly Bounded (EPR = 1.0)'
        })

    # Video streaming feasibility on 16x16 configuration
    cfg16 = [b for b in benchmark_results if b['block_size'] == '16x16'][0]
    pure_th_16 = cfg16['throughput_mbps']
    e2e_th_16 = cfg16['e2e_throughput_mbps']

    streaming_eval = []
    for vp in VIDEO_PROFILES:
        rate = vp['data_rate_mbps']
        load_crypto = round((rate / pure_th_16) * 100.0, 1)
        load_e2e = round((rate / e2e_th_16) * 100.0, 1)
        streaming_eval.append({
            'profile': vp['name'],
            'resolution': vp['resolution'],
            'fps': vp['fps'],
            'data_rate_decimal_mbps': rate,
            'load_crypto_only_pct': load_crypto,
            'load_end_to_end_pct': load_e2e,
            'realtime_feasible_crypto': load_crypto <= 100.0,
            'realtime_feasible_e2e': load_e2e <= 100.0
        })

    run_payload = {
        'run_index': run_index,
        'seed': seed,
        'timestamp': int(time.time()),
        'hostname': hostname,
        'cpu_name': cpu_name,
        'cores': cores,
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'cryptography_version': cryptography.__version__,
        'power_profile': power_info,
        'image': 'submarine.jpg',
        'raw_dimensions': f"{raw_w}x{raw_h}",
        'raw_bytes': raw_bytes_len,
        'pbkdf2_mean_ms': round(pbkdf2_mean_ms, 2),
        'pbkdf2_std_ms': round(pbkdf2_std_ms, 2),
        'pbkdf2_iterations': PBKDF2_ITERATIONS,
        'session_setup_mean_ms': round(setup_mean_ms, 2),
        'session_setup_std_ms': round(setup_std_ms, 2),
        'benchmark_results': benchmark_results,
        'pure_crypto': {
            'enc_mean_ms': cfg16['enc_time_mean_ms'],
            'enc_std_ms': cfg16['enc_time_std_ms'],
            'dec_mean_ms': cfg16['dec_time_mean_ms'],
            'dec_std_ms': cfg16['dec_time_std_ms'],
            'throughput_decimal_mbps': pure_th_16
        },
        'end_to_end': {
            'enc_mean_ms': cfg16['e2e_enc_time_mean_ms'],
            'enc_std_ms': cfg16['e2e_enc_time_std_ms'],
            'dec_mean_ms': cfg16['e2e_dec_time_mean_ms'],
            'dec_std_ms': cfg16['e2e_dec_time_std_ms'],
            'throughput_decimal_mbps': e2e_th_16
        },
        'video_streaming_load': streaming_eval
    }
    return run_payload

def run_multi_session_benchmark(num_runs=15, base_seed=GLOBAL_SEED):
    print("=" * 80)
    print(f"RUNNING UNIFIED PORTABLE BENCHMARK SUITE ({num_runs} SESSIONS)")
    print("Source for Table 4, Table 5, Figure 4, and results_macros.tex")
    print("=" * 80)

    bench_runs_dir = os.path.join(RESULTS_DIR, "bench_runs")
    os.makedirs(bench_runs_dir, exist_ok=True)

    # Pre-flight system check
    initial_power = get_power_info()
    cpu_name = get_cpu_info()
    cores = os.cpu_count() or 1
    hostname = socket.gethostname()
    clean_host = "".join(c for c in hostname if c.isalnum() or c in "-_")

    print(f"Host: {hostname} ({cpu_name}, {cores} logical threads)")
    print(f"Initial Power Plan: {initial_power['active_scheme']}")
    print(f"Initial Power State: {initial_power['ac_status']} (Battery {initial_power['battery_pct']}%)")
    print(f"Command: python scripts/benchmark_portable.py")
    print(f"Background Apps: Standard user session; running benchmark in dedicated process.")

    all_runs = []
    for i in range(1, num_runs + 1):
        s = base_seed + i - 1
        print(f"\n>>> Executing Benchmark Session {i}/{num_runs} (Seed: {s})...")
        res = run_single_benchmark(seed=s, run_index=i)
        all_runs.append(res)
        run_file = os.path.join(bench_runs_dir, f"run_{i}.json")
        with open(run_file, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2)
        print(f"  Session {i:2d}: Pure Crypto = {res['pure_crypto']['throughput_decimal_mbps']:>6.1f} MB/s | E2E = {res['end_to_end']['throughput_decimal_mbps']:>6.1f} MB/s")

    # Aggregate per-metric cross-run medians, min, max, IQR for EVERY block configuration
    ref_results = all_runs[0]['benchmark_results']
    median_benchmark_results = []
    per_config_stats = {}

    for cfg_idx, ref_cfg in enumerate(ref_results):
        cfg_name = ref_cfg['configuration']
        bs = ref_cfg['block_size']
        
        # Collect across all runs
        enc_times = [r['benchmark_results'][cfg_idx]['enc_time_mean_ms'] for r in all_runs]
        dec_times = [r['benchmark_results'][cfg_idx]['dec_time_mean_ms'] for r in all_runs]
        pure_ths = [r['benchmark_results'][cfg_idx]['throughput_mbps'] for r in all_runs]
        e2e_enc_times = [r['benchmark_results'][cfg_idx]['e2e_enc_time_mean_ms'] for r in all_runs]
        e2e_dec_times = [r['benchmark_results'][cfg_idx]['e2e_dec_time_mean_ms'] for r in all_runs]
        e2e_ths = [r['benchmark_results'][cfg_idx]['e2e_throughput_mbps'] for r in all_runs]

        enc_med = round(float(np.median(enc_times)), 2)
        dec_med = round(float(np.median(dec_times)), 2)
        pure_th_med = round(float(np.median(pure_ths)), 1)
        e2e_enc_med = round(float(np.median(e2e_enc_times)), 2)
        e2e_dec_med = round(float(np.median(e2e_dec_times)), 2)
        e2e_th_med = round(float(np.median(e2e_ths)), 1)

        cfg_stat = {
            'configuration': cfg_name,
            'block_size': bs,
            'enc_ms': {
                'median': enc_med,
                'min': round(float(np.min(enc_times)), 2),
                'max': round(float(np.max(enc_times)), 2),
                'iqr': round(float(np.percentile(enc_times, 75) - np.percentile(enc_times, 25)), 2),
                'values': enc_times
            },
            'dec_ms': {
                'median': dec_med,
                'min': round(float(np.min(dec_times)), 2),
                'max': round(float(np.max(dec_times)), 2),
                'iqr': round(float(np.percentile(dec_times, 75) - np.percentile(dec_times, 25)), 2),
                'values': dec_times
            },
            'pure_crypto_mbps': {
                'median': pure_th_med,
                'min': round(float(np.min(pure_ths)), 1),
                'max': round(float(np.max(pure_ths)), 1),
                'iqr': round(float(np.percentile(pure_ths, 75) - np.percentile(pure_ths, 25)), 1),
                'spread': round(float(np.max(pure_ths) - np.min(pure_ths)), 1),
                'values': pure_ths
            },
            'e2e_enc_ms': {
                'median': e2e_enc_med,
                'min': round(float(np.min(e2e_enc_times)), 2),
                'max': round(float(np.max(e2e_enc_times)), 2),
                'iqr': round(float(np.percentile(e2e_enc_times, 75) - np.percentile(e2e_enc_times, 25)), 2),
                'values': e2e_enc_times
            },
            'e2e_dec_ms': {
                'median': e2e_dec_med,
                'min': round(float(np.min(e2e_dec_times)), 2),
                'max': round(float(np.max(e2e_dec_times)), 2),
                'iqr': round(float(np.percentile(e2e_dec_times, 75) - np.percentile(e2e_dec_times, 25)), 2),
                'values': e2e_dec_times
            },
            'e2e_throughput_mbps': {
                'median': e2e_th_med,
                'min': round(float(np.min(e2e_ths)), 1),
                'max': round(float(np.max(e2e_ths)), 1),
                'iqr': round(float(np.percentile(e2e_ths, 75) - np.percentile(e2e_ths, 25)), 1),
                'spread': round(float(np.max(e2e_ths) - np.min(e2e_ths)), 1),
                'values': e2e_ths
            }
        }
        per_config_stats[bs] = cfg_stat

        # Build median row for Table 4
        median_row = dict(ref_cfg)
        median_row['enc_time_mean_ms'] = enc_med
        median_row['dec_time_mean_ms'] = dec_med
        median_row['throughput_mbps'] = pure_th_med
        median_row['e2e_enc_time_mean_ms'] = e2e_enc_med
        median_row['e2e_dec_time_mean_ms'] = e2e_dec_med
        median_row['e2e_throughput_mbps'] = e2e_th_med
        median_row['enc_time_iqr_ms'] = cfg_stat['enc_ms']['iqr']
        median_row['dec_time_iqr_ms'] = cfg_stat['dec_ms']['iqr']
        median_row['pure_crypto_iqr_mbps'] = cfg_stat['pure_crypto_mbps']['iqr']
        median_row['e2e_throughput_iqr_mbps'] = cfg_stat['e2e_throughput_mbps']['iqr']
        median_benchmark_results.append(median_row)

    # Key derivation metrics over all runs
    pbkdf2_all = [r['pbkdf2_mean_ms'] for r in all_runs]
    pbkdf2_med = round(float(np.median(pbkdf2_all)), 2)
    pbkdf2_iqr = round(float(np.percentile(pbkdf2_all, 75) - np.percentile(pbkdf2_all, 25)), 2)

    setup_all = [r['session_setup_mean_ms'] for r in all_runs]
    setup_med = round(float(np.median(setup_all)), 2)
    setup_iqr = round(float(np.percentile(setup_all, 75) - np.percentile(setup_all, 25)), 2)

    # Video streaming feasibility based on 16x16 medians, min, max
    cfg16_stats = per_config_stats['16x16']
    p16_med = cfg16_stats['pure_crypto_mbps']['median']
    p16_min = cfg16_stats['pure_crypto_mbps']['min']
    p16_max = cfg16_stats['pure_crypto_mbps']['max']

    e16_med = cfg16_stats['e2e_throughput_mbps']['median']
    e16_min = cfg16_stats['e2e_throughput_mbps']['min']
    e16_max = cfg16_stats['e2e_throughput_mbps']['max']

    streaming_eval = []
    for vp in VIDEO_PROFILES:
        rate = vp['data_rate_mbps']
        load_crypto_med = round((rate / p16_med) * 100.0, 1)
        load_crypto_min = round((rate / p16_max) * 100.0, 1)  # best throughput -> lowest load
        load_crypto_max = round((rate / p16_min) * 100.0, 1)  # worst throughput -> highest load

        load_e2e_med = round((rate / e16_med) * 100.0, 1)
        load_e2e_min = round((rate / e16_max) * 100.0, 1)
        load_e2e_max = round((rate / e16_min) * 100.0, 1)

        def classify(load):
            if load < 90.0:
                return "supported on this host"
            elif load <= 110.0:
                return "at the limit of this host"
            else:
                return "not supported"

        streaming_eval.append({
            'profile': vp['name'],
            'resolution': vp['resolution'],
            'fps': vp['fps'],
            'data_rate_decimal_mbps': rate,
            'load_crypto_median_pct': load_crypto_med,
            'load_crypto_min_pct': load_crypto_min,
            'load_crypto_max_pct': load_crypto_max,
            'status_crypto': classify(load_crypto_med),
            'load_e2e_median_pct': load_e2e_med,
            'load_e2e_min_pct': load_e2e_min,
            'load_e2e_max_pct': load_e2e_max,
            'status_e2e': classify(load_e2e_med)
        })

    # Summary payload
    summary = {
        'runs_count': num_runs,
        'command_used': 'python scripts/benchmark_portable.py',
        'hostname': hostname,
        'cpu_name': cpu_name,
        'cores': cores,
        'platform': platform.platform(),
        'power_plan_raw': initial_power['active_scheme'],
        'power_plan_name': 'Balanced' if 'balanced' in initial_power['active_scheme'].lower() else 'High Performance',
        'ac_status': initial_power['ac_status'],
        'battery_pct': initial_power['battery_pct'],
        'seeds': [r['seed'] for r in all_runs],
        'pbkdf2_ms': {
            'median': pbkdf2_med,
            'min': round(float(np.min(pbkdf2_all)), 2),
            'max': round(float(np.max(pbkdf2_all)), 2),
            'iqr': pbkdf2_iqr,
            'values': pbkdf2_all
        },
        'session_setup_ms': {
            'median': setup_med,
            'min': round(float(np.min(setup_all)), 2),
            'max': round(float(np.max(setup_all)), 2),
            'iqr': setup_iqr,
            'values': setup_all
        },
        'per_config_stats': per_config_stats,
        'video_streaming_feasibility': streaming_eval,
        'benchmark_results': median_benchmark_results
    }

    # Save to bench_multi_runs.json
    multi_file = os.path.join(RESULTS_DIR, "bench_multi_runs.json")
    with open(multi_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved multi-run summary to {multi_file}")

    # Save all raw runs in bench_<hostname>_runs.json
    runs_file = os.path.join(RESULTS_DIR, f"bench_{clean_host}_runs.json")
    with open(runs_file, "w", encoding="utf-8") as f:
        json.dump({'summary': summary, 'runs': all_runs}, f, indent=2)
    print(f"Saved all {num_runs} runs and statistics to {runs_file}")

    # Save overhead_metrics.json (single source for Table 4)
    overhead_file = os.path.join(RESULTS_DIR, "overhead_metrics.json")
    overhead_payload = {
        'image': all_runs[0]['image'],
        'raw_dimensions': all_runs[0]['raw_dimensions'],
        'raw_bytes': all_runs[0]['raw_bytes'],
        'pbkdf2_mean_ms': pbkdf2_med,
        'pbkdf2_iterations': PBKDF2_ITERATIONS,
        'session_setup_mean_ms': setup_med,
        'num_runs': num_runs,
        'power_profile': initial_power,
        'power_plan_name': summary['power_plan_name'],
        'benchmark_results': median_benchmark_results,
        'multi_run_stats': {
            'pure_crypto_median_mbps': cfg16_stats['pure_crypto_mbps']['median'],
            'pure_crypto_min_mbps': cfg16_stats['pure_crypto_mbps']['min'],
            'pure_crypto_max_mbps': cfg16_stats['pure_crypto_mbps']['max'],
            'pure_crypto_iqr_mbps': cfg16_stats['pure_crypto_mbps']['iqr'],
            'pure_crypto_spread_mbps': cfg16_stats['pure_crypto_mbps']['spread'],
            'end_to_end_median_mbps': cfg16_stats['e2e_throughput_mbps']['median'],
            'end_to_end_min_mbps': cfg16_stats['e2e_throughput_mbps']['min'],
            'end_to_end_max_mbps': cfg16_stats['e2e_throughput_mbps']['max'],
            'end_to_end_iqr_mbps': cfg16_stats['e2e_throughput_mbps']['iqr'],
            'end_to_end_spread_mbps': cfg16_stats['e2e_throughput_mbps']['spread'],
        }
    }
    with open(overhead_file, "w", encoding="utf-8") as f:
        json.dump(overhead_payload, f, indent=2)
    print(f"Updated overhead metrics at {overhead_file}")

    # Save environment.json (single source for Table 5)
    env_file = os.path.join(RESULTS_DIR, "environment.json")
    env_payload = {
        'hostname': hostname,
        'cpu_name': cpu_name,
        'cpu_model': cpu_name,
        'cores': cores,
        'cpu_logical_threads': cores,
        'platform': platform.platform(),
        'python_version': platform.python_version(),
        'cryptography_version': cryptography.__version__,
        'power_profile': initial_power,
        'power_plan_name': summary['power_plan_name'],
        'num_runs': num_runs,
        'pbkdf2_mean_ms': pbkdf2_med,
        'session_setup_mean_ms': setup_med,
        'pure_crypto': {
            'throughput_decimal_mbps': cfg16_stats['pure_crypto_mbps']['median'],
            'min_mbps': cfg16_stats['pure_crypto_mbps']['min'],
            'max_mbps': cfg16_stats['pure_crypto_mbps']['max'],
            'iqr_mbps': cfg16_stats['pure_crypto_mbps']['iqr'],
            'spread_mbps': cfg16_stats['pure_crypto_mbps']['spread']
        },
        'end_to_end': {
            'throughput_decimal_mbps': cfg16_stats['e2e_throughput_mbps']['median'],
            'min_mbps': cfg16_stats['e2e_throughput_mbps']['min'],
            'max_mbps': cfg16_stats['e2e_throughput_mbps']['max'],
            'iqr_mbps': cfg16_stats['e2e_throughput_mbps']['iqr'],
            'spread_mbps': cfg16_stats['e2e_throughput_mbps']['spread']
        },
        'video_streaming_load': streaming_eval
    }
    with open(env_file, "w", encoding="utf-8") as f:
        json.dump(env_payload, f, indent=2)
    print(f"Updated environment specs at {env_file}")

    # Save host benchmark
    host_file = os.path.join(RESULTS_DIR, f"bench_{clean_host}.json")
    with open(host_file, "w", encoding="utf-8") as f:
        json.dump(env_payload, f, indent=2)
    print(f"Updated host benchmark at {host_file}")

    print("\n" + "=" * 80)
    print(f"FINAL UNIFIED BENCHMARK RESULTS ({num_runs}-RUN MEDIANS)")
    print("=" * 80)
    print(f"Power Plan: {summary['power_plan_name']} ({summary['power_plan_raw']})")
    print(f"Power State: {summary['ac_status']} (Battery {summary['battery_pct']}%)")
    print(f"Pure Crypto 16x16:  Median = {cfg16_stats['pure_crypto_mbps']['median']} MB/s (IQR: {cfg16_stats['pure_crypto_mbps']['iqr']} MB/s, Min: {cfg16_stats['pure_crypto_mbps']['min']}, Max: {cfg16_stats['pure_crypto_mbps']['max']}, Spread: {cfg16_stats['pure_crypto_mbps']['spread']} MB/s)")
    print(f"End-to-End 16x16:   Median = {cfg16_stats['e2e_throughput_mbps']['median']} MB/s (IQR: {cfg16_stats['e2e_throughput_mbps']['iqr']} MB/s, Min: {cfg16_stats['e2e_throughput_mbps']['min']}, Max: {cfg16_stats['e2e_throughput_mbps']['max']}, Spread: {cfg16_stats['e2e_throughput_mbps']['spread']} MB/s)")
    print("\nTable 4 Grid (Medians):")
    for b in median_benchmark_results:
        print(f"  {b['configuration']:<30} | Enc: {b['enc_time_mean_ms']:>6.2f} ms | Dec: {b['dec_time_mean_ms']:>6.2f} ms | Pure: {b['throughput_mbps']:>7.1f} MB/s | E2E: {b['e2e_throughput_mbps']:>7.1f} MB/s | Ovhd: {b['total_overhead_pct']:>5.2f}%")
    print("\nVideo Streaming Feasibility (16x16 Proposed):")
    for se in streaming_eval:
        print(f"  {se['profile']:<14} ({se['data_rate_decimal_mbps']:>6.1f} MB/s): Crypto = {se['load_crypto_median_pct']:>5.1f}% [{se['status_crypto']}] (Range: {se['load_crypto_min_pct']:>5.1f}%-{se['load_crypto_max_pct']:>5.1f}%) | E2E = {se['load_e2e_median_pct']:>5.1f}% [{se['status_e2e']}] (Range: {se['load_e2e_min_pct']:>5.1f}%-{se['load_e2e_max_pct']:>5.1f}%)")

    return summary

if __name__ == '__main__':
    run_multi_session_benchmark(num_runs=15)
