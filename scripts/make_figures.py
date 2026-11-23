"""Generates publication-quality figures (PDF and high-res PNG) for the paper.
Reads results/*.json, loads input/submarine.jpg, and produces figures in figures/ and paper_icmlde/figures/.
"""

import os
import sys

# Ensure matplotlib uses a local writable cache dir in sandbox
os.environ['MPLCONFIGDIR'] = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'results', '.mplconfig'))
os.makedirs(os.environ['MPLCONFIGDIR'], exist_ok=True)

import json
import shutil
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from PIL import Image

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, RESULTS_DIR, FIGURES_DIR, INPUT_DIR
from src.image_processor import load_image, pad_image, unpad_image, split_into_blocks, merge_blocks
from src.encryption import encrypt_blocks
from src.decryption import decrypt_blocks
from src.error_concealment import conceal_failed_blocks
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id
from src.baseline_ciphers import cbc_encrypt_monolithic, cbc_decrypt_monolithic

# Set font and styling for publication
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 11
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['legend.fontsize'] = 9
plt.rcParams['figure.titlesize'] = 12

PAPER_FIG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'paper_icmlde', 'figures'))
os.makedirs(FIGURES_DIR, exist_ok=True)
os.makedirs(PAPER_FIG_DIR, exist_ok=True)

def load_json(name):
    with open(os.path.join(RESULTS_DIR, name), 'r', encoding='utf-8') as f:
        return json.load(f)

# -----------------------------------------------------------------------------
# Figure 1: Architecture Diagram
# -----------------------------------------------------------------------------
def generate_fig1_architecture():
    fig, ax = plt.subplots(figsize=(10.5, 3.5), dpi=300)
    ax.axis('off')

    box_props = dict(boxstyle='round,pad=0.5', facecolor='#F0F4F8', edgecolor='#1F4E79', linewidth=1.5)
    sender_props = dict(boxstyle='round,pad=0.5', facecolor='#E2F0D9', edgecolor='#385723', linewidth=1.5)
    rx_props = dict(boxstyle='round,pad=0.5', facecolor='#FFF2CC', edgecolor='#D6B656', linewidth=1.5)
    ml_props = dict(boxstyle='round,pad=0.5', facecolor='#FCE4D6', edgecolor='#C65911', linewidth=1.5)

    ax.text(0.12, 0.75, "Sender / IoT Node\n\n- PBKDF2-HMAC (600k rounds)\n- HKDF Bound Key Schedule\n- Session Header Auth\n- Block-wise AES-256-GCM\n- 800B Framed Records", 
            ha='center', va='center', bbox=sender_props, fontsize=8)

    ax.text(0.38, 0.75, "Untrusted Channel\n\n- In-place Bit Corruption\n- Record Deletion / Loss\n- Block Splicing & Swapping\n- Stale Epoch Replay", 
            ha='center', va='center', bbox=box_props, fontsize=8)

    ax.text(0.66, 0.75, "Receiver Engine\n\n- Replay Rejection & DRL Gate\n- Monotonic Epoch Check\n- Per-Block GHASH Verification\n- Tag-Directed Concealment", 
            ha='center', va='center', bbox=rx_props, fontsize=8)

    ax.text(0.90, 0.75, "Downstream ML\n\n- MobileNetV2 Pipeline\n- Retention under Corruption\n- Zero Retransmission Delay\n- High Availability", 
            ha='center', va='center', bbox=ml_props, fontsize=8)

    # Arrows
    arrow_props = dict(arrowstyle="->", lw=2, color='#1F4E79')
    ax.annotate('', xy=(0.25, 0.75), xytext=(0.21, 0.75), arrowprops=arrow_props)
    ax.annotate('', xy=(0.52, 0.75), xytext=(0.48, 0.75), arrowprops=arrow_props)
    ax.annotate('', xy=(0.79, 0.75), xytext=(0.76, 0.75), arrowprops=arrow_props)

    # Framing structure
    ax.text(0.5, 0.24, "Transmitted Record Framing (800 Bytes per $16\\times 16$ Block, 4.17% Overhead):", ha='center', fontsize=9, fontweight='bold')
    
    colors = ['#BDD7EE', '#F8CBAD', '#D9E1F2', '#C6E0B4']
    widths = [0.14, 0.16, 0.42, 0.18]
    labels = ['Index (4B)\nBig-Endian Header', 'Nonce IV (12B)\n96-bit AES-GCM IV', 'Ciphertext (768B)\nAES-256 CTR Keystream', 'Auth Tag (16B)\nGHASH AAD Bound']
    
    x_curr = 0.05
    y_box = 0.04
    h_box = 0.13
    for c, w, l in zip(colors, widths, labels):
        rect = patches.Rectangle((x_curr, y_box), w, h_box, facecolor=c, edgecolor='black', linewidth=1.2)
        ax.add_patch(rect)
        ax.text(x_curr + w/2, y_box + h_box/2, l, ha='center', va='center', fontsize=7.5, fontweight='bold')
        x_curr += w + 0.01

    plt.tight_layout()
    pdf_path = os.path.join(FIGURES_DIR, 'fig1_architecture.pdf')
    png_path = os.path.join(FIGURES_DIR, 'fig1_architecture.png')
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.savefig(png_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Generated {pdf_path} and {png_path}")

# -----------------------------------------------------------------------------
# Figure 2: Visual Comparison (K=25 Deterministic Trial)
# -----------------------------------------------------------------------------
def generate_fig2_visual_containment():
    fig2_metrics = load_json('fig2_metrics.json')
    sub_path = os.path.join(INPUT_DIR, 'submarine.jpg')
    orig_arr = load_image(sub_path)
    padded_arr, orig_shape = pad_image(orig_arr, 16)
    tot = (padded_arr.shape[0] // 16) * (padded_arr.shape[1] // 16)
    grid_shape = (padded_arr.shape[0] // 16, padded_arr.shape[1] // 16)
    block_shape = (16, 16, 3)
    
    import random
    rng = random.Random(fig2_metrics['trial_seed'])
    corr_indices = sorted(rng.sample(range(tot), fig2_metrics['K']))
    
    sess = generate_session_key()
    hs = generate_salt()
    ps = generate_salt()
    key = derive_key(sess, hs, ps, "Fig2DeterministicSecretKey2026!", get_device_id(), 0)
    
    blocks = split_into_blocks(padded_arr, 16)
    records = encrypt_blocks(blocks, key, padded_arr.shape, epoch=0)
    corrupted_records = list(records)
    for idx in corr_indices:
        r = bytearray(corrupted_records[idx])
        r[16] ^= 0xFF
        corrupted_records[idx] = bytes(r)
        
    # Monolithic GCM
    mono_img = np.zeros_like(orig_arr)
    
    # Unframed CBC
    flat = padded_arr.tobytes()
    iv_cbc, ct_cbc = cbc_encrypt_monolithic(flat, key)
    ct_corrupt = bytearray(ct_cbc)
    for idx in sorted(corr_indices, reverse=True):
        off = idx * 768
        if off + 16 <= len(ct_corrupt):
            del ct_corrupt[off:off+16]
    pt_cbc = cbc_decrypt_monolithic(iv_cbc, bytes(ct_corrupt), key)
    if len(pt_cbc) < len(flat):
        pt_cbc = pt_cbc + b"\x00" * (len(flat) - len(pt_cbc))
    cbc_padded = np.frombuffer(pt_cbc[:len(flat)], dtype=np.uint8).reshape(padded_arr.shape)
    cbc_img = unpad_image(cbc_padded, orig_shape)
    
    # Proposed Raw
    dec_raw = decrypt_blocks(corrupted_records, key, padded_arr.shape, block_shape, tot, epoch=0, enable_concealment=False)
    raw_img = unpad_image(merge_blocks(dec_raw['blocks'], padded_arr.shape), orig_shape)
    
    # Proposed Concealed
    conc_blocks = conceal_failed_blocks(dec_raw['blocks'], dec_raw['failed_indices'], grid_shape, block_shape)
    conc_img = unpad_image(merge_blocks(conc_blocks, padded_arr.shape), orig_shape)

    fig, axes = plt.subplots(1, 5, figsize=(15, 3.2), dpi=300)
    
    titles = [
        "(a) Original Clean\n(1199x460 Submarine)",
        "(b) Monolithic AES-GCM\n(0% Avail., Aborted)",
        f"(c) Unframed AES-CBC\n(Desync, {fig2_metrics['cbc_psnr']:.2f} dB)",
        f"(d) Proposed Raw\n(Isolated, {fig2_metrics['raw_psnr']:.2f} dB)",
        f"(e) Proposed Concealed\n(Restored, {fig2_metrics['conc_psnr']:.2f} dB)"
    ]
    imgs = [orig_arr, mono_img, cbc_img, raw_img, conc_img]

    for ax, t, im in zip(axes, titles, imgs):
        ax.imshow(im)
        ax.set_title(t, fontsize=9.5, pad=6)
        ax.axis('off')

    plt.tight_layout()
    pdf_path = os.path.join(FIGURES_DIR, 'fig2_visual_containment.pdf')
    png_path = os.path.join(FIGURES_DIR, 'fig2_visual_containment.png')
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.savefig(png_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Generated {pdf_path} and {png_path}")

# -----------------------------------------------------------------------------
# Figure 3: PSNR vs Corrupted Blocks K
# -----------------------------------------------------------------------------
def generate_fig3_psnr():
    data = load_json('containment_metrics.json')
    k_vals = [r['corrupted_blocks'] for r in data if r['corrupted_blocks'] > 0]
    
    cbc_u_psnr = [r['cbc_loss_psnr_mean'] for r in data if r['corrupted_blocks'] > 0]
    cbc_f_psnr = [r['cbc_framed_psnr_mean'] for r in data if r['corrupted_blocks'] > 0]
    raw_psnr = [r['gcm_psnr_raw_mean'] for r in data if r['corrupted_blocks'] > 0]
    conc_psnr = [r['gcm_psnr_conc_mean'] for r in data if r['corrupted_blocks'] > 0]
    mono_psnr = [0.0 for _ in k_vals]

    fig, ax = plt.subplots(figsize=(6.5, 4.2), dpi=300)
    
    ax.plot(k_vals, conc_psnr, 'o-', color='#2CA02C', lw=2.2, markersize=6, label='Proposed Scheme (Concealed)')
    ax.plot(k_vals, raw_psnr, 's--', color='#1F77B4', lw=1.8, markersize=5, label='Proposed Scheme (Raw Zero-Mask)')
    ax.plot(k_vals, cbc_f_psnr, 'd-.', color='#FF7F0E', lw=1.8, markersize=5, label='Framed AES-CBC (Packet Loss)')
    ax.plot(k_vals, cbc_u_psnr, '^-.', color='#D62728', lw=1.8, markersize=5, label='Unframed AES-CBC (Stream Loss)')
    ax.plot(k_vals, mono_psnr, 'x:', color='#7F7F7F', lw=1.8, markersize=6, label='Monolithic AES-GCM (Payload Aborted)')

    ax.set_xlabel("Number of Corrupted / Lost Blocks ($K$)")
    ax.set_ylabel("Reconstruction PSNR (dB)")
    ax.set_title("Error Containment: Image Quality vs Transmission Corruption", pad=10)
    ax.grid(True, linestyle='--', alpha=0.6)
    ax.legend(frameon=True, loc='upper right', fontsize=8.5)
    ax.set_ylim(-2, 50)

    plt.tight_layout()
    pdf_path = os.path.join(FIGURES_DIR, 'fig3_psnr_containment.pdf')
    png_path = os.path.join(FIGURES_DIR, 'fig3_psnr_containment.png')
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.savefig(png_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Generated {pdf_path} and {png_path}")

# -----------------------------------------------------------------------------
# Figure 4: Computational and Framing Overhead Trade-off
# -----------------------------------------------------------------------------
def generate_fig4_overhead():
    overhead_meta = load_json('overhead_metrics.json')
    results = overhead_meta.get('benchmark_results', overhead_meta) if isinstance(overhead_meta, dict) else overhead_meta
    blocks = [b for b in results if not b['configuration'].startswith('Monolithic')]
    
    labels = [b['block_size'] for b in blocks]
    enc_times = [b['enc_time_mean_ms'] for b in blocks]
    overheads = [b['total_overhead_pct'] for b in blocks]

    x = np.arange(len(labels))
    width = 0.35

    fig, ax1 = plt.subplots(figsize=(6.5, 4.0), dpi=300)

    color1 = '#1F4E79'
    ax1.set_xlabel('Block Granularity ($B \\times B$ Pixels)')
    ax1.set_ylabel('Encryption Latency (ms)', color=color1)
    bars1 = ax1.bar(x - width/2, enc_times, width, label='Encryption Time (ms)', color=color1, alpha=0.85)
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_ylim(0, max(enc_times) * 1.3)

    ax2 = ax1.twinx()
    color2 = '#C65911'
    ax2.set_ylabel('Framing Overhead (%)', color=color2)
    bars2 = ax2.bar(x + width/2, overheads, width, label='Framing Overhead (%)', color=color2, alpha=0.85)
    ax2.tick_params(axis='y', labelcolor=color2)
    ax2.set_ylim(0, max(overheads) * 1.3)

    ax1.set_xticks(x)
    ax1.set_xticklabels(labels)
    ax1.set_title("Computational Latency vs. Framing Overhead Trade-off", pad=10)

    # Dynamic annotation from measured data
    prop_enc = enc_times[1]  # 16x16
    prop_oh = overheads[1]
    ax1.annotate(f'Selected Operating Point\n({prop_enc:.2f} ms, {prop_oh:.2f}% Overhead)', 
                 xy=(1 - width/2, prop_enc), xytext=(1.2, prop_enc * 1.8),
                 arrowprops=dict(facecolor='black', shrink=0.05, width=1, headwidth=6),
                 fontsize=8.5, ha='left')

    plt.tight_layout()
    pdf_path = os.path.join(FIGURES_DIR, 'fig4_overhead_tradeoff.pdf')
    png_path = os.path.join(FIGURES_DIR, 'fig4_overhead_tradeoff.png')
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.savefig(png_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Generated {pdf_path} and {png_path}")

# -----------------------------------------------------------------------------
# Figure 5: Downstream Machine Learning Pipeline Robustness
# -----------------------------------------------------------------------------
def generate_fig5_ml():
    ml_data = load_json('ml_downstream.json')
    results = ml_data.get('results', ml_data) if isinstance(ml_data, dict) else ml_data

    corrupt_pcts = [r['corrupted_fraction_pct'] for r in results]
    mono = [r['mono_gcm_agreement_pct'] for r in results]
    cbc_u = [r['cbc_unframed_agreement_mean_pct'] for r in results]
    cbc_f = [r.get('cbc_framed_agreement_mean_pct', r['proposed_zero_agreement_mean_pct']) for r in results]
    zero = [r['proposed_zero_agreement_mean_pct'] for r in results]
    conc = [r['proposed_conc_agreement_mean_pct'] for r in results]

    fig, ax = plt.subplots(figsize=(6.5, 4.2), dpi=300)

    ax.plot(corrupt_pcts, conc, 'o-', color='#2CA02C', lw=2.2, markersize=6, label='Proposed Scheme (Concealed)')
    ax.plot(corrupt_pcts, zero, 's--', color='#1F77B4', lw=1.8, markersize=5, label='Proposed Scheme (Zero-Masked)')
    ax.plot(corrupt_pcts, cbc_f, 'd-.', color='#FF7F0E', lw=1.8, markersize=5, label='Framed AES-CBC (Packet Loss)')
    ax.plot(corrupt_pcts, cbc_u, '^-.', color='#D62728', lw=1.8, markersize=5, label='Unframed AES-CBC (Stream Loss)')
    ax.plot(corrupt_pcts, mono, 'x:', color='#7F7F7F', lw=1.8, markersize=6, label='Monolithic AES-GCM (0% Avail.)')

    ax.set_xlabel("Transmission Block Corruption Rate (%)")
    ax.set_ylabel("MobileNetV2 Top-1 Classification Agreement (%)")
    ax.set_title("Downstream ML Pipeline Robustness Under Adversarial Channel", pad=10)
    ax.grid(True, linestyle='--', alpha=0.6)
    ax.legend(frameon=True, loc='lower left', fontsize=8.5)
    ax.set_ylim(-2, 105)

    plt.tight_layout()
    pdf_path = os.path.join(FIGURES_DIR, 'fig5_ml_downstream.pdf')
    png_path = os.path.join(FIGURES_DIR, 'fig5_ml_downstream.png')
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.savefig(png_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Generated {pdf_path} and {png_path}")

# -----------------------------------------------------------------------------
# Figure 6: Multi-Image Error Containment & Concealment Gain Summary
# -----------------------------------------------------------------------------
def generate_fig6_multi_image():
    multi_path = os.path.join(RESULTS_DIR, 'containment_multi_image_full.json')
    if not os.path.exists(multi_path):
        return
    with open(multi_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    images = ['cameraman', 'baboon', 'peppers', 'medical_mri', 'submarine', 'satellite']
    colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']
    markers = ['o', 's', '^', 'D', 'v', 'p']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.2), dpi=300)

    for img_key, color, m in zip(images, colors, markers):
        if img_key not in data.get('results_per_image', {}):
            continue
        info = data['results_per_image'][img_key]
        rows = info.get('fraction_rows', [])
        fractions = [r['actual_fraction_pct'] for r in rows]
        raw_psnrs = [r['proposed_raw_psnr_mean'] for r in rows]
        conc_psnrs = [r['proposed_conc_psnr_mean'] for r in rows]
        gains = [r['proposed_gain_mean_db'] for r in rows]

        label_name = img_key.replace('_', ' ').title()
        ax1.plot(fractions, conc_psnrs, marker=m, color=color, lw=1.8, markersize=5, label=f"{label_name}")
        ax1.plot(fractions, raw_psnrs, marker=m, color=color, lw=1.0, linestyle=':', alpha=0.5)

        ax2.plot(fractions, gains, marker=m, color=color, lw=1.8, markersize=5, label=f"{label_name}")

    ax1.set_xlabel("Corrupted Area Fraction $f$ (%)")
    ax1.set_ylabel("Reconstruction PSNR (dB)")
    ax1.set_title("(a) Reconstruction PSNR (Solid: Concealed, Dotted: Raw)")
    ax1.grid(True, linestyle='--', alpha=0.6)
    ax1.legend(frameon=True, fontsize=8, loc='upper right')

    ax2.set_xlabel("Corrupted Area Fraction $f$ (%)")
    ax2.set_ylabel("Concealment Gain $\\Delta$PSNR (dB)")
    ax2.set_title("(b) Spatial Concealment Gain Across Images")
    ax2.grid(True, linestyle='--', alpha=0.6)
    ax2.legend(frameon=True, fontsize=8, loc='upper right')

    plt.tight_layout()
    pdf_path = os.path.join(FIGURES_DIR, 'fig6_multi_image_containment.pdf')
    png_path = os.path.join(FIGURES_DIR, 'fig6_multi_image_containment.png')
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.savefig(png_path, bbox_inches='tight', dpi=300)
    plt.close()
    print(f"Generated {pdf_path} and {png_path}")

def sync_figures_to_paper():
    for f in os.listdir(FIGURES_DIR):
        if f.endswith(('.png', '.pdf')):
            shutil.copy2(os.path.join(FIGURES_DIR, f), os.path.join(PAPER_FIG_DIR, f))
    print(f"Synced figures to {PAPER_FIG_DIR}")

def main():
    print("Generating all publication figures...")
    generate_fig1_architecture()
    generate_fig2_visual_containment()
    generate_fig3_psnr()
    generate_fig4_overhead()
    generate_fig5_ml()
    generate_fig6_multi_image()
    sync_figures_to_paper()
    print("All figures generated and synced.")

if __name__ == '__main__':
    main()
