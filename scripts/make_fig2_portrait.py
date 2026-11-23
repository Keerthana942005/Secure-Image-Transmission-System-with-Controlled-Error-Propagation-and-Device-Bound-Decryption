import os
import sys
import json
import random
import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Set local mplconfigdir
os.environ['MPLCONFIGDIR'] = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'results', '.mplconfig'))
os.makedirs(os.environ['MPLCONFIGDIR'], exist_ok=True)

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import INPUT_DIR, FIGURES_DIR
from src.image_processor import load_image, pad_image, unpad_image, split_into_blocks, merge_blocks
from src.encryption import encrypt_blocks
from src.decryption import decrypt_blocks
from src.error_concealment import conceal_failed_blocks
from src.key_manager import generate_session_key, generate_salt, derive_key, get_device_id
from src.baseline_ciphers import cbc_encrypt_monolithic, cbc_decrypt_monolithic

def generate_portrait_figure():
    with open('results/fig2_metrics.json') as f:
        fig2_metrics = json.load(f)

    sub_path = os.path.join(INPUT_DIR, 'submarine.jpg')
    orig_arr = load_image(sub_path)
    padded_arr, orig_shape = pad_image(orig_arr, 16)
    tot = (padded_arr.shape[0] // 16) * (padded_arr.shape[1] // 16)
    grid_shape = (padded_arr.shape[0] // 16, padded_arr.shape[1] // 16)
    block_shape = (16, 16, 3)

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

    # (a) Original
    im_a = Image.fromarray(orig_arr)

    # (b) Monolithic GCM (0% availability, black image)
    im_b = Image.fromarray(np.zeros_like(orig_arr))

    # (c) Unframed CBC
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
    im_c = Image.fromarray(unpad_image(cbc_padded, orig_shape))

    # (d) Proposed Raw
    dec_raw = decrypt_blocks(corrupted_records, key, padded_arr.shape, block_shape, tot, epoch=0, enable_concealment=False)
    raw_img = unpad_image(merge_blocks(dec_raw['blocks'], padded_arr.shape), orig_shape)
    im_d = Image.fromarray(raw_img)

    # (e) Proposed Concealed
    conc_blocks = conceal_failed_blocks(dec_raw['blocks'], dec_raw['failed_indices'], grid_shape, block_shape)
    conc_img = unpad_image(merge_blocks(conc_blocks, padded_arr.shape), orig_shape)
    im_e = Image.fromarray(conc_img)

    panels = [
        (im_a, "(a) Original Clean", "(1199x460 Submarine)"),
        (im_b, "(b) Monolithic AES-GCM", "(0% Avail., Aborted)"),
        (im_c, "(c) Unframed AES-CBC", f"(Desync, {fig2_metrics['cbc_psnr']:.2f} dB)"),
        (im_d, "(d) Proposed Raw", f"(Isolated, {fig2_metrics['raw_psnr']:.2f} dB)"),
        (im_e, "(e) Proposed Concealed", f"(Restored, {fig2_metrics['conc_psnr']:.2f} dB)")
    ]

    # Target width for each panel in the portrait layout
    target_pw = 1199
    target_ph = 460
    
    # We will build two versions:
    # 1. Styled with purple border and lavender background matching uploaded image
    # 2. Clean white background for direct paper / LaTeX use

    # Try to load a nice serif font or default
    font_bold = None
    font_regular = None
    for font_path in [
        "C:\\Windows\\Fonts\\timesbd.ttf",
        "C:\\Windows\\Fonts\\georgiab.ttf",
        "C:\\Windows\\Fonts\\arialbd.ttf"
    ]:
        if os.path.exists(font_path):
            font_bold = ImageFont.truetype(font_path, 28)
            break
    for font_path in [
        "C:\\Windows\\Fonts\\times.ttf",
        "C:\\Windows\\Fonts\\georgia.ttf",
        "C:\\Windows\\Fonts\\arial.ttf"
    ]:
        if os.path.exists(font_path):
            font_regular = ImageFont.truetype(font_path, 24)
            break

    if font_bold is None:
        font_bold = ImageFont.load_default()
        font_regular = font_bold

    # Dimensions
    panel_gap = 36
    title_height = 70
    inner_pad_x = 50
    inner_pad_y = 50
    outer_pad = 40
    border_radius = 24
    border_width = 3

    inner_w = target_pw + (2 * inner_pad_x)
    inner_h = (5 * target_ph) + (5 * title_height) + (4 * panel_gap) + (2 * inner_pad_y)
    
    total_w = inner_w + (2 * outer_pad)
    total_h = inner_h + (2 * outer_pad)

    print(f"Portrait canvas dimensions: {total_w} x {total_h} (Aspect ratio: {total_w/total_h:.2f})")

    # Colors
    c_outer_bg = (238, 240, 252) # Soft lavender
    c_inner_bg = (255, 255, 255) # Pure white
    c_border = (139, 92, 246)    # Violet / Purple (#8B5CF6)
    c_text = (17, 24, 39)        # Gray 900
    c_subtext = (55, 65, 81)     # Gray 700

    canvas = Image.new("RGB", (total_w, total_h), c_outer_bg)
    draw = ImageDraw.Draw(canvas)

    # Draw rounded rectangle for inner container
    rx0 = outer_pad
    ry0 = outer_pad
    rx1 = outer_pad + inner_w
    ry1 = outer_pad + inner_h
    
    draw.rounded_rectangle(
        [rx0, ry0, rx1, ry1],
        radius=border_radius,
        fill=c_inner_bg,
        outline=c_border,
        width=border_width
    )

    # Render each panel
    cur_y = ry0 + inner_pad_y
    center_x = total_w // 2

    for img, line1, line2 in panels:
        # Measure text line 1
        bbox1 = draw.textbbox((0, 0), line1, font=font_bold)
        w1 = bbox1[2] - bbox1[0]
        h1 = bbox1[3] - bbox1[1]

        # Measure text line 2
        bbox2 = draw.textbbox((0, 0), line2, font=font_regular)
        w2 = bbox2[2] - bbox2[0]
        h2 = bbox2[3] - bbox2[1]

        # Draw line 1
        x1 = center_x - (w1 // 2)
        y1 = cur_y
        draw.text((x1, y1), line1, fill=c_text, font=font_bold)

        # Draw line 2
        x2 = center_x - (w2 // 2)
        y2 = y1 + h1 + 6
        draw.text((x2, y2), line2, fill=c_subtext, font=font_regular)

        cur_y += title_height

        # Paste panel image centered
        img_x = center_x - (target_pw // 2)
        canvas.paste(img, (img_x, cur_y))

        cur_y += target_ph + panel_gap

    # Save styled portrait version
    out_styled = os.path.join(FIGURES_DIR, "fig2_visual_containment_portrait.png")
    canvas.save(out_styled, quality=95)
    print(f"Saved styled portrait image to {out_styled}")

    # Copy to paper_icmlde/figures/
    paper_styled = os.path.join("paper_icmlde", "figures", "fig2_visual_containment_portrait.png")
    canvas.save(paper_styled, quality=95)

    # Save to artifact dir
    artifact_styled = os.path.join(r"C:\Users\lenovo\.gemini\antigravity\brain\b2f071e6-6efd-4510-b505-a90b427dbb99", "fig2_visual_containment_portrait.png")
    canvas.save(artifact_styled, quality=95)

    # Clean white version without purple outer padding (for papers/LaTeX)
    clean_canvas = canvas.crop((rx0, ry0, rx1, ry1))
    clean_out = os.path.join(FIGURES_DIR, "fig2_visual_containment_portrait_clean.png")
    clean_canvas.save(clean_out, quality=95)
    clean_paper = os.path.join("paper_icmlde", "figures", "fig2_visual_containment_portrait_clean.png")
    clean_canvas.save(clean_paper, quality=95)
    artifact_clean = os.path.join(r"C:\Users\lenovo\.gemini\antigravity\brain\b2f071e6-6efd-4510-b505-a90b427dbb99", "fig2_visual_containment_portrait_clean.png")
    clean_canvas.save(artifact_clean, quality=95)

    print("All portrait figures generated and copied successfully!")

if __name__ == '__main__':
    generate_portrait_figure()
