import os
import shutil
import pptx
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

SRC_TEMPLATE = r'C:\Users\lenovo\.gemini\antigravity\brain\b2f071e6-6efd-4510-b505-a90b427dbb99\.user_uploaded\media_1795363099272_f6238956.pptx'
OUT_PPTX = 'ICMLDE_2026_Poster_SecureImageTransmission.pptx'

# Colors
C_TITLE = RGBColor(15, 23, 42)        # Slate 900
C_HEADER = RGBColor(30, 58, 138)      # Blue 900
C_SUB = RGBColor(30, 64, 175)         # Blue 800
C_BODY = RGBColor(30, 41, 59)         # Slate 800
C_MUTED = RGBColor(71, 85, 105)       # Slate 600
C_ACCENT = RGBColor(4, 120, 87)       # Emerald 700
C_WHITE = RGBColor(255, 255, 255)
C_TABLE_BG = RGBColor(248, 250, 252)  # Slate 50
C_HIGHLIGHT_BG = RGBColor(236, 253, 245) # Emerald 50

def set_para(p, text, font_size, bold=False, italic=False, color=C_BODY, space_after=Pt(4)):
    p.text = text
    p.font.name = 'Arial'
    p.font.size = Pt(font_size)
    p.font.bold = bold
    p.font.italic = italic
    p.font.color.rgb = color
    p.space_after = space_after

def add_lead_item(tf, prefix, content, font_size=19, prefix_color=C_BODY, space_after=Pt(5)):
    p = tf.add_paragraph()
    p.text = prefix
    p.font.name = 'Arial'
    p.font.size = Pt(font_size)
    p.font.bold = True
    p.font.color.rgb = prefix_color
    r = p.add_run()
    r.text = content
    r.font.name = 'Arial'
    r.font.size = Pt(font_size)
    r.font.bold = False
    r.font.color.rgb = C_BODY
    p.space_after = space_after

def build_poster():
    print("Copying fresh template...")
    shutil.copyfile(SRC_TEMPLATE, OUT_PPTX)
    prs = pptx.Presentation(OUT_PPTX)
    slide = prs.slides[0]

    # Map shapes by name
    shapes = {s.name: s for s in slide.shapes}

    # ==================== HEADER ====================
    # 1. Title Label
    if 'Title label' in shapes:
        s = shapes['Title label']
        s.top = Inches(0.70)
        s.height = Inches(1.40)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p = tf.paragraphs[0]
        set_para(p, "Secure Image Transmission System with Controlled Error Propagation and Device-Bound Decryption", 44, bold=True, color=C_TITLE, space_after=Pt(2))

    # 2. Authors & Affiliations (TextShape 1)
    if 'TextShape 1' in shapes:
        s = shapes['TextShape 1']
        s.top = Inches(2.15)
        s.height = Inches(1.30)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Keerthana Nellyeri¹, Swetha Rajesh¹, Radhu Krishna R.¹,*", 28, bold=True, color=C_BODY, space_after=Pt(4))
        p1 = tf.add_paragraph()
        set_para(p1, "¹School of Computing, Amrita Vishwa Vidyapeetham, Amritapuri, Kollam, India    ·    *radhukr@am.amrita.edu", 21, bold=False, color=C_MUTED, space_after=Pt(0))

    # 3. Institution Logo placeholder (CustomShape 5)
    if 'CustomShape 5' in shapes:
        tf = shapes['CustomShape 5'].text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        p0.alignment = PP_ALIGN.CENTER
        set_para(p0, "AMRITA", 30, bold=True, color=RGBColor(153, 27, 27), space_after=Pt(2))
        p1 = tf.add_paragraph()
        p1.alignment = PP_ALIGN.CENTER
        set_para(p1, "Vishwa Vidyapeetham", 19, bold=True, color=RGBColor(30, 41, 59), space_after=Pt(2))
        p2 = tf.add_paragraph()
        p2.alignment = PP_ALIGN.CENTER
        set_para(p2, "School of Computing", 15, bold=False, color=C_MUTED, space_after=Pt(0))

    # 4. ICMLDE Badge
    if 'ICMLDE badge' in shapes:
        tf = shapes['ICMLDE badge'].text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        p0.alignment = PP_ALIGN.CENTER
        set_para(p0, "ICMLDE 2026", 38, bold=True, color=C_HEADER, space_after=Pt(2))
        p1 = tf.add_paragraph()
        p1.alignment = PP_ALIGN.CENTER
        set_para(p1, "5th Elsevier International Conference on Machine Learning & Data Engineering", 15, bold=False, color=C_MUTED, space_after=Pt(0))

    # ==================== COLUMN 1 ====================
    # 5. Motivation & Problem
    if 'Motivation & Problem' in shapes:
        s = shapes['Motivation & Problem']
        s.top = Inches(3.90)
        s.height = Inches(4.50)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Motivation & Problem", 34, bold=True, color=C_HEADER, space_after=Pt(6))
        
        add_lead_item(tf, "• Visual Pipelines & Edge-AI: ", 
                      "Edge-to-cloud visual pipelines in healthcare, defense, and industrial IoT transmit high-resolution images across lossy wireless channels directly into deep neural networks (DNNs).",
                      font_size=19, space_after=Pt(5))
        add_lead_item(tf, "• The Authentication Dilemma: ", 
                      "Monolithic AEAD (e.g., standard whole-image AES-GCM) drops the entire frame upon a single bit error (0% availability). Unauthenticated ciphers (e.g., AES-CBC) suffer catastrophic packet-loss desynchronization (EPR = 200.48) and allow tampered pixels to reach classifiers undetected.",
                      font_size=19, space_after=Pt(5))
        add_lead_item(tf, "• Research Question: ", 
                      "Can we strictly bound error propagation (EPR = 1.00) and enforce physical device access control while restoring visual features for downstream ML without packet retransmission?",
                      font_size=19, prefix_color=C_HEADER, space_after=Pt(0))

    # 6. Key Contributions
    if 'Key Contributions' in shapes:
        s = shapes['Key Contributions']
        s.top = Inches(8.55)
        s.height = Inches(5.10)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Key Contributions", 34, bold=True, color=C_HEADER, space_after=Pt(6))

        add_lead_item(tf, "• Block-Level AEAD Pipeline: ",
                      "Independent AES-256-GCM encryption on 16×16 blocks (800B frames) bound to 20-byte spatial and epoch AAD, guaranteeing bounded containment (EPR = 1.0000).",
                      font_size=19, space_after=Pt(5))
        add_lead_item(tf, "• Two-Factor Endpoint Binding: ",
                      "SHA-256 receiver MAC fingerprint combined with a 600,000-iteration PBKDF2 passphrase via HKDF-SHA256, restricting decryption strictly to authorized physical hardware.",
                      font_size=19, space_after=Pt(5))
        add_lead_item(tf, "• Headline Result & ML Resilience: ",
                      "Tag-directed spatial concealment recovers quarantined blocks without retransmission, achieving 83.8% MobileNetV2 top-1 agreement at 9.18% block loss (+42.1% over zero-fill) and delivering +10.78 to +26.64 dB PSNR gains across 6 benchmark images.",
                      font_size=19, prefix_color=C_ACCENT, space_after=Pt(0))

    # Teaser Picture & Caption
    if 'Figure placeholder: [Teaser figure]' in shapes:
        sp = shapes['Figure placeholder: [Teaser figure]']
        left, width = sp.left, sp.width
        sp_elem = sp._element
        sp_elem.getparent().remove(sp_elem)
        
        pic_top = Inches(13.80)
        pic_w = width
        slide.shapes.add_picture('paper_icmlde/figures/fig2_poster_grid.png', left, pic_top, width=pic_w)
        print("Inserted Figure 1 (Visual Containment Grid)")

    if 'Caption: [Teaser figure]' in shapes:
        s = shapes['Caption: [Teaser figure]']
        s.top = Inches(19.20)
        s.height = Inches(1.10)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Figure 1. Visual error containment at K = 25 corrupted blocks (1.15% loss): (a) Clean original, (b) Corrupted bitstream, (c) AES-CBC desynchronization cascade (11.03 dB), (d) Zero-fill quarantine (30.62 dB), (e) Proposed tag-directed spatial concealment (44.38 dB, +13.76 dB gain).", 17, italic=True, color=C_MUTED, space_after=Pt(0))

    # ==================== COLUMN 2 ====================
    # 7. Method Header
    if 'Method' in shapes:
        s = shapes['Method']
        s.top = Inches(3.90)
        s.height = Inches(0.70)
        tf = s.text_frame
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Method", 34, bold=True, color=C_HEADER, space_after=Pt(2))

    # Architecture Diagram & Caption
    if 'Figure placeholder: [Architecture / pipeline diagram]' in shapes:
        sp = shapes['Figure placeholder: [Architecture / pipeline diagram]']
        left, width = sp.left, sp.width
        sp_elem = sp._element
        sp_elem.getparent().remove(sp_elem)
        
        pic_top = Inches(4.70)
        pic_w = width
        slide.shapes.add_picture('paper_icmlde/figures/fig1_architecture.png', left, pic_top, width=pic_w)
        print("Inserted Figure 2 (Architecture Diagram)")

    if 'Caption: [Architecture / pipeline diagram]' in shapes:
        s = shapes['Caption: [Architecture / pipeline diagram]']
        s.top = Inches(9.45)
        s.height = Inches(0.85)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Figure 2. Proposed cross-layer architecture: from input padding and 2-factor key derivation through 800-byte framed AES-256-GCM, channel transit, GHASH tag verification, and tag-directed spatial error concealment.", 17, italic=True, color=C_MUTED, space_after=Pt(0))

    # 8. Method steps (How It Works)
    if 'Method steps' in shapes:
        s = shapes['Method steps']
        s.top = Inches(10.45)
        s.height = Inches(5.30)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "How It Works", 30, bold=True, color=C_HEADER, space_after=Pt(6))

        add_lead_item(tf, "1. Ingestion & 2-Factor Binding: ",
                      "Zero-pad image to 16×16 multiples (768B plaintext). Receiver MAC SHA-256 + 600k PBKDF2 passphrase derive 256-bit key via HKDF-SHA256, binding decryption strictly to physical hardware.",
                      font_size=19, space_after=Pt(5))
        add_lead_item(tf, "2. 800-Byte Framing & Spatial AAD: ",
                      "Each block carries 4B index ∥ 12B nonce ∥ 768B ciphertext ∥ 16B GHASH tag. 20-byte AAD = uint32(i ∥ H ∥ W ∥ N ∥ t_epoch) blocks reordering and epoch splicing attacks.",
                      font_size=19, space_after=Pt(5))
        add_lead_item(tf, "3. Tag-Directed Spatial Concealment: ",
                      "Tampered or dropped blocks fail 128-bit GHASH authentication and are isolated (EPR = 1.00). Verified orthogonal neighbors interpolate missing pixels via inverse-distance weighting without retransmission.",
                      font_size=19, space_after=Pt(0))

    # 9. Data & Experimental Setup
    if 'Data & Experimental Setup' in shapes:
        s = shapes['Data & Experimental Setup']
        s.top = Inches(15.95)
        s.height = Inches(6.85)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Data & Experimental Setup", 30, bold=True, color=C_HEADER, space_after=Pt(6))

        items = [
            ("• Datasets: ", "6 benchmark images (Cameraman 256², Baboon 512², Peppers 512², Medical MRI 512², Satellite Aerial 1024², Submarine 1200×464) + 500 ImageNet validation images (100,500 total inferences)."),
            ("• Baselines: ", "Monolithic AES-GCM (NIST SP 800-38D), Unframed AES-CBC (RFC 3602), Framed AES-CBC, Zero-Fill Quarantine, OpenCV Inpainting (Telea)."),
            ("• Metrics: ", "Shannon Entropy, NPCR (>99.60%), UACI (33.48–33.51%), Pearson correlation (|r| ≤ 0.0304), Error Propagation Radius (EPR), PSNR/SSIM, Top-1 Agreement (%)."),
            ("• Hardware & Platform: ", "13th Gen Intel Core i5-13420H (12 threads), Windows 11, Python 3.13, OpenSSL 4.0.3, cryptography 50.0.2 (AES-NI enabled), PyTorch MobileNetV2.")
        ]
        for title, desc in items:
            add_lead_item(tf, title, desc, font_size=18, space_after=Pt(4))

    # ==================== COLUMN 3 ====================
    # 10. Results Header
    if 'Results' in shapes:
        s = shapes['Results']
        s.top = Inches(3.90)
        s.height = Inches(0.70)
        tf = s.text_frame
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Results", 34, bold=True, color=C_HEADER, space_after=Pt(2))

    # 11. Table 1 (Main Results Table)
    if 'Main results table' in shapes:
        s = shapes['Main results table']
        s.top = Inches(4.70)
        s.height = Inches(3.60)
        tbl = s.table
        table_data = [
            ["Transmission Scheme", "EPR (Containment)", "PSNR at K=25", "ML Top-1 (K=18)"],
            ["Monolithic AES-GCM", "N/A (Total Drop)", "0.00 dB (Abort)", "0.0%"],
            ["Unframed AES-CBC", "200.48 (Cascade)", "11.03 dB", "23.5%"],
            ["Zero-Fill Quarantine", "1.00 (Isolated)", "30.62 dB", "41.6%"],
            ["Ours (Spatial Concealment)", "1.00 (Bounded)", "44.38 dB (+13.76 dB)", "83.8% (+42.1%)"]
        ]
        for r_idx, row in enumerate(tbl.rows):
            for c_idx, cell in enumerate(row.cells):
                cell.text = table_data[r_idx][c_idx]
                p = cell.text_frame.paragraphs[0]
                p.alignment = PP_ALIGN.CENTER if c_idx > 0 else PP_ALIGN.LEFT
                is_hdr = (r_idx == 0)
                is_ours = (r_idx == 4)
                bold = is_hdr or is_ours
                color = C_WHITE if is_hdr else (C_ACCENT if is_ours else C_BODY)
                set_para(p, cell.text, 18, bold=bold, color=color, space_after=Pt(0))
                # Fill
                if is_hdr:
                    cell.fill.solid()
                    cell.fill.fore_color.rgb = C_HEADER
                elif is_ours:
                    cell.fill.solid()
                    cell.fill.fore_color.rgb = C_HIGHLIGHT_BG
                else:
                    cell.fill.solid()
                    cell.fill.fore_color.rgb = C_TABLE_BG if r_idx % 2 == 1 else C_WHITE

    # 12. Table Caption
    if 'Caption: table' in shapes:
        s = shapes['Caption: table']
        s.top = Inches(8.40)
        s.height = Inches(0.85)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Table 1. Multi-scheme comparison under 9.18% block loss (K = 18) and visual containment at K = 25. Best results in bold. Crypto throughput: 569.2 MB/s; framing overhead: 4.17%.", 17, italic=True, color=C_MUTED, space_after=Pt(0))

    # Ablation Plot & Caption
    if 'Figure placeholder: [Ablation / scaling plot]' in shapes:
        sp = shapes['Figure placeholder: [Ablation / scaling plot]']
        left, width = sp.left, sp.width
        sp_elem = sp._element
        sp_elem.getparent().remove(sp_elem)
        
        target_h = Inches(5.30)
        target_w = Inches(5.30 * 1.54) # ~ 8.16 in
        center_left = left + Inches((width.inches - target_w.inches) / 2)
        pic_top = Inches(9.35)
        slide.shapes.add_picture('paper_icmlde/figures/fig5_ml_downstream.png', center_left, pic_top, width=target_w, height=target_h)
        print("Inserted Figure 3 (MobileNetV2 Downstream ML Plot)")

    if 'Caption: [Ablation / scaling plot]' in shapes:
        s = shapes['Caption: [Ablation / scaling plot]']
        s.top = Inches(14.75)
        s.height = Inches(0.85)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Figure 3. MobileNetV2 top-1 prediction agreement across 500 ImageNet images under increasing block corruption. Proposed spatial concealment maintains 83.8% agreement at K = 18 (9.18% loss).", 17, italic=True, color=C_MUTED, space_after=Pt(0))

    # 13. Conclusion
    if 'Conclusion' in shapes:
        s = shapes['Conclusion']
        s.top = Inches(15.75)
        s.height = Inches(4.35)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Conclusion", 30, bold=True, color=C_HEADER, space_after=Pt(6))

        c_items = [
            ("• Core Finding: ", "Block-level AES-256-GCM framing with tag-directed spatial concealment eliminates the all-or-nothing vulnerability of monolithic AEAD while guaranteeing 100% INT-CTXT integrity."),
            ("• Quantitative Impact: ", "Strictly bounds error propagation to EPR = 1.00, recovers +10.78 to +26.64 dB PSNR, and maintains 83.8% top-1 ML agreement at 9.18% block loss (+42.1% over zero-fill)."),
            ("• Future Scope: ", "Replace software MAC fingerprinting with TPM 2.0 / ARM TrustZone hardware roots, and implement native C/Rust SIMD for real-time 4K 60fps streaming.")
        ]
        for title, desc in c_items:
            add_lead_item(tf, title, desc, font_size=18, space_after=Pt(4))

    # 14. QR Code & References
    if 'QR placeholder' in shapes:
        sp = shapes['QR placeholder']
        left, top, width, height = sp.left, sp.top, sp.width, sp.height
        sp_elem = sp._element
        sp_elem.getparent().remove(sp_elem)
        slide.shapes.add_picture('paper_icmlde/figures/qr_code.png', Inches(32.6), Inches(20.30), width=Inches(2.5), height=Inches(2.5))
        print("Inserted QR Code")

    if 'Links & References' in shapes:
        s = shapes['Links & References']
        s.left = Inches(35.40)
        s.top = Inches(20.20)
        s.width = Inches(11.50)
        s.height = Inches(2.65)
        tf = s.text_frame
        tf.word_wrap = True
        tf.clear()
        p0 = tf.paragraphs[0]
        set_para(p0, "Project Code & Key References", 24, bold=True, color=C_HEADER, space_after=Pt(4))
        
        refs = [
            "[1] NIST, 'Recommendation for Block Cipher Modes: Galois/Counter Mode (GCM),' SP 800-38D, 2007.",
            "[2] H. Krawczyk & P. Eronen, 'HMAC-based Key Derivation (HKDF),' RFC 5869, 2010.",
            "[3] M. Sandler et al., 'MobileNetV2: Inverted Residuals & Linear Bottlenecks,' CVPR 2018."
        ]
        for r_txt in refs:
            p = tf.add_paragraph()
            set_para(p, r_txt, 15, bold=False, color=C_MUTED, space_after=Pt(2))

    prs.save(OUT_PPTX)
    print(f"[SUCCESS] Perfectly aligned poster created and saved to {OUT_PPTX}")

if __name__ == '__main__':
    build_poster()
