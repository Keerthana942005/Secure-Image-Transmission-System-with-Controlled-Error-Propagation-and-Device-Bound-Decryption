import os
import shutil
import pptx
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

SRC_TEMPLATE = r'C:\Users\lenovo\.gemini\antigravity\brain\b2f071e6-6efd-4510-b505-a90b427dbb99\.user_uploaded\media_1795362444304_e0385115.pptx'
OUT_PPTX = 'ICMLDE_2026_Presentation_SecureImageTransmission.pptx'

# Palette
C_TITLE = RGBColor(15, 23, 42)       # Slate 900
C_HEADER = RGBColor(30, 58, 138)     # Blue 900
C_SUB = RGBColor(30, 64, 175)        # Blue 800
C_BODY = RGBColor(30, 41, 59)        # Slate 800
C_MUTED = RGBColor(71, 85, 105)      # Slate 600
C_ACCENT = RGBColor(4, 120, 87)      # Emerald 700
C_WHITE = RGBColor(255, 255, 255)
C_TABLE_BG = RGBColor(248, 250, 252) # Slate 50
C_HIGHLIGHT_BG = RGBColor(236, 253, 245) # Emerald 50

def set_para(p, text, font_size, bold=False, italic=False, color=C_BODY, space_after=Pt(4), align=PP_ALIGN.LEFT):
    p.text = text
    p.font.name = 'Arial'
    p.font.size = Pt(font_size)
    p.font.bold = bold
    p.font.italic = italic
    p.font.color.rgb = color
    p.space_after = space_after
    p.alignment = align

def add_lead(tf, prefix, content, font_size=13, prefix_color=C_BODY, space_after=Pt(4)):
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

def build_presentation():
    print("Copying fresh presentation template...")
    shutil.copyfile(SRC_TEMPLATE, OUT_PPTX)
    prs = pptx.Presentation(OUT_PPTX)

    # ==================== SLIDE 1: Title Slide ====================
    s1 = prs.slides[0]
    # Shape 6: Paper Title
    s1.shapes[6].text_frame.clear()
    p = s1.shapes[6].text_frame.paragraphs[0]
    set_para(p, "Secure Image Transmission System with Controlled Error Propagation and Device-Bound Decryption", 24, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(4))

    # Shape 7: Authors, Affiliation, Paper ID
    s1.shapes[7].text_frame.clear()
    p0 = s1.shapes[7].text_frame.paragraphs[0]
    set_para(p0, "Keerthana Nellyeri¹, Swetha Rajesh¹, Radhu Krishna R.¹,*", 16, bold=True, color=C_BODY, align=PP_ALIGN.CENTER, space_after=Pt(4))
    p1 = s1.shapes[7].text_frame.add_paragraph()
    set_para(p1, "¹School of Computing, Amrita Vishwa Vidyapeetham, Amritapuri, Kollam, India", 13, bold=False, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(2))
    p2 = s1.shapes[7].text_frame.add_paragraph()
    set_para(p2, "*Corresponding Author: radhukr@am.amrita.edu  ·  Paper ID: ICMLDE-2026-XXX", 12, bold=False, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # ==================== SLIDE 2: Introduction ====================
    s2 = prs.slides[1]
    # Shape 1: Left text box
    tf = s2.shapes[1].text_frame
    tf.word_wrap = True
    tf.clear()
    p = tf.paragraphs[0]
    set_para(p, "Research Context & Scope", 16, bold=True, color=C_HEADER, space_after=Pt(6))
    add_lead(tf, "• Context & Need: ", "Critical vision applications across healthcare, defense, and industrial IoT transmit high-resolution images over lossy wireless channels directly into downstream deep neural networks (DNNs).", font_size=13, space_after=Pt(5))
    add_lead(tf, "• The Core Dilemma: ", "Monolithic encryption (AES-GCM) discards the entire frame upon a single bit error, while unauthenticated ciphers allow corrupted pixels to silently degrade classification accuracy.", font_size=13, space_after=Pt(5))
    add_lead(tf, "• Proposed Solution: ", "A cross-layer cryptosystem combining 16×16 block AES-256-GCM framing, 2-factor device key derivation, and tag-directed spatial error concealment.", font_size=13, space_after=Pt(5))
    add_lead(tf, "• Scope of Talk: ", "Architecture, error containment proof (EPR = 1.00), cryptographic randomness, and MobileNetV2 downstream classification resilience.", font_size=13, prefix_color=C_ACCENT, space_after=Pt(0))

    # Right side: replace Shape 3 icon and Shape 4 text with Architecture picture
    sp3 = s2.shapes[3]._element
    sp4 = s2.shapes[4]._element
    sp3.getparent().remove(sp3)
    sp4.getparent().remove(sp4)
    # Insert picture inside right card pos=(5.8, 1.5, 3.7, 4.9)
    s2.shapes.add_picture('paper_icmlde/figures/fig1_architecture.png', Inches(5.9), Inches(2.2), width=Inches(3.5))

    # ==================== SLIDE 3: Problem Statement ====================
    s3 = prs.slides[2]
    # Shape 4: Top statement
    s3.shapes[4].text_frame.clear()
    p = s3.shapes[4].text_frame.paragraphs[0]
    set_para(p, "Standard monolithic AEAD (AES-GCM) discards entire images upon single transmission errors (0% availability). Unauthenticated ciphers allow corrupted or manipulated pixels to pass undetected, degrading downstream machine learning classifiers.", 14, bold=False, color=C_BODY, space_after=Pt(0))

    # Card 1 (Who is affected)
    s3.shapes[8].text_frame.clear()
    set_para(s3.shapes[8].text_frame.paragraphs[0], "Who is Affected", 14, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(2))
    s3.shapes[9].text_frame.clear()
    set_para(s3.shapes[9].text_frame.paragraphs[0], "Telemedicine PACS, tactical defense drones, industrial IoT, and distributed edge-to-cloud visual AI classifiers operating over lossy wireless channels.", 11, bold=False, color=C_BODY, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # Card 2 (Scale of the issue)
    s3.shapes[13].text_frame.clear()
    set_para(s3.shapes[13].text_frame.paragraphs[0], "Scale of the Issue", 14, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(2))
    s3.shapes[14].text_frame.clear()
    set_para(s3.shapes[14].text_frame.paragraphs[0], "1-bit error in monolithic AEAD causes 100% data loss. In unframed CBC, packet loss desynchronizes to EPR = 200.48 and drops ML top-1 agreement to 23.5%.", 11, bold=False, color=C_BODY, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # Card 3 (Current gaps)
    s3.shapes[18].text_frame.clear()
    set_para(s3.shapes[18].text_frame.paragraphs[0], "Current Gaps", 14, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(2))
    s3.shapes[19].text_frame.clear()
    set_para(s3.shapes[19].text_frame.paragraphs[0], "1D streaming AEAD (STREAM) stalls on dropped packets; heuristic chaotic ciphers lack formal security proofs, standardized MAC tags, and noise resilience.", 11, bold=False, color=C_BODY, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # ==================== SLIDE 4: Background & Contributions ====================
    s4 = prs.slides[3]
    # Table 4x3
    tbl = s4.shapes[1].table
    t_data = [
        ["Prior Study", "Cryptographic Approach", "Critical Limitation"],
        ["Dworkin et al. / NIST", "AES-CBC Chained Mode", "No integrity verification; packet loss causes infinite desynchronization"],
        ["Zhou et al. / Hua et al.", "Chaotic Map Ciphers", "Heuristic; lacks standardized MAC tags; highly vulnerable under noise"],
        ["Hoang et al. (STREAM)", "1D Streaming AEAD", "Enforces strict monotonic order; single dropped chunk halts entire stream"]
    ]
    for r_idx, row in enumerate(tbl.rows):
        for c_idx, cell in enumerate(row.cells):
            cell.text = t_data[r_idx][c_idx]
            p = cell.text_frame.paragraphs[0]
            is_hdr = (r_idx == 0)
            set_para(p, cell.text, 10 if is_hdr else 9, bold=is_hdr, color=C_WHITE if is_hdr else C_BODY, space_after=Pt(0))
            if is_hdr:
                cell.fill.solid()
                cell.fill.fore_color.rgb = C_HEADER
            else:
                cell.fill.solid()
                cell.fill.fore_color.rgb = C_TABLE_BG if r_idx % 2 == 1 else C_WHITE

    # Card 1: Underlying Theory (Shape 14)
    s4.shapes[14].text_frame.clear()
    set_para(s4.shapes[14].text_frame.paragraphs[0], "AES-256-GCM (NIST SP 800-38D) with 128-bit GHASH INT-CTXT integrity; PBKDF2 (600k rounds) + HKDF-SHA256 key hardening; 2D inverse-distance boundary interpolation.", 10, bold=False, color=C_BODY, space_after=Pt(0))

    # Card 2: Research Gap (Shape 15)
    s4.shapes[15].text_frame.clear()
    set_para(s4.shapes[15].text_frame.paragraphs[0], "No existing system provides simultaneous cryptographic integrity, physical hardware binding, strictly bounded error containment (EPR = 1.00), and downstream ML recovery without retransmission.", 10, bold=False, color=C_BODY, space_after=Pt(0))

    # Card 3: Main Contributions (Shape 16)
    s4.shapes[16].text_frame.clear()
    set_para(s4.shapes[16].text_frame.paragraphs[0], "1. Block-Level AEAD: 16×16 blocks with 800B framing and 20B spatial AAD (EPR = 1.00).\n2. 2-Factor Device Binding: MAC SHA-256 + 600k PBKDF2 passphrase via HKDF-SHA256.\n3. Headline Result: Preserves 83.8% top-1 ML agreement at 9.18% block loss (+42.1% over zero-fill).", 9, bold=False, color=C_BODY, space_after=Pt(0))

    # ==================== SLIDE 5: Proposed Methodology ====================
    s5 = prs.slides[4]
    # Update titles in the 4 steps
    s5.shapes[4].text_frame.clear()
    set_para(s5.shapes[4].text_frame.paragraphs[0], "Image\nFraming", 12, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))
    s5.shapes[9].text_frame.clear()
    set_para(s5.shapes[9].text_frame.paragraphs[0], "Two-Factor\nBinding", 12, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))
    s5.shapes[14].text_frame.clear()
    set_para(s5.shapes[14].text_frame.paragraphs[0], "Block AEAD\nPipeline", 12, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))
    s5.shapes[19].text_frame.clear()
    set_para(s5.shapes[19].text_frame.paragraphs[0], "Spatial\nConcealment", 12, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # Update description box (Shape 20)
    tf = s5.shapes[20].text_frame
    tf.word_wrap = True
    tf.clear()
    add_lead(tf, "1. Image Partitioning: ", "RGB image padded to multiples of 16; divided into N non-overlapping 16×16×3 blocks (768 bytes plaintext).", font_size=12, space_after=Pt(4))
    add_lead(tf, "2. Two-Factor Key Derivation: ", "Combines receiver device ID (SHA-256 MAC) and session passphrase (600,000 PBKDF2 rounds, 106.03 ms) via HKDF-SHA256 into a 256-bit AES key.", font_size=12, space_after=Pt(4))
    add_lead(tf, "3. Block-Level AES-256-GCM Framing: ", "Each block encrypted with fresh 96-bit nonce; 800B record format (4B Index ∥ 12B Nonce ∥ 768B Ciphertext ∥ 16B GHASH Tag) bound to 20-byte spatial and epoch AAD.", font_size=12, space_after=Pt(4))
    add_lead(tf, "4. Verification & Tag-Directed Concealment: ", "Receiver verifies 128-bit GHASH tag. Failed blocks isolated (EPR = 1.00) and reconstructed via 4-neighbor inverse-distance spatial interpolation without retransmission.", font_size=12, prefix_color=C_ACCENT, space_after=Pt(0))

    # ==================== SLIDE 6: Experimental Setup ====================
    s6 = prs.slides[5]
    # Numbers
    s6.shapes[2].text_frame.clear()
    set_para(s6.shapes[2].text_frame.paragraphs[0], "6", 36, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))
    s6.shapes[3].text_frame.clear()
    set_para(s6.shapes[3].text_frame.paragraphs[0], "Benchmark Images", 13, bold=True, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(0))

    s6.shapes[5].text_frame.clear()
    set_para(s6.shapes[5].text_frame.paragraphs[0], "100.5 K", 36, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))
    s6.shapes[6].text_frame.clear()
    set_para(s6.shapes[6].text_frame.paragraphs[0], "ML Inferences", 13, bold=True, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(0))

    s6.shapes[8].text_frame.clear()
    set_para(s6.shapes[8].text_frame.paragraphs[0], "4", 36, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))
    s6.shapes[9].text_frame.clear()
    set_para(s6.shapes[9].text_frame.paragraphs[0], "Baselines", 13, bold=True, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(0))

    s6.shapes[11].text_frame.clear()
    set_para(s6.shapes[11].text_frame.paragraphs[0], "8", 36, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(0))
    s6.shapes[12].text_frame.clear()
    set_para(s6.shapes[12].text_frame.paragraphs[0], "Core Metrics", 13, bold=True, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # Detail Cards
    s6.shapes[16].text_frame.clear()
    set_para(s6.shapes[16].text_frame.paragraphs[0], "6 benchmark images (Cameraman, Baboon, Peppers, MRI, Satellite 1024², Submarine) + 500 ImageNet validation images across 5 corruption levels.", 10, bold=False, color=C_BODY, space_after=Pt(0))

    s6.shapes[20].text_frame.clear()
    set_para(s6.shapes[20].text_frame.paragraphs[0], "13th Gen Intel Core i5-13420H (12 threads), Windows 11, Python 3.13, OpenSSL 4.0.3, cryptography 50.0.2 (AES-NI enabled), PyTorch MobileNetV2.", 10, bold=False, color=C_BODY, space_after=Pt(0))

    s6.shapes[24].text_frame.clear()
    set_para(s6.shapes[24].text_frame.paragraphs[0], "Monolithic AES-GCM (NIST SP 800-38D), Unframed AES-CBC (RFC 3602), Framed AES-CBC, Zero-Fill Quarantine, OpenCV Inpainting.", 10, bold=False, color=C_BODY, space_after=Pt(0))

    s6.shapes[28].text_frame.clear()
    set_para(s6.shapes[28].text_frame.paragraphs[0], "Shannon Entropy, NPCR (>99.60%), UACI (33.48–33.51%), Correlation |r| ≤ 0.0304, EPR, PSNR/SSIM, Top-1 Agreement (%), Throughput.", 10, bold=False, color=C_BODY, space_after=Pt(0))

    # ==================== SLIDE 7: Results ====================
    s7 = prs.slides[6]
    # Update text frames BEFORE touching shape tree
    # Shape 3: Big metric '+42.1%'
    s7.shapes[3].text_frame.clear()
    set_para(s7.shapes[3].text_frame.paragraphs[0], "+42.1%", 36, bold=True, color=C_ACCENT, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # Shape 4: Metric subtitle
    s7.shapes[4].text_frame.clear()
    set_para(s7.shapes[4].text_frame.paragraphs[0], "higher ML top-1 agreement over zero-fill at 9.18% block loss (+60.2% over CBC)", 11, bold=True, color=C_BODY, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # Shape 5: Key findings
    tf = s7.shapes[5].text_frame
    tf.word_wrap = True
    tf.clear()
    add_lead(tf, "• Finding 1: ", "Entropy reaches 7.9991–7.9999 bits; NPCR > 99.60%; 100% detection across 1,800 security attack trials.", font_size=10, space_after=Pt(4))
    add_lead(tf, "• Finding 2: ", "EPR is strictly bounded at 1.0000; spatial concealment yields +10.78 to +26.64 dB PSNR gains over quarantine.", font_size=10, space_after=Pt(4))
    add_lead(tf, "• Finding 3: ", "MobileNetV2 maintains 83.8% top-1 agreement at K=18 loss, whereas monolithic AEAD drops to 0.0% availability.", font_size=10, prefix_color=C_ACCENT, space_after=Pt(0))

    # Now replace default chart (Shape 1) with fig3_psnr_containment.png
    chart_sp = s7.shapes[1]._element
    chart_sp.getparent().remove(chart_sp)
    s7.shapes.add_picture('paper_icmlde/figures/fig3_psnr_containment.png', Inches(0.5), Inches(1.4), width=Inches(5.8))

    # ==================== SLIDE 8: Comparative Analysis ====================
    s8 = prs.slides[7]
    # Grab references to captions before removing placeholders
    cap1_shape = s8.shapes[5]
    cap2_shape = s8.shapes[8]
    sp3 = s8.shapes[3]._element
    sp4 = s8.shapes[4]._element
    sp6 = s8.shapes[6]._element
    sp7 = s8.shapes[7]._element

    # Remove placeholder texts and icons
    for sp in [sp3, sp4, sp6, sp7]:
        sp.getparent().remove(sp)

    # Insert Left picture: fig2_poster_grid.png
    s8.shapes.add_picture('paper_icmlde/figures/fig2_poster_grid.png', Inches(0.6), Inches(1.8), width=Inches(4.1))
    cap1_shape.text_frame.clear()
    set_para(cap1_shape.text_frame.paragraphs[0], "Fig. 1: Visual Containment (Submarine at K=25). CBC: 11.03 dB; Zero-fill: 30.62 dB; Spatial concealment: 44.38 dB (+13.76 dB gain).", 9, italic=True, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # Insert Right picture: fig5_ml_downstream.png
    s8.shapes.add_picture('paper_icmlde/figures/fig5_ml_downstream.png', Inches(5.3), Inches(1.8), width=Inches(4.1))
    cap2_shape.text_frame.clear()
    set_para(cap2_shape.text_frame.paragraphs[0], "Fig. 2: MobileNetV2 Top-1 Prediction Agreement across 500 ImageNet images. Spatial concealment preserves 83.8% at K=18 loss.", 9, italic=True, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(0))

    # ==================== SLIDE 9: Discussion ====================
    s9 = prs.slides[8]
    s9.shapes[5].text_frame.clear()
    set_para(s9.shapes[5].text_frame.paragraphs[0], "We hypothesized that decoupling authenticated encryption into 16×16 blocks with independent nonces would bound error propagation to EPR = 1.00, and that 2D spatial pixel correlations would allow tag-directed interpolation to recover enough visual semantics for downstream DNN classification without packet retransmission.", 11, bold=False, color=C_BODY, space_after=Pt(0))

    s9.shapes[10].text_frame.clear()
    set_para(s9.shapes[10].text_frame.paragraphs[0], "EPR = 1.0000 strictly validated across 900 trials; zero successful forgeries (Adv < 1.49e-37); spatial concealment achieves +10.78 to +26.64 dB PSNR gain over quarantine and preserves 83.8% top-1 ML agreement under 9.18% block loss across 100,500 inferences.", 11, bold=False, color=C_BODY, space_after=Pt(0))

    s9.shapes[15].text_frame.clear()
    set_para(s9.shapes[15].text_frame.paragraphs[0], "Resolves the historical conflict between cryptographic authentication and channel error tolerance. Provides a drop-in secure transport for edge-to-cloud AI pipelines in telemedicine, defense, and industrial IoT without latency penalties from ARQ retransmission.", 11, bold=False, color=C_BODY, space_after=Pt(0))

    # ==================== SLIDE 10: Conclusion & Future Scope ====================
    s10 = prs.slides[9]
    # Conclusion bullet points
    tf = s10.shapes[5].text_frame
    tf.word_wrap = True
    tf.clear()
    add_lead(tf, "• Main Contribution: ", "An error-resilient visual cryptosystem combining 16×16 block AES-256-GCM, 20B spatial AAD binding, 2-factor PBKDF2/HKDF device binding, and tag-directed spatial concealment.", font_size=10, space_after=Pt(4))
    add_lead(tf, "• Key Result: ", "Strictly bounded EPR = 1.00, 100% tamper detection, and 83.8% downstream ML top-1 agreement at 9.18% block loss with only 4.17% analytical framing overhead.", font_size=10, space_after=Pt(4))
    add_lead(tf, "• Practical Impact: ", "Eliminates catastrophic data loss of monolithic AEAD while guaranteeing end-to-end INT-CTXT integrity.", font_size=10, prefix_color=C_ACCENT, space_after=Pt(0))

    # Future Scope bullet points
    tf = s10.shapes[10].text_frame
    tf.word_wrap = True
    tf.clear()
    add_lead(tf, "• Hardware Attestation: ", "Upgrade software MAC fingerprinting to hardware-rooted TPM 2.0 / ARM TrustZone anchors.", font_size=10, space_after=Pt(4))
    add_lead(tf, "• Deep Generative Inpainting: ", "Integrate edge GANs/Diffusion models to reconstruct complex stochastic textures beyond spatial gradients.", font_size=10, space_after=Pt(4))
    add_lead(tf, "• High-Throughput SIMD: ", "Implement native C/Rust pipeline with multi-threading to achieve real-time 4K 60fps streaming (>1.49 GB/s).", font_size=10, space_after=Pt(0))

    # ==================== SLIDE 11: References ====================
    s11 = prs.slides[10]
    tf = s11.shapes[1].text_frame
    tf.word_wrap = True
    tf.clear()
    refs = [
        "[1] NIST, 'Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC,' NIST Special Publication 800-38D, 2007.",
        "[2] H. Krawczyk and P. Eronen, 'HMAC-based Extract-and-Expand Key Derivation Function (HKDF),' IETF RFC 5869, 2010.",
        "[3] M. Sandler, A. Howard, M. Zhu, A. Zhmoginov, and L.-C. Chen, 'MobileNetV2: Inverted Residuals and Linear Bottlenecks,' in Proc. IEEE/CVF CVPR, 2018, pp. 4510–4520.",
        "[4] Z. Wang, A. C. Bovik, H. R. Sheikh, and E. P. Simoncelli, 'Image Quality Assessment: From Error Visibility to Structural Similarity,' IEEE Trans. Image Process., vol. 13, no. 4, pp. 600–612, 2004.",
        "[5] A. Telea, 'An Image Inpainting Technique Based on the Fast Marching Method,' J. Graph. Tools, vol. 9, no. 1, pp. 23–34, 2004."
    ]
    for r_idx, r_text in enumerate(refs):
        p = tf.add_paragraph() if r_idx > 0 else tf.paragraphs[0]
        set_para(p, r_text, 12, bold=False, color=C_MUTED, space_after=Pt(8))

    # ==================== SLIDE 12: Thank You ====================
    s12 = prs.slides[11]
    s12.shapes[0].text_frame.clear()
    set_para(s12.shapes[0].text_frame.paragraphs[0], "THANK YOU", 44, bold=True, color=C_HEADER, align=PP_ALIGN.CENTER, space_after=Pt(6))

    s12.shapes[1].text_frame.clear()
    p0 = s12.shapes[1].text_frame.paragraphs[0]
    set_para(p0, "Questions & Discussion", 22, bold=True, color=C_BODY, align=PP_ALIGN.CENTER, space_after=Pt(6))
    p1 = s12.shapes[1].text_frame.add_paragraph()
    set_para(p1, "Keerthana Nellyeri · Swetha Rajesh · Radhu Krishna R.*", 15, bold=True, color=C_BODY, align=PP_ALIGN.CENTER, space_after=Pt(4))
    p2 = s12.shapes[1].text_frame.add_paragraph()
    set_para(p2, "School of Computing, Amrita Vishwa Vidyapeetham, Amritapuri, Kollam, India", 13, bold=False, color=C_MUTED, align=PP_ALIGN.CENTER, space_after=Pt(2))
    p3 = s12.shapes[1].text_frame.add_paragraph()
    set_para(p3, "*Corresponding Author: radhukr@am.amrita.edu", 13, bold=False, color=C_ACCENT, align=PP_ALIGN.CENTER, space_after=Pt(0))

    prs.save(OUT_PPTX)
    print(f"[SUCCESS] 12-slide presentation generated and saved to {OUT_PPTX}")

if __name__ == '__main__':
    build_presentation()
