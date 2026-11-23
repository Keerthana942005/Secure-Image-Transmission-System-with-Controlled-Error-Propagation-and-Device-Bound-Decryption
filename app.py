import streamlit as st
import numpy as np
from PIL import Image
import os
import io
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.config import (
    BLOCK_SIZE, PACKAGE_PATH, INPUT_DIR, RESULTS_DIR,
    DEFAULT_TAU, MIN_PASSPHRASE_LENGTH, PBKDF2_ITERATIONS
)
from src.key_manager import (
    get_device_id,
    generate_session_key,
    generate_salt,
    derive_key,
    derive_session_keys,
    generate_receiver_static_keypair,
    save_receiver_static_key,
    load_receiver_static_key,
    get_key_fingerprint,
    verify_device,
    revoke_device,
    unrevoke_device,
    is_device_revoked,
    is_fingerprint_revoked,
    validate_passphrase
)
from src.image_processor import load_image, pad_image, split_into_blocks, merge_blocks, unpad_image
from src.encryption import encrypt_blocks
from src.decryption import (
    decrypt_blocks,
    receive_and_decrypt_stream,
    ACTION_CONCEALED,
    ACTION_REJECTED_OVER_THRESHOLD,
    ACTION_DUPLICATE_IGNORED,
    ACTION_SESSION_REJECTED,
    ACTION_DETECTED_AND_QUARANTINED
)
from src.record_format import (
    pack_record,
    unpack_record,
    create_session_header,
    parse_session_header_fields,
    verify_session_header_hmac,
    HeaderAuthenticationError
)
from src.error_simulator import corrupt_blocks, drop_blocks, swap_blocks
from src.file_handler import save_package, load_package
from src.image_crypto_metrics import (
    calculate_entropy,
    calculate_npcr,
    calculate_uaci,
    calculate_correlation,
    calculate_psnr,
    calculate_ssim
)
from src.error_concealment import conceal_failed_blocks

# Streamlit Page Config
st.set_page_config(page_title="MIL-SECURE COMMAND CENTER", page_icon="🛡️", layout="wide")

if "mission_log" not in st.session_state:
    st.session_state.mission_log = []

def add_log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.mission_log.append(f"[{timestamp}] {message}")

if not st.session_state.mission_log:
    add_log("SYSTEM INITIALIZED")
    add_log("AEAD Encryption Engine ONLINE (AES-256-GCM, 800B Framed Records)")
    add_log("Key Transport ONLINE (X25519 Ephemeral-Static Agreement + 134B Authenticated Header)")
    add_log("Device Authorization Module ACTIVE (HKDF-SHA256 + PBKDF2-HMAC-SHA256)")
    add_log("Error Containment Shield ARMED (Index-Bounded 20B AAD)")

# Ensure receiver static key exists
RX_KEY_PATH = os.path.join(RESULTS_DIR, "receiver_static_privkey.pem")
if not os.path.exists(RX_KEY_PATH):
    rx_priv_init = generate_receiver_static_keypair()
    save_receiver_static_key(rx_priv_init, RX_KEY_PATH)

# Custom CSS for dark military theme
st.markdown("""
<style>
    .stApp {
        background-color: #0a0f1c;
        color: #e0e0e0;
    }
    .title-text {
        color: #00ff88;
        font-family: 'Courier New', Courier, monospace;
        text-align: center;
        font-size: 2.3em;
        font-weight: bold;
        text-shadow: 0 0 10px #00ff88;
        margin-bottom: 0px;
    }
    .subtitle-text {
        color: #a0a0a0;
        font-family: 'Courier New', Courier, monospace;
        text-align: center;
        font-size: 1.05em;
        margin-bottom: 20px;
    }
    .metric-card {
        background-color: #12182b;
        border: 1px solid #00ff88;
        border-radius: 5px;
        padding: 12px;
        text-align: center;
        font-family: 'Courier New', Courier, monospace;
        box-shadow: 0 0 10px rgba(0, 255, 136, 0.2);
    }
    .metric-value {
        color: #00ff88;
        font-size: 1.25em;
        font-weight: bold;
    }
    .alert-text {
        color: #ff0033;
        font-size: 1.7em;
        font-weight: bold;
        text-align: center;
        text-shadow: 0 0 10px #ff0033;
        font-family: 'Courier New', Courier, monospace;
        margin-top: 15px;
        padding: 15px;
        border: 2px solid #ff0033;
        background-color: rgba(255, 0, 51, 0.1);
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 16px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 45px;
        background-color: #12182b;
        border-radius: 4px 4px 0px 0px;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00ff88 !important;
        color: #0a0f1c !important;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.markdown('<p class="title-text">🛡️ SECURE IMAGE TRANSMISSION COMMAND CENTER</p>', unsafe_allow_html=True)
st.markdown('<p class="subtitle-text">Device-Bound AEAD • Bounded Error Propagation (EPR=1.0) • Spatial Integrity & Concealment</p>', unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)
with col1:
    st.markdown('<div class="metric-card">Encryption Engine<br><span class="metric-value">AES-256-GCM + 20B AAD</span></div>', unsafe_allow_html=True)
with col2:
    st.markdown('<div class="metric-card">Key Transport<br><span class="metric-value">X25519 + 134B Auth Header</span></div>', unsafe_allow_html=True)
with col3:
    st.markdown('<div class="metric-card">Error Containment<br><span class="metric-value">STRICT (EPR = 1.00)</span></div>', unsafe_allow_html=True)

st.markdown("---")

tab1, tab2, tab3, tab4 = st.tabs(["📤 Sender Console", "📥 Receiver Console", "📊 Security & Benchmark Metrics", "🛡️ Device & Session Control"])

with tab1:
    st.header("📤 Sender Console")
    
    col_s1, col_s2 = st.columns(2)
    with col_s1:
        rx_priv_current = load_receiver_static_key(RX_KEY_PATH)
        rx_pub_current = rx_priv_current.public_key()
        rx_fp_bytes = get_key_fingerprint(rx_pub_current)
        rx_fp_hex = rx_fp_bytes.hex()
        
        st.info(f"🔑 Enrolled Receiver Key Fingerprint: `{rx_fp_hex[:16]}...{rx_fp_hex[-8:]}`")
        
        authorized_id = st.text_input("Enter Authorized Receiver Device ID:", get_device_id())
        session_passphrase = st.text_input(
            "🔑 Session Passphrase (Min. 16 chars with uppercase, lowercase, numbers, symbols)",
            type="password",
            value="AlphaSecureKey2026!Protected"
        )
        is_pass_valid, pass_msg = validate_passphrase(session_passphrase)
        if not is_pass_valid:
            st.error(f"Passphrase Policy Error: {pass_msg}")
        else:
            st.success("✅ Passphrase meets NIST SP 800-132 complexity policy.")
            
        session_epoch = st.number_input("Session Epoch / Monotonic Step", min_value=0, max_value=999, value=1)
        use_det_nonce = st.checkbox("Use Deterministic IV (IV_i = salt || uint64(i))", value=False)
        
    with col_s2:
        img_source = st.radio("Image Source", ["Select Benchmark Image", "Upload Custom Image"])
        img_arr = None
        if img_source == "Select Benchmark Image":
            benchmark_dir = INPUT_DIR
            available_images = [f for f in os.listdir(benchmark_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg'))] if os.path.exists(benchmark_dir) else []
            if available_images:
                chosen_img = st.selectbox("Choose Benchmark Dataset:", available_images)
                img_path = os.path.join(benchmark_dir, chosen_img)
                img_arr = load_image(img_path)
            else:
                st.warning("No benchmark images found in input directory.")
        else:
            uploaded_file = st.file_uploader("Upload Image to Encrypt", type=["png", "jpg", "jpeg"])
            if uploaded_file:
                img_arr = load_image(uploaded_file)
                
    if img_arr is not None and authorized_id and is_pass_valid:
        st.image(img_arr, caption=f"Original Plaintext Image: {img_arr.shape[1]}x{img_arr.shape[0]} px ({img_arr.shape[2]} ch)", width=400)
        
        if st.button("🚀 Encrypt Image Package"):
            add_log("Encryption procedure initiated")
            with st.spinner("Processing & Encrypting..."):
                padded_img, original_shape = pad_image(img_arr, BLOCK_SIZE)
                add_log(f"Padded dimensions: {padded_img.shape}")
                
                blocks = split_into_blocks(padded_img, BLOCK_SIZE)
                add_log(f"Split into {len(blocks)} blocks ({BLOCK_SIZE}x{BLOCK_SIZE} px)")
                
                # Sender ephemeral X25519 keypair
                tx_eph_priv = x25519.X25519PrivateKey.generate()
                tx_eph_pub = tx_eph_priv.public_key()
                tx_eph_pub_bytes = tx_eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
                rx_pub_bytes = rx_pub_current.public_bytes(Encoding.Raw, PublicFormat.Raw)
                
                # X25519 shared secret
                shared_secret = tx_eph_priv.exchange(rx_pub_current)
                salt_hkdf = generate_salt(16)
                salt_pbkdf2 = generate_salt(16)
                
                # Two-factor key derivation
                k_aes, k_hdr, _ = derive_session_keys(
                    shared_secret, tx_eph_pub_bytes, rx_pub_bytes,
                    salt_hkdf, salt_pbkdf2, session_passphrase, authorized_id,
                    session_epoch, iterations=PBKDF2_ITERATIONS
                )
                add_log(f"Session keys derived (PBKDF2 {PBKDF2_ITERATIONS:,} rounds + HKDF-SHA256)")
                
                # Create 134-byte authenticated session header
                hdr_bytes = create_session_header(
                    session_epoch, padded_img.shape[0], padded_img.shape[1], len(blocks),
                    salt_hkdf, salt_pbkdf2, tx_eph_pub_bytes, rx_fp_bytes, k_hdr
                )
                add_log(f"Created 134-byte HMAC-SHA256 authenticated session header")
                
                encrypted_records = encrypt_blocks(
                    blocks, k_aes, padded_img.shape, 
                    epoch=session_epoch, deterministic_nonce=use_det_nonce
                )
                add_log(f"Packaged {len(encrypted_records)} framed records (800B/record: 4B idx || 12B IV || 768B CT || 16B Tag)")
                
                plain_entropy = calculate_entropy(img_arr)
                
                package = {
                    'session_header': hdr_bytes,
                    'encrypted_records': encrypted_records,
                    'padded_shape': padded_img.shape,
                    'block_shape': (BLOCK_SIZE, BLOCK_SIZE, 3),
                    'total_blocks': len(blocks),
                    'authorized_device_id': authorized_id,
                    'session_epoch': session_epoch,
                    'original_shape': original_shape,
                    'original_arr': img_arr
                }
                
                save_package(PACKAGE_PATH, package)
                add_log("Transmission package written to disk")
                
                raw_bytes = img_arr.nbytes
                pkg_bytes = len(hdr_bytes) + sum(len(r) for r in encrypted_records)
                overhead_pct = ((pkg_bytes - raw_bytes) / raw_bytes) * 100.0
                
                st.session_state['encryption_stats'] = {
                    'Original Image Shape': f"{original_shape[1]}x{original_shape[0]} ({original_shape[2]} ch)",
                    'Padded Shape': f"{padded_img.shape[1]}x{padded_img.shape[0]}",
                    'Total Blocks': len(blocks),
                    'Session Header': f"{len(hdr_bytes)} Bytes (HMAC-SHA256 Authenticated)",
                    'Record Framing': "800 Bytes (4B Idx || 12B IV || 768B CT || 16B Tag)",
                    'Payload Size': f"{pkg_bytes:,} bytes",
                    'Framing Overhead': f"{pkg_bytes - raw_bytes:,} bytes ({overhead_pct:.2f}%)",
                    'Plaintext Entropy': f"{plain_entropy['overall']:.4f} bits (Max: 8.0000)"
                }
                st.success(f"✅ Image encrypted successfully! ({len(blocks)} blocks, Total Overhead: {overhead_pct:.2f}%)")

with tab2:
    st.header("📥 Receiver Console")
    
    col_r1, col_r2 = st.columns(2)
    with col_r1:
        cur_dev_id = get_device_id()
        st.info(f"📍 Current Host Device ID: `{cur_dev_id}`")
        receiver_passphrase = st.text_input(
            "🔑 Enter Session Secret Passphrase",
            type="password",
            value="AlphaSecureKey2026!Protected"
        )
        tau_val = st.slider("Concealment Recovery Threshold (tau)", min_value=0.05, max_value=0.50, value=0.25, step=0.05)
        
    with col_r2:
        st.subheader("Adversarial Channel Simulator")
        scenario = st.selectbox("Select Corruption Scenario:", [
            "M1: In-Place Bit-Flip Tampering (InvalidTag)",
            "M2: Unannounced Stream Byte Loss (Unframed CBC Failure)",
            "M3: Record Deletion / Dropped Packets (Framing Gap)",
            "Pairwise Block Swap / Reordering Attack"
        ])
        
        corruptions = st.slider("Corruption Intensity (Blocks affected)", min_value=0, max_value=200, value=25, step=5)
        enable_concealment = st.checkbox("✨ Enable Tag-Directed Boundary Concealment", value=True)
        
    if st.button("🔓 Decrypt and Reconstruct Image"):
        package = load_package(PACKAGE_PATH)
        if not package or 'session_header' not in package:
            st.error("No valid encrypted package found. Please encrypt an image in the Sender Console first.")
        else:
            hdr_bytes = package['session_header']
            rx_priv = load_receiver_static_key(RX_KEY_PATH)
            
            # Step 1: Parse and verify session header
            try:
                parsed_hdr = parse_session_header_fields(hdr_bytes)
                header_valid = True
            except HeaderAuthenticationError as e:
                header_valid = False
                st.error(f"Session Header Corrupted: {e}")
                
            if header_valid:
                st.success(f"🛡️ 134-Byte Session Header Verified (Epoch: {parsed_hdr['epoch']}, Dimensions: {parsed_hdr['width']}x{parsed_hdr['height']}, Blocks: {parsed_hdr['total_blocks']})")
                
                enc_records = list(package['encrypted_records'])
                
                # Apply simulated corruption
                if scenario.startswith("M1") and corruptions > 0:
                    add_log(f"Simulating M1 in-place bit-flips on {corruptions} records")
                    enc_records = corrupt_blocks(enc_records, corruptions)
                elif scenario.startswith("M3") and corruptions > 0:
                    add_log(f"Simulating M3 packet drops on {corruptions} records")
                    enc_records = drop_blocks(enc_records, corruptions)
                elif scenario.startswith("Pairwise") and len(enc_records) > 2:
                    add_log("Simulating adversarial block swap attack")
                    enc_records = swap_blocks(enc_records, (10, 11))
                    
                with st.spinner("Executing receiver cryptographic gates and spatial concealment..."):
                    dec_res = receive_and_decrypt_stream(
                        hdr_bytes, enc_records, rx_priv, receiver_passphrase,
                        cur_dev_id, tau=tau_val, enable_concealment=enable_concealment,
                        iterations=PBKDF2_ITERATIONS
                    )
                    
                    action = dec_res['action']
                    orig_shape = package['original_shape']
                    padded_shape = package['padded_shape']
                    orig_arr = package.get('original_arr', None)
                    grid_shape = (padded_shape[0] // BLOCK_SIZE, padded_shape[1] // BLOCK_SIZE)
                    
                    if action == ACTION_SESSION_REJECTED:
                        st.markdown('<p class="alert-text">🚨 SESSION REJECTED: Header HMAC or DRL Authorization Check Failed</p>', unsafe_allow_html=True)
                        add_log("ACTION: SESSION REJECTED")
                    elif action == ACTION_REJECTED_OVER_THRESHOLD:
                        st.markdown(f'<p class="alert-text">⚠️ CORRUPTION EXCEEDED RECOVERY THRESHOLD (tau = {tau_val:.2f})</p>', unsafe_allow_html=True)
                        add_log(f"ACTION: REJECTED OVER THRESHOLD ({dec_res['failed_fraction']:.2%} > {tau_val:.2%})")
                    else:
                        recon_blocks = dec_res['blocks']
                        recon_img = unpad_image(merge_blocks(recon_blocks, padded_shape), orig_shape)
                        
                        psnr_recon = calculate_psnr(orig_arr, recon_img) if orig_arr is not None else 0.0
                        ssim_recon = calculate_ssim(orig_arr, recon_img) if orig_arr is not None else 0.0
                        
                        # Spatial quarantine overlay
                        mask_overlay = np.array(recon_img).copy()
                        for f_idx in dec_res['failed_indices']:
                            gy = (f_idx // grid_shape[1]) * BLOCK_SIZE
                            gx = (f_idx % grid_shape[1]) * BLOCK_SIZE
                            mask_overlay[gy:gy+BLOCK_SIZE, gx:gx+BLOCK_SIZE, :] = [255, 0, 0]  # Red for corrupted
                        for m_idx in dec_res['missing_indices']:
                            gy = (m_idx // grid_shape[1]) * BLOCK_SIZE
                            gx = (m_idx % grid_shape[1]) * BLOCK_SIZE
                            mask_overlay[gy:gy+BLOCK_SIZE, gx:gx+BLOCK_SIZE, :] = [0, 0, 255]  # Blue for missing
                            
                        mask_overlay = unpad_image(mask_overlay, orig_shape)
                        
                        col_v1, col_v2, col_v3 = st.columns(3)
                        with col_v1:
                            if orig_arr is not None:
                                st.image(orig_arr, caption="Original Plaintext", use_column_width=True)
                        with col_v2:
                            st.image(mask_overlay, caption="Spatial Quarantine Map (Red: Tag Failure, Blue: Loss)", use_column_width=True)
                        with col_v3:
                            st.image(recon_img, caption=f"Recovered Output (PSNR: {psnr_recon:.2f} dB, SSIM: {ssim_recon:.4f})", use_column_width=True)
                            
                        failed_count = dec_res['failed_blocks']
                        missing_count = dec_res['missing_blocks']
                        epr = (failed_count + missing_count) / float(corruptions) if corruptions > 0 else 1.0
                        
                        st.session_state['decryption_stats'] = {
                            'Receiver Action': action,
                            'Authentic Blocks Verified': dec_res['authentic_blocks'],
                            'Failed Blocks (Invalid Tag)': failed_count,
                            'Missing Blocks (Packet Loss)': missing_count,
                            'Error Propagation Radius (EPR)': f"{epr:.2f}",
                            'Corruption Fraction': f"{dec_res['failed_fraction']:.2%}",
                            'Threshold Tau': f"{tau_val:.2f}",
                            'Recovered PSNR': f"{psnr_recon:.2f} dB",
                            'Recovered SSIM': f"{ssim_recon:.4f}"
                        }
                        
                        # Session export
                        session_export = {
                            'timestamp': int(datetime.now().timestamp()),
                            'action': action,
                            'tau': tau_val,
                            'scenario': scenario,
                            'corrupted_blocks': corruptions,
                            'authentic_blocks': dec_res['authentic_blocks'],
                            'failed_blocks': failed_count,
                            'missing_blocks': missing_count,
                            'epr': epr,
                            'psnr': round(psnr_recon, 2),
                            'ssim': round(ssim_recon, 4)
                        }
                        st.download_button("📥 Export Session Metrics (JSON)", json.dumps(session_export, indent=2), "session_run.json", "application/json")

with tab3:
    st.header("📊 Security, Cryptographic & Benchmark Metrics")
    col_m1, col_m2 = st.columns(2)
    with col_m1:
        st.subheader("Sender Cryptographic Metrics")
        if 'encryption_stats' in st.session_state:
            for k, v in st.session_state['encryption_stats'].items():
                st.markdown(f"**{k}**: `{v}`")
        else:
            st.info("Encrypt an image in Sender Console to view live metrics.")
            
    with col_m2:
        st.subheader("Receiver Containment Metrics")
        if 'decryption_stats' in st.session_state:
            for k, v in st.session_state['decryption_stats'].items():
                st.markdown(f"**{k}**: `{v}`")
        else:
            st.info("Decrypt an image in Receiver Console to view containment metrics.")
            
    st.markdown("---")
    st.subheader("Cryptographic Baseline Comparison")
    st.markdown("""
    | Property / Metric | Proposed Block AES-256-GCM | Monolithic AES-GCM | Unframed AES-CBC | Framed AES-CBC |
    | :--- | :--- | :--- | :--- | :--- |
    | **Ciphertext Entropy** | **7.9991 -- 7.9999** bits | ~7.9999 bits | ~7.9998 bits | ~7.9998 bits |
    | **Integrity Enforcement** | **128-bit GHASH per block** | Monolithic (128-bit) | None (Silent Tampering) | None (Silent Tampering) |
    | **Packet Loss Containment**| **Strictly Bounded (EPR=1.0)** | Catastrophic Discard (0% Avail.) | Desynchronization (EPR $\\le 200.48$) | Recoverable Alignment |
    | **In-Place Bit-Flip** | **Quarantined (EPR=1.0)** | Discarded Entirely | Localized (2 AES blocks) | Localized (2 AES blocks) |
    | **Downstream ML Retention**| **83.78% @ 9.2% corruption** | 0.0% Availability | 23.54% Retention | 41.64% Retention |
    """)

with tab4:
    st.header("🛡️ Device Revocation & Key Lifecycle Management")
    cur_dev = get_device_id()
    st.write(f"**Current Device Identifier:** `{cur_dev}`")
    is_rev = is_device_revoked(cur_dev)
    st.write(f"**Revocation Status:** {'🚨 REVOKED' if is_rev else '✅ ACTIVE / AUTHORIZED'}")
    
    col_d1, col_d2 = st.columns(2)
    with col_d1:
        if st.button("🚨 Revoke Current Device"):
            revoke_device(cur_dev)
            add_log("Local receiver device revoked")
            st.rerun()
    with col_d2:
        if st.button("✅ Restore Current Device"):
            unrevoke_device(cur_dev)
            add_log("Local receiver device restored")
            st.rerun()
            
    st.markdown("---")
    st.info("ℹ️ Security Boundary Notice: Key transport uses X25519 ephemeral-static key agreement authenticated via HMAC-SHA256. If the shared passphrase is compromised, retroactive decryption of past sessions is possible (No Forward Secrecy across passphrase compromise). Refer to docs/SECURITY.md.")
