import os
import sys
import json
import csv
import struct
import numpy as np
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import GLOBAL_SEED, BLOCK_SIZE, RESULTS_DIR, PBKDF2_ITERATIONS
from src.image_processor import pad_image, split_into_blocks
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
from src.key_manager import (
    generate_receiver_static_keypair,
    get_key_fingerprint,
    derive_session_keys,
    generate_session_key,
    generate_salt,
    derive_key,
    get_device_id,
    verify_and_update_epoch,
    get_last_accepted_epoch,
    reset_epoch_tracker,
    reset_drl_tracker,
    revoke_device,
    unrevoke_device,
    revoke_fingerprint,
    unrevoke_fingerprint,
    sign_drl,
    verify_and_load_drl,
    DRLRollbackError,
    DRLSignatureError
)

NUM_SECURITY_TRIALS = 100

def run_security_attack_suite(seed=GLOBAL_SEED):
    rng = np.random.RandomState(seed)
    
    device_id = get_device_id()
    passphrase = "PrimarySecurityPassphrase2026!"
    
    print("=" * 80)
    print("RUNNING ADVERSARIAL SECURITY MATRIX (18 VECTORS x 100 TRIALS)")
    print("=" * 80)
    
    # 18 Attack vectors matching specification
    scenarios = [
        # 1. in-place bit-flip in ciphertext -> detected_and_quarantined
        ("In-Place Bit-Flip in Ciphertext",
         "Single-byte ciphertext modification in random block",
         "GHASH Tag Verification Failure",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 2. block swap -> detected_and_quarantined
        ("Block Swap / Index Splicing",
         "Pairwise swapping of distinct block records",
         "AAD Block Index Mismatch",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 3. header index tamper -> detected_and_quarantined
        ("Header Index Tampering",
         "Adversary alters transmitted record index field",
         "AAD Block Index Mismatch",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 4. cross-session splice -> detected_and_quarantined
        ("Cross-Session Splice",
         "Injection of block from prior session into current stream",
         "AAD Session Salt / Epoch Mismatch",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 5. cross-epoch replay -> detected_and_quarantined
        ("Cross-Epoch Replay in Stream",
         "Replaying stale block packet from earlier session epoch",
         "AAD Epoch Field Mismatch",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 6. dropped record -> concealed
        ("Dropped Record (Packet Loss)",
         "Silent drop of 1 block (below tau threshold)",
         "Index Gap Detection & Boundary Concealment",
         ACTION_CONCEALED),
        
        # 7. duplicated record -> duplicate_ignored
        ("Duplicated Record Injection",
         "Adversary injects duplicated valid block record",
         "Monotonic Index Deduplication Filter",
         ACTION_DUPLICATE_IGNORED),
        
        # 8. stream truncation -> rejected_over_threshold
        ("Stream Truncation Attack",
         "Truncation of trailing 50% of stream (exceeding tau=0.25)",
         "Corruption Threshold Exceeded Gate (tau=0.25)",
         ACTION_REJECTED_OVER_THRESHOLD),
        
        # 9. H/W/N tamper in AAD -> detected_and_quarantined
        ("Dimension Tampering in AAD (H/W/N)",
         "Adversary alters claimed image dimensions in AAD binding",
         "Global AAD Dimensions Verification Failure",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 10. wrong device ID -> detected_and_quarantined / rejected_over_threshold
        ("Unauthorized Device ID",
         "Receiver using unauthorized device identifier",
         "2FA Key Derivation Divergence / GHASH Failure",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 11. wrong passphrase -> detected_and_quarantined / rejected_over_threshold
        ("Incorrect Passphrase",
         "Receiver using incorrect passphrase in 2FA key derivation",
         "2FA Key Derivation Divergence / GHASH Failure",
         ACTION_DETECTED_AND_QUARANTINED),
        
        # 12. revoked device -> session_rejected
        ("Revoked Device Access",
         "Decryption attempt by revoked device on DRL",
         "Device Revocation List (DRL) Authorization Check",
         ACTION_SESSION_REJECTED),
        
        # 13. session-header bit-flip -> session_rejected
        ("Session Header Bit-Flip",
         "Single-bit corruption in 134-byte session header",
         "Constant-Time Header HMAC-SHA256 Failure",
         ACTION_SESSION_REJECTED),
        
        # 14. ephemeral public key substitution -> session_rejected
        ("Ephemeral Public Key Substitution",
         "Adversary substitutes sender ephemeral X25519 key",
         "Constant-Time Header HMAC-SHA256 Failure",
         ACTION_SESSION_REJECTED),
        
        # 15. wrong receiver static key -> session_rejected
        ("Wrong Receiver Static Key",
         "Encrypted for Receiver A, attempted decryption by Receiver B",
         "Fingerprint Mismatch / Header HMAC Verification Failure",
         ACTION_SESSION_REJECTED),
        
        # 16. DRL rollback -> session_rejected
        ("DRL Rollback Attack",
         "Adversary attempts to install stale DRL with lower version",
         "Monotonic Version Rollback Protection",
         ACTION_SESSION_REJECTED),
        
        # 17. forged DRL signature -> session_rejected
        ("Forged DRL Signature",
         "Adversary modifies DRL content or tampers with Ed25519 signature",
         "Ed25519 Digital Signature Verification Failure",
         ACTION_SESSION_REJECTED),
        
        # 18. forged epoch header lockout -> session_rejected
        ("Forged Epoch Header Lockout",
         "Forged header with huge epoch and bad HMAC fails without advancing stored epoch",
         "Pre-HMAC Read-Only Monotonicity Guard & State Isolation",
         ACTION_SESSION_REJECTED)
    ]
    
    results = []
    
    # 64x64 test image (16 blocks of 16x16: 4x4 grid)
    base_img = rng.randint(0, 256, (64, 64, 3), dtype=np.uint8)
    padded, orig_shape = pad_image(base_img, BLOCK_SIZE)
    blocks = split_into_blocks(padded, BLOCK_SIZE)
    total_blocks = len(blocks)  # 16
    block_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
    
    # Fast iterations for security tests (1,000 rounds)
    TEST_ITER = 1000
    
    for name, desc, mech, expected_action in scenarios:
        detected_count = 0
        observed_actions = {}
        
        for t in range(NUM_SECURITY_TRIALS):
            trial_seed = seed + t
            t_rng = np.random.RandomState(trial_seed)
            reset_epoch_tracker()
            
            # Setup fresh keys for this trial
            rx_priv = x25519.X25519PrivateKey.generate()
            rx_pub = rx_priv.public_key()
            rx_fp = get_key_fingerprint(rx_pub)
            rx_pub_bytes = rx_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            
            tx_eph_priv = x25519.X25519PrivateKey.generate()
            tx_eph_pub = tx_eph_priv.public_key()
            tx_eph_pub_bytes = tx_eph_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
            
            shared_secret = tx_eph_priv.exchange(rx_pub)
            salt_hkdf = generate_salt(16)
            salt_pbkdf2 = generate_salt(16)
            epoch = 1
            
            k_aes, k_hdr, _ = derive_session_keys(
                shared_secret, tx_eph_pub_bytes, rx_pub_bytes,
                salt_hkdf, salt_pbkdf2, passphrase, device_id, epoch, iterations=TEST_ITER
            )
            
            hdr_bytes = create_session_header(
                epoch, padded.shape[0], padded.shape[1], total_blocks,
                salt_hkdf, salt_pbkdf2, tx_eph_pub_bytes, rx_fp, k_hdr
            )
            
            enc_records = encrypt_blocks(blocks, k_aes, padded.shape, epoch=epoch)
            
            # Execute specific vector
            if name == "In-Place Bit-Flip in Ciphertext":
                target_idx = t_rng.randint(0, total_blocks)
                corrupted = list(enc_records)
                r = bytearray(corrupted[target_idx])
                bit_pos = 16 + t_rng.randint(0, 767)
                r[bit_pos] ^= 0x01
                corrupted[target_idx] = bytes(r)
                # 1 block out of 16 = 6.25% <= tau=0.25; without concealment -> detected_and_quarantined
                dec = decrypt_blocks(corrupted, k_aes, padded.shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=False, concealment_tau=0.25)
                act = dec['action']
                if act == expected_action and target_idx in dec['failed_indices']:
                    detected_count += 1
                    
            elif name == "Block Swap / Index Splicing":
                # Swap blocks 0 and 1 (2 blocks out of 16 = 12.5% <= tau=0.25)
                rec0 = enc_records[0]
                rec1 = enc_records[1]
                idx0, n0, c0, t0_tag = unpack_record(rec0)
                idx1, n1, c1, t1_tag = unpack_record(rec1)
                tampered = list(enc_records)
                tampered[0] = pack_record(0, n1, c1, t1_tag)
                tampered[1] = pack_record(1, n0, c0, t0_tag)
                dec = decrypt_blocks(tampered, k_aes, padded.shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=False, concealment_tau=0.25)
                act = dec['action']
                if act == expected_action and 0 in dec['failed_indices'] and 1 in dec['failed_indices']:
                    detected_count += 1
                    
            elif name == "Header Index Tampering":
                # Adversary alters transmitted header index (index 0 altered to index 1)
                rec = enc_records[0]
                idx, n, c, tag = unpack_record(rec)
                tampered = pack_record(1, n, c, tag)
                # Receiver processes tampered record; AAD mismatch triggers InvalidTag quarantine
                dec = decrypt_blocks([tampered], k_aes, padded.shape, block_shape, total_blocks=2,
                                     epoch=epoch, enable_concealment=False, concealment_tau=1.0)
                act = dec['action']
                if act == expected_action and 1 in dec['failed_indices']:
                    detected_count += 1
                    
            elif name == "Cross-Session Splice":
                sess2 = generate_session_key()
                hs2 = generate_salt()
                ps2 = generate_salt()
                k_aes2 = derive_key(sess2, hs2, ps2, passphrase, device_id, epoch=2)
                records_sess2 = encrypt_blocks(blocks, k_aes2, padded.shape, epoch=2)
                spliced = list(records_sess2)
                spliced[0] = enc_records[0]  # block from session 1
                dec = decrypt_blocks(spliced, k_aes2, padded.shape, block_shape, total_blocks,
                                     epoch=2, enable_concealment=False, concealment_tau=0.25)
                act = dec['action']
                if act == expected_action and 0 in dec['failed_indices']:
                    detected_count += 1
                    
            elif name == "Cross-Epoch Replay in Stream":
                k_aes_ep2, _, _ = derive_session_keys(
                    shared_secret, tx_eph_pub_bytes, rx_pub_bytes,
                    salt_hkdf, salt_pbkdf2, passphrase, device_id, epoch=2, iterations=TEST_ITER
                )
                records_ep2 = encrypt_blocks(blocks, k_aes_ep2, padded.shape, epoch=2)
                spliced = list(records_ep2)
                spliced[0] = enc_records[0]  # block from epoch 1
                dec = decrypt_blocks(spliced, k_aes_ep2, padded.shape, block_shape, total_blocks,
                                     epoch=2, enable_concealment=False, concealment_tau=0.25)
                act = dec['action']
                if act == expected_action and 0 in dec['failed_indices']:
                    detected_count += 1
                    
            elif name == "Dropped Record (Packet Loss)":
                # Drop 1 block out of 16 (6.25% <= tau=0.25) -> concealed
                drop_target = t_rng.randint(0, total_blocks)
                dropped = [r for r in enc_records if unpack_record(r)[0] != drop_target]
                dec = decrypt_blocks(dropped, k_aes, padded.shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=True, concealment_tau=0.25)
                act = dec['action']
                if act == expected_action and drop_target in dec['missing_indices']:
                    detected_count += 1
                    
            elif name == "Duplicated Record Injection":
                # Inject 1 duplicate block record
                dup = list(enc_records) + [enc_records[0]]
                dec = decrypt_blocks(dup, k_aes, padded.shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=False, concealment_tau=0.25)
                act = dec['action']
                if act == expected_action and dec['duplicate_blocks_ignored'] == 1:
                    detected_count += 1
                    
            elif name == "Stream Truncation Attack":
                # Truncate trailing 50% (8 blocks missing out of 16 -> 50% > tau=0.25)
                truncated = enc_records[:8]
                dec = decrypt_blocks(truncated, k_aes, padded.shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=True, concealment_tau=0.25)
                act = dec['action']
                if act == expected_action and len(dec['missing_indices']) == 8:
                    detected_count += 1
                    
            elif name == "Dimension Tampering in AAD (H/W/N)":
                tampered_shape = (padded.shape[0] * 2, padded.shape[1], 3)
                dec = decrypt_blocks(enc_records, k_aes, tampered_shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=False, concealment_tau=1.0)
                act = dec['action']
                if act == expected_action and dec['failed_blocks'] == total_blocks:
                    detected_count += 1
                    
            elif name == "Unauthorized Device ID":
                wrong_dev = f"{t_rng.randint(100000, 999999):064d}"
                wrong_k_aes, _, _ = derive_session_keys(
                    shared_secret, tx_eph_pub_bytes, rx_pub_bytes,
                    salt_hkdf, salt_pbkdf2, passphrase, wrong_dev, epoch, iterations=TEST_ITER
                )
                dec = decrypt_blocks(enc_records, wrong_k_aes, padded.shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=False, concealment_tau=1.0)
                act = dec['action']
                if act == expected_action and dec['failed_blocks'] == total_blocks:
                    detected_count += 1
                    
            elif name == "Incorrect Passphrase":
                wrong_pw = f"WrongPassword_{t}!"
                wrong_k_aes, _, _ = derive_session_keys(
                    shared_secret, tx_eph_pub_bytes, rx_pub_bytes,
                    salt_hkdf, salt_pbkdf2, wrong_pw, device_id, epoch, iterations=TEST_ITER
                )
                dec = decrypt_blocks(enc_records, wrong_k_aes, padded.shape, block_shape, total_blocks,
                                     epoch=epoch, enable_concealment=False, concealment_tau=1.0)
                act = dec['action']
                if act == expected_action and dec['failed_blocks'] == total_blocks:
                    detected_count += 1
                    
            elif name == "Revoked Device Access":
                revoke_device(device_id)
                res = receive_and_decrypt_stream(
                    hdr_bytes, enc_records, rx_priv, passphrase, device_id,
                    tau=0.25, iterations=TEST_ITER
                )
                unrevoke_device(device_id)
                act = res['action']
                if act == expected_action:
                    detected_count += 1
                    
            elif name == "Session Header Bit-Flip":
                hdr_corrupt = bytearray(hdr_bytes)
                flip_pos = t_rng.randint(0, len(hdr_bytes))
                hdr_corrupt[flip_pos] ^= 0x01
                res = receive_and_decrypt_stream(
                    bytes(hdr_corrupt), enc_records, rx_priv, passphrase, device_id,
                    tau=0.25, iterations=TEST_ITER
                )
                act = res['action']
                if act == expected_action:
                    detected_count += 1
                    
            elif name == "Ephemeral Public Key Substitution":
                rogue_priv = x25519.X25519PrivateKey.generate()
                rogue_pub_bytes = rogue_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
                hdr_tampered = bytearray(hdr_bytes)
                hdr_tampered[54:86] = rogue_pub_bytes
                res = receive_and_decrypt_stream(
                    bytes(hdr_tampered), enc_records, rx_priv, passphrase, device_id,
                    tau=0.25, iterations=TEST_ITER
                )
                act = res['action']
                if act == expected_action:
                    detected_count += 1
                    
            elif name == "Wrong Receiver Static Key":
                wrong_rx_priv = x25519.X25519PrivateKey.generate()
                res = receive_and_decrypt_stream(
                    hdr_bytes, enc_records, wrong_rx_priv, passphrase, device_id,
                    tau=0.25, iterations=TEST_ITER
                )
                act = res['action']
                if act == expected_action:
                    detected_count += 1
                    
            elif name == "DRL Rollback Attack":
                reset_drl_tracker()
                drl_signer = ed25519.Ed25519PrivateKey.generate()
                drl_v2 = sign_drl(drl_signer, version=2, entries=["revoked_a"])
                drl_v1 = sign_drl(drl_signer, version=1, entries=["revoked_b"])
                
                # Receiver has installed version 2
                verify_and_load_drl(drl_v2, drl_signer.public_key())
                
                # Attacker tries to install older version 1 over version 2
                try:
                    verify_and_load_drl(drl_v1, drl_signer.public_key())
                    act = "accepted_rollback"
                except DRLRollbackError:
                    act = ACTION_SESSION_REJECTED
                    detected_count += 1
                finally:
                    reset_drl_tracker()
                        
            elif name == "Forged DRL Signature":
                drl_signer = ed25519.Ed25519PrivateKey.generate()
                drl_doc = sign_drl(drl_signer, version=1, entries=["revoked_x"])
                # Tamper entries
                drl_doc['entries'].append("unauthorized_entry")
                try:
                    verify_and_load_drl(drl_doc, drl_signer.public_key())
                    act = "accepted_forgery"
                except DRLSignatureError:
                    act = ACTION_SESSION_REJECTED
                    detected_count += 1
                    
            elif name == "Forged Epoch Header Lockout":
                reset_epoch_tracker(clean_disk=False)
                verify_and_update_epoch("lockout_sender_node", 1)
                
                # Adversary injects forged header with huge epoch and corrupted HMAC
                forged_hdr = bytearray(hdr_bytes)
                struct.pack_into(">I", forged_hdr, 6, 999999 + t)
                forged_hdr[-1] ^= 0xFF
                
                res = receive_and_decrypt_stream(
                    bytes(forged_hdr), enc_records, rx_priv, passphrase, device_id,
                    sender_id="lockout_sender_node", tau=0.25, iterations=TEST_ITER
                )
                act = res['action']
                if act == expected_action and get_last_accepted_epoch("lockout_sender_node") == 1:
                    detected_count += 1
                    
            observed_actions[act] = observed_actions.get(act, 0) + 1
        
        rate = (detected_count / float(NUM_SECURITY_TRIALS)) * 100.0
        most_common_act = max(observed_actions, key=observed_actions.get)
        entry = {
            'attack_scenario': name,
            'description': desc,
            'expected_action': expected_action,
            'observed_action': most_common_act,
            'detection_mechanism': mech,
            'trials': NUM_SECURITY_TRIALS,
            'detected_count': detected_count,
            'detection_rate_pct': round(rate, 2)
        }
        results.append(entry)
        print(f"{name:<35} | Action: {most_common_act:<26} | Detected: {detected_count:>3}/{NUM_SECURITY_TRIALS} ({rate:.1f}%) | {mech}")
        
    out_json = os.path.join(RESULTS_DIR, "security_tests.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print("\nSaved security test results to", out_json)
    
    out_csv = os.path.join(RESULTS_DIR, "security_tests.csv")
    with open(out_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print("Saved security test CSV to", out_csv)
    return results

if __name__ == "__main__":
    run_security_attack_suite()
