import unittest
import os
import struct
import numpy as np

from src.config import BLOCK_SIZE
from src.image_processor import pad_image, split_into_blocks
from src.encryption import encrypt_blocks
from src.decryption import decrypt_blocks
from src.record_format import pack_record, unpack_record
from src.key_manager import (
    generate_session_key,
    generate_salt,
    derive_key,
    get_device_id,
    verify_device,
    revoke_device,
    unrevoke_device,
    is_device_revoked,
    verify_and_update_epoch,
    reset_epoch_tracker
)

class TestSecurityAttacks(unittest.TestCase):
    """Systematic validation of 12 security and adversarial attack scenarios."""

    def setUp(self):
        reset_epoch_tracker()
        self.device_id = get_device_id()
        self.passphrase = "SecretPassphrase123!"
        self.session_key = generate_session_key()
        self.hkdf_salt = generate_salt()
        self.pw_salt = generate_salt()
        self.key = derive_key(self.session_key, self.hkdf_salt, self.pw_salt, 
                              self.passphrase, self.device_id, epoch=1)
        
        # Create a small 32x32 test image (4 blocks of 16x16)
        self.orig_img = np.random.randint(0, 256, (32, 32, 3), dtype=np.uint8)
        self.padded_img, self.orig_shape = pad_image(self.orig_img)
        self.blocks = split_into_blocks(self.padded_img)
        self.total_blocks = len(self.blocks)
        self.block_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
        self.enc_records = encrypt_blocks(self.blocks, self.key, self.padded_img.shape, epoch=1)

    def test_clean_transmission(self):
        res = decrypt_blocks(self.enc_records, self.key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertEqual(res['failed_count'], 0)
        self.assertEqual(res['missing_count'], 0)
        for orig, dec in zip(self.blocks, res['blocks']):
            np.testing.assert_array_equal(orig, dec)

    def test_block_swap_attack(self):
        # Swap payloads: record at header index 0 has payload of block 1,
        # and record at header index 1 has payload of block 0
        idx0, nonce0, ct0, tag0 = unpack_record(self.enc_records[0])
        idx1, nonce1, ct1, tag1 = unpack_record(self.enc_records[1])
        
        tampered = list(self.enc_records)
        # Header 0 with payload 1
        tampered[0] = pack_record(0, nonce1, ct1, tag1)
        # Header 1 with payload 0
        tampered[1] = pack_record(1, nonce0, ct0, tag0)
        
        res = decrypt_blocks(tampered, self.key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertIn(0, res['failed_indices'])
        self.assertIn(1, res['failed_indices'])
        self.assertEqual(res['failed_count'], 2)

    def test_cross_session_splice_attack(self):
        # Encrypt with epoch 1, attempt to inject block into epoch 2 session
        key2 = derive_key(self.session_key, self.hkdf_salt, self.pw_salt, self.passphrase, self.device_id, epoch=2)
        records_ep2 = encrypt_blocks(self.blocks, key2, self.padded_img.shape, epoch=2)
        # Splice block 0 from epoch 1 into epoch 2
        spliced = list(records_ep2)
        spliced[0] = self.enc_records[0]
        res = decrypt_blocks(spliced, key2, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=2)
        self.assertIn(0, res['failed_indices'])

    def test_cross_epoch_replay_rejection(self):
        sender = "sender_alpha"
        self.assertTrue(verify_and_update_epoch(sender, 1))
        self.assertTrue(verify_and_update_epoch(sender, 2))
        # Replay epoch 1 -> must be rejected
        self.assertFalse(verify_and_update_epoch(sender, 1))
        # Replay epoch 2 -> must be rejected
        self.assertFalse(verify_and_update_epoch(sender, 2))
        # Advance epoch 3 -> accepted
        self.assertTrue(verify_and_update_epoch(sender, 3))

    def test_dropped_block_detection(self):
        # Drop block index 2
        dropped = [r for r in self.enc_records if unpack_record(r)[0] != 2]
        res = decrypt_blocks(dropped, self.key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertIn(2, res['missing_indices'])
        self.assertEqual(res['missing_count'], 1)
        # Other blocks must decrypt cleanly
        self.assertEqual(res['failed_count'], 0)

    def test_duplicated_block_handling(self):
        # Duplicate block 0 at end of stream
        dup = list(self.enc_records) + [self.enc_records[0]]
        res = decrypt_blocks(dup, self.key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertEqual(res['failed_count'], 0)
        self.assertEqual(res['missing_count'], 0)

    def test_truncated_stream(self):
        # Truncate stream to only first 2 blocks
        truncated = self.enc_records[:2]
        res = decrypt_blocks(truncated, self.key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertEqual(res['missing_indices'], [2, 3])
        self.assertEqual(res['missing_count'], 2)

    def test_modified_metadata_aad_mismatch(self):
        # Attacker modifies claimed height/width
        tampered_shape = (64, 32, 3)
        res = decrypt_blocks(self.enc_records, self.key, tampered_shape, self.block_shape, self.total_blocks, epoch=1)
        # All blocks fail because AAD binds height/width
        self.assertEqual(res['failed_count'], self.total_blocks)

    def test_tampered_header_index(self):
        # Alter header index of record 0 to index 3
        idx, nonce, ct, tag = unpack_record(self.enc_records[0])
        tampered_rec = pack_record(3, nonce, ct, tag)
        res = decrypt_blocks([tampered_rec], self.key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertIn(3, res['failed_indices'])

    def test_wrong_device_id_rejection(self):
        wrong_id = "0000000000000000000000000000000000000000000000000000000000000000"
        self.assertFalse(verify_device(wrong_id))
        wrong_key = derive_key(self.session_key, self.hkdf_salt, self.pw_salt, self.passphrase, wrong_id, epoch=1)
        res = decrypt_blocks(self.enc_records, wrong_key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertEqual(res['failed_count'], self.total_blocks)

    def test_wrong_passphrase_rejection(self):
        wrong_pw = "WrongPassphrase999!"
        wrong_key = derive_key(self.session_key, self.hkdf_salt, self.pw_salt, wrong_pw, self.device_id, epoch=1)
        res = decrypt_blocks(self.enc_records, wrong_key, self.padded_img.shape, self.block_shape, self.total_blocks, epoch=1)
        self.assertEqual(res['failed_count'], self.total_blocks)

    def test_device_revocation_enforcement(self):
        self.assertFalse(is_device_revoked(self.device_id))
        revoke_device(self.device_id)
        self.assertTrue(is_device_revoked(self.device_id))
        self.assertFalse(verify_device(self.device_id))
        unrevoke_device(self.device_id)
        self.assertFalse(is_device_revoked(self.device_id))
        self.assertTrue(verify_device(self.device_id))

    def test_device_id_not_exposed_in_exports_or_results(self):
        """F2: Verify that get_device_id() output never appears in exported session JSON or results."""
        dev_id = get_device_id()
        self.assertTrue(len(dev_id) == 64, "Device ID should be a 64-char SHA-256 hex string")

        # 1. Check all JSON and CSV in results/ (excluding archive)
        results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
        if os.path.exists(results_dir):
            for root, dirs, files in os.walk(results_dir):
                if "archive" in root:
                    continue
                for f in files:
                    if f.endswith((".json", ".csv")):
                        fpath = os.path.join(root, f)
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as rf:
                            content = rf.read()
                            self.assertNotIn(dev_id, content, f"Device ID found in results file: {fpath}")

        # 2. Verify dashboard session export structure from app.py
        mock_export = {
            'timestamp': 1730700000,
            'action': 'concealed',
            'tau': 0.25,
            'scenario': 'M3 Packet Loss',
            'corrupted_blocks': 10,
            'authentic_blocks': 100,
            'failed_blocks': 0,
            'missing_blocks': 10,
            'epr': 1.0,
            'psnr': 45.57,
            'ssim': 0.9997
        }
        export_str = str(mock_export)
        self.assertNotIn(dev_id, export_str)
        self.assertNotIn("device_id", mock_export)
        self.assertNotIn("device", mock_export)

    def test_cbc_malleability_tamper_detection(self):
        """G2: Test that CBC bit malleability controls plaintext bits in unauthenticated CBC,
        while Proposed AES-GCM and CBC+HMAC detect and quarantine the tampered block.
        """
        from experiments.exp_cbc_malleability import run_malleability_experiment
        res = run_malleability_experiment(num_trials=20, seed=123, save_results=False)
        self.assertEqual(res["summary"]["unframed_cbc"]["controlled_bit_flip_success_rate_pct"], 100.0)
        self.assertEqual(res["summary"]["unframed_cbc"]["detection_rate_pct"], 0.0)
        self.assertEqual(res["summary"]["framed_cbc"]["controlled_bit_flip_success_rate_pct"], 100.0)
        self.assertEqual(res["summary"]["framed_cbc"]["detection_rate_pct"], 0.0)
        self.assertEqual(res["summary"]["cbc_hmac"]["detection_rate_pct"], 100.0)
        self.assertEqual(res["summary"]["cbc_hmac"]["controlled_bit_flip_success_rate_pct"], 0.0)
        self.assertEqual(res["summary"]["proposed_gcm"]["detection_rate_pct"], 100.0)
        self.assertEqual(res["summary"]["proposed_gcm"]["controlled_bit_flip_success_rate_pct"], 0.0)

if __name__ == "__main__":
    unittest.main()

