import unittest
import numpy as np
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.record_format import pack_record, create_session_header
from src.key_manager import (
    generate_receiver_static_keypair,
    get_key_fingerprint,
    derive_session_keys,
    reset_epoch_tracker,
    revoke_fingerprint,
    unrevoke_fingerprint,
    get_last_accepted_epoch
)
from src.encryption import encrypt_blocks
from src.decryption import (
    decrypt_blocks,
    receive_and_decrypt_stream,
    ACTION_CONCEALED,
    ACTION_REJECTED_OVER_THRESHOLD,
    ACTION_DUPLICATE_IGNORED,
    ACTION_SESSION_REJECTED,
    ACTION_DETECTED_AND_QUARANTINED,
    ACTION_AUTHENTIC
)

class TestReceiverPolicy(unittest.TestCase):
    def setUp(self):
        reset_epoch_tracker(clean_disk=True)
        self.rx_priv, self.rx_pub = generate_receiver_static_keypair()
        self.rx_pub_bytes = self.rx_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.fingerprint = get_key_fingerprint(self.rx_pub)
        
        self.tx_priv, self.tx_pub = generate_receiver_static_keypair()
        self.tx_pub_bytes = self.tx_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        
        self.salt_hkdf = b"0" * 16
        self.salt_pbkdf2 = b"1" * 16
        self.passphrase = "SecretPassphrase2026!#"
        self.device_id = "test_device_id_val"
        self.epoch = 1
        
        # 4 blocks of 16x16x3 (32x32 image)
        self.H, self.W = 32, 32
        self.block_shape = (16, 16, 3)
        self.total_blocks = 4
        
        shared = self.tx_priv.exchange(self.rx_pub)
        self.k_aes, self.k_hdr, self.k_session = derive_session_keys(
            shared, self.tx_pub_bytes, self.rx_pub_bytes,
            self.salt_hkdf, self.salt_pbkdf2, self.passphrase, self.device_id, self.epoch,
            iterations=1000
        )
        
        # Create 4 test blocks
        self.blocks = [np.full((16, 16, 3), i * 50, dtype=np.uint8) for i in range(4)]
        self.records = encrypt_blocks(self.blocks, self.k_aes, (32, 32, 3), epoch=self.epoch)
        self.header = create_session_header(
            self.epoch, self.H, self.W, self.total_blocks,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint, self.k_hdr
        )

    def test_authentic_stream(self):
        res = receive_and_decrypt_stream(
            self.header, self.records, self.rx_priv,
            self.passphrase, self.device_id, enable_concealment=True,
            iterations=1000
        )
        self.assertEqual(res['action'], ACTION_AUTHENTIC)
        self.assertEqual(res['authentic_blocks'], 4)
        self.assertEqual(res['failed_blocks'], 0)
        self.assertEqual(res['missing_blocks'], 0)
        self.assertEqual(res['duplicate_blocks_ignored'], 0)
        self.assertFalse(res['concealment_applied'])

    def test_missing_gap_and_concealment(self):
        # Drop block index 1 (1 of 4 blocks = 25% <= tau=0.30)
        lossy_records = [self.records[0], self.records[2], self.records[3]]
        res = receive_and_decrypt_stream(
            self.header, lossy_records, self.rx_priv,
            self.passphrase, self.device_id, enable_concealment=True, tau=0.30,
            iterations=1000
        )
        self.assertEqual(res['action'], ACTION_CONCEALED)
        self.assertEqual(res['missing_blocks'], 1)
        self.assertEqual(res['missing_indices'], [1])
        self.assertTrue(res['concealment_applied'])
        self.assertTrue(res['concealed_block_mask'][0, 1])
        # Concealed streams must NEVER be marked authentic
        self.assertNotEqual(res['action'], ACTION_AUTHENTIC)

    def test_rejected_over_threshold(self):
        # Drop 2 of 4 blocks = 50% > tau=0.25
        lossy_records = [self.records[0], self.records[3]]
        res = receive_and_decrypt_stream(
            self.header, lossy_records, self.rx_priv,
            self.passphrase, self.device_id, enable_concealment=True, tau=0.25,
            iterations=1000
        )
        self.assertEqual(res['action'], ACTION_REJECTED_OVER_THRESHOLD)
        self.assertFalse(res['concealment_applied'])
        self.assertEqual(res['failed_fraction'], 0.5)

    def test_detected_and_quarantined_when_concealment_disabled(self):
        # 1 corrupt block with enable_concealment=False
        corrupted = list(self.records)
        r1 = bytearray(corrupted[1])
        r1[20] ^= 0xFF
        corrupted[1] = bytes(r1)
        
        res = receive_and_decrypt_stream(
            self.header, corrupted, self.rx_priv,
            self.passphrase, self.device_id, enable_concealment=False, tau=0.5,
            iterations=1000
        )
        self.assertEqual(res['action'], ACTION_DETECTED_AND_QUARANTINED)
        self.assertEqual(res['failed_blocks'], 1)
        self.assertFalse(res['concealment_applied'])

    def test_duplicate_records_ignored(self):
        # Transmit [R0, R1, R1 (duplicate), R2, R3]
        dup_records = [self.records[0], self.records[1], self.records[1], self.records[2], self.records[3]]
        res = receive_and_decrypt_stream(
            self.header, dup_records, self.rx_priv,
            self.passphrase, self.device_id, enable_concealment=True,
            iterations=1000
        )
        self.assertEqual(res['action'], ACTION_DUPLICATE_IGNORED)
        self.assertEqual(res['duplicate_blocks_ignored'], 1)
        self.assertEqual(res['authentic_blocks'], 4)

    def test_session_rejected_wrong_passphrase(self):
        res = receive_and_decrypt_stream(
            self.header, self.records, self.rx_priv,
            "WrongSecretPassphrase123!", self.device_id,
            iterations=1000
        )
        self.assertEqual(res['action'], ACTION_SESSION_REJECTED)
        self.assertEqual(len(res['blocks']), 0)

    def test_session_rejected_revoked_fingerprint(self):
        revoke_fingerprint(self.fingerprint)
        try:
            res = receive_and_decrypt_stream(
                self.header, self.records, self.rx_priv,
                self.passphrase, self.device_id,
                iterations=1000
            )
            self.assertEqual(res['action'], ACTION_SESSION_REJECTED)
        finally:
            unrevoke_fingerprint(self.fingerprint)

    def test_session_rejected_epoch_replay(self):
        shared = self.tx_priv.exchange(self.rx_pub)
        _, k_hdr_ep2, _ = derive_session_keys(
            shared, self.tx_pub_bytes, self.rx_pub_bytes,
            self.salt_hkdf, self.salt_pbkdf2, self.passphrase, self.device_id, 2,
            iterations=1000
        )
        header_ep2 = create_session_header(
            2, self.H, self.W, self.total_blocks,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint, k_hdr_ep2
        )
        # Verify epoch 2 passes header gate (records fail block decryption if encrypted under epoch 1)
        res1 = receive_and_decrypt_stream(
            header_ep2, self.records, self.rx_priv,
            self.passphrase, self.device_id,
            iterations=1000
        )
        self.assertNotEqual(res1['action'], ACTION_SESSION_REJECTED)

        # Replaying epoch 1 or epoch 2 must be rejected at the session gate
        res2 = receive_and_decrypt_stream(
            self.header, self.records, self.rx_priv,
            self.passphrase, self.device_id,
            iterations=1000
        )
        self.assertEqual(res2['action'], ACTION_SESSION_REJECTED)

    def test_forged_header_huge_epoch_leaves_stored_epoch_unchanged(self):
        """Fix F1(a, b): Forged header with huge epoch and bad HMAC leaves stored epoch unchanged;
        subsequent legitimate header with next epoch succeeds.
        """
        sender = "default_sender"
        # 1. Establish valid session at epoch 1
        res1 = receive_and_decrypt_stream(
            self.header, self.records, self.rx_priv,
            self.passphrase, self.device_id, sender_id=sender,
            iterations=1000
        )
        self.assertEqual(res1['action'], ACTION_AUTHENTIC)
        self.assertEqual(get_last_accepted_epoch(sender), 1)

        # 2. Adversary sends forged header with epoch=999,999 and corrupted HMAC
        shared = self.tx_priv.exchange(self.rx_pub)
        _, k_hdr_huge, _ = derive_session_keys(
            shared, self.tx_pub_bytes, self.rx_pub_bytes,
            self.salt_hkdf, self.salt_pbkdf2, self.passphrase, self.device_id, 999999,
            iterations=1000
        )
        forged_header = bytearray(create_session_header(
            999999, self.H, self.W, self.total_blocks,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint, k_hdr_huge
        ))
        forged_header[-1] ^= 0xFF  # Corrupt HMAC tag

        res_forged = receive_and_decrypt_stream(
            bytes(forged_header), self.records, self.rx_priv,
            self.passphrase, self.device_id, sender_id=sender,
            iterations=1000
        )
        self.assertEqual(res_forged['action'], ACTION_SESSION_REJECTED)
        # CRITICAL ASSERTION: Stored epoch MUST remain 1, NOT 999,999!
        self.assertEqual(get_last_accepted_epoch(sender), 1)

        # 3. Legitimate sender sends header with epoch=2 -> MUST SUCCEED!
        _, k_hdr_ep2, _ = derive_session_keys(
            shared, self.tx_pub_bytes, self.rx_pub_bytes,
            self.salt_hkdf, self.salt_pbkdf2, self.passphrase, self.device_id, 2,
            iterations=1000
        )
        header_ep2 = create_session_header(
            2, self.H, self.W, self.total_blocks,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint, k_hdr_ep2
        )
        res_legit = receive_and_decrypt_stream(
            header_ep2, self.records, self.rx_priv,
            self.passphrase, self.device_id, sender_id=sender,
            iterations=1000
        )
        self.assertNotEqual(res_legit['action'], ACTION_SESSION_REJECTED)
        self.assertEqual(get_last_accepted_epoch(sender), 2)

    def test_crash_between_verification_and_persistence_does_not_rollback(self):
        """Fix F1(c): Simulating restart/crash does not roll stored epoch backwards."""
        sender = "crash_test_sender"
        # Atomically commit epoch 5 with persistence
        from src.key_manager import commit_epoch, check_epoch_monotonicity
        self.assertTrue(commit_epoch(sender, 5, persist=True))
        self.assertEqual(get_last_accepted_epoch(sender, persist=True), 5)

        # Simulate process crash / in-memory reset
        reset_epoch_tracker(clean_disk=False)

        # Monotonicity check against disk store must still reject epoch 5 and epoch 4
        self.assertFalse(check_epoch_monotonicity(sender, 5, persist=True))
        self.assertFalse(check_epoch_monotonicity(sender, 4, persist=True))
        self.assertTrue(check_epoch_monotonicity(sender, 6, persist=True))

if __name__ == '__main__':
    unittest.main()
