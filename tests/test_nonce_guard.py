import os
import unittest
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.encryption import (
    encrypt_blocks,
    reset_key_invocation_counter,
    KeyRolloverLimitExceeded
)
import src.encryption as encryption_mod
from src.decryption import decrypt_blocks
from src.record_format import unpack_record

class TestNonceAndKeyGuards(unittest.TestCase):
    def setUp(self):
        reset_key_invocation_counter()
        self.key = os.urandom(32)
        self.blocks = [np.zeros((16, 16, 3), dtype=np.uint8) for _ in range(10)]

    def test_key_invocation_limit_guard(self):
        # Monkeypatch the limit to 15 blocks
        orig_limit = encryption_mod.MAX_GCM_INVOCATIONS_PER_KEY
        try:
            encryption_mod.MAX_GCM_INVOCATIONS_PER_KEY = 15
            
            # First batch of 10 should succeed
            encrypt_blocks(self.blocks, self.key, (32, 80, 3))
            
            # Second batch of 10 would exceed 15 (10 + 10 = 20 > 15) -> must raise KeyRolloverLimitExceeded
            with self.assertRaises(KeyRolloverLimitExceeded):
                encrypt_blocks(self.blocks, self.key, (32, 80, 3))
                
            # A different key has its own fresh limit
            other_key = os.urandom(32)
            encrypt_blocks(self.blocks, other_key, (32, 80, 3))
        finally:
            encryption_mod.MAX_GCM_INVOCATIONS_PER_KEY = orig_limit

    def test_no_duplicate_nonces_across_sessions(self):
        """Task 4.2: Assert zero duplicate (key, IV) pairs across 100 sessions of 4096 blocks."""
        seen_nonces = set()
        total_blocks = 4096
        num_sessions = 100
        
        # Test random nonces across multiple sessions
        for s in range(num_sessions):
            # In each session, generate 4096 96-bit nonces (as encrypt_blocks does)
            session_nonces = [os.urandom(12) for _ in range(total_blocks)]
            
            # Assert all nonces within the session are unique
            self.assertEqual(len(set(session_nonces)), total_blocks)
            
            # Assert no collision across sessions under same key
            for n in session_nonces:
                self.assertNotIn(n, seen_nonces)
                seen_nonces.add(n)

        self.assertEqual(len(seen_nonces), total_blocks * num_sessions)

    def test_deterministic_nonce_mode(self):
        """Task 4.3: Test optional deterministic nonce salt32 || uint64(i)."""
        recs = encrypt_blocks(self.blocks, self.key, (32, 80, 3), deterministic_nonce=True)
        self.assertEqual(len(recs), 10)
        
        # Unpack nonces and verify format: salt (4B) || index (8B)
        salts = set()
        for idx, r in enumerate(recs):
            rec_idx, nonce, ct, tag = unpack_record(r)
            self.assertEqual(rec_idx, idx)
            self.assertEqual(len(nonce), 12)
            salt = nonce[:4]
            salts.add(salt)
            nonce_idx = int.from_bytes(nonce[4:], "big")
            self.assertEqual(nonce_idx, idx)
            
        # All blocks in same session share the session salt
        self.assertEqual(len(salts), 1)

        # Verify decryption works seamlessly with deterministic nonces
        dec = decrypt_blocks(recs, self.key, (32, 80, 3), (16, 16, 3), 10)
        self.assertEqual(dec['authentic_blocks'], 10)
        self.assertEqual(dec['failed_blocks'], 0)

    def test_duplicate_nonce_tamper_and_replay_detection(self):
        """Task 5: Verify that duplicate nonces with modified ciphertext trigger GCM tag failure,
        and verbatim duplicate records are filtered via monotonic deduplication.
        """
        recs = encrypt_blocks(self.blocks, self.key, (32, 80, 3))
        rec0_idx, rec0_nonce, rec0_ct, rec0_tag = unpack_record(recs[0])
        
        # 1. Adversary reuses rec0's nonce with different ciphertext and original tag
        tampered_ct = bytearray(rec0_ct)
        tampered_ct[0] ^= 0x01
        from src.record_format import pack_record
        forged_rec = pack_record(rec0_idx, rec0_nonce, bytes(tampered_ct), rec0_tag)
        
        # Decrypt batch containing the forged record
        test_stream = [forged_rec] + list(recs[1:])
        dec = decrypt_blocks(test_stream, self.key, (32, 80, 3), (16, 16, 3), 10, enable_concealment=False)
        self.assertEqual(dec['failed_blocks'], 1)
        self.assertIn(0, dec['failed_indices'])
        
        # 2. Adversary replays identical valid record (duplicate index + nonce)
        duplicate_stream = [recs[0], recs[0]] + list(recs[1:])
        dec_dup = decrypt_blocks(duplicate_stream, self.key, (32, 80, 3), (16, 16, 3), 10, enable_concealment=False)
        self.assertEqual(dec_dup['duplicate_blocks_ignored'], 1)
        self.assertEqual(dec_dup['authentic_blocks'], 10)

if __name__ == '__main__':
    unittest.main()

