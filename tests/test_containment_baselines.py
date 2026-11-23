import unittest
import os
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.baseline_ciphers import (
    cbc_encrypt_monolithic,
    cbc_decrypt_monolithic,
    cbc_block_framed_encrypt,
    cbc_block_framed_decrypt,
    cbc_block_hmac_encrypt,
    cbc_block_hmac_decrypt
)
from src.encryption import encrypt_blocks
from src.decryption import decrypt_blocks

class TestContainmentBaselines(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.mac_key = os.urandom(32)
        self.block_shape = (16, 16, 3)  # 768 bytes = 48 AES blocks of 16 bytes
        # Create 10 deterministic test blocks
        self.blocks = [np.full((16, 16, 3), (i + 1) * 20, dtype=np.uint8) for i in range(10)]
        self.flat = b"".join(b.tobytes() for b in self.blocks)  # 7680 bytes

    def test_cbc_bit_flip_affects_at_most_two_blocks(self):
        """Task 5.9: CBC bit flip affects <= 2 AES blocks and <= 2 image blocks."""
        iv, ct = cbc_encrypt_monolithic(self.flat, self.key)
        ct_corrupt = bytearray(ct)
        
        # Flip a bit in the middle of block 3 (byte offset 3 * 768 + 100)
        flip_pos = 3 * 768 + 100
        ct_corrupt[flip_pos] ^= 0x01
        
        pt = cbc_decrypt_monolithic(iv, bytes(ct_corrupt), self.key)
        
        # Check affected 16-byte AES blocks
        num_aes_blocks = len(self.flat) // 16
        aes_wrong = 0
        for b_idx in range(num_aes_blocks):
            orig_aes = self.flat[b_idx*16:(b_idx+1)*16]
            dec_aes = pt[b_idx*16:(b_idx+1)*16]
            if orig_aes != dec_aes:
                aes_wrong += 1
                
        # In CBC mode: 1 ciphertext block error corrupts its own plaintext block completely
        # and flips 1 bit in the NEXT plaintext block. Thus, exactly 2 AES blocks are corrupted!
        self.assertLessEqual(aes_wrong, 2)
        self.assertEqual(aes_wrong, 2)

        # Check affected 768-byte image blocks
        image_blocks_wrong = 0
        for i_idx in range(10):
            orig_img = self.flat[i_idx*768:(i_idx+1)*768]
            dec_img = pt[i_idx*768:(i_idx+1)*768]
            if orig_img != dec_img:
                image_blocks_wrong += 1
                
        self.assertLessEqual(image_blocks_wrong, 2)

    def test_framed_cbc_under_m3_record_deletion(self):
        """Task 5.9: Framed CBC under M3 loses only the deleted record's block."""
        records = cbc_block_framed_encrypt(self.blocks, self.key)
        
        # Delete record index 4
        deleted_records = [r for idx, r in enumerate(records) if idx != 4]
        
        dec = cbc_block_framed_decrypt(deleted_records, self.key, self.block_shape, 10)
        self.assertEqual(dec['missing_indices'], [4])
        self.assertEqual(dec['missing_count'], 1)
        
        # All other 9 blocks must be 100% byte-for-byte identical to original
        for i in range(10):
            if i != 4:
                self.assertTrue(np.array_equal(self.blocks[i], dec['blocks'][i]))

    def test_cbc_hmac_detects_every_flipped_record(self):
        """Task 5.9: CBC+HMAC detects every flipped record."""
        records = cbc_block_hmac_encrypt(self.blocks, self.key, self.mac_key)
        
        # Corrupt 3 random records: index 2, 5, 8
        corrupted = list(records)
        for idx in [2, 5, 8]:
            r = bytearray(corrupted[idx])
            r[25] ^= 0x01
            corrupted[idx] = bytes(r)
            
        dec = cbc_block_hmac_decrypt(corrupted, self.key, self.mac_key, self.block_shape, 10)
        self.assertEqual(sorted(dec['failed_indices']), [2, 5, 8])
        self.assertEqual(dec['failed_count'], 3)
        self.assertEqual(dec['missing_count'], 0)

    def test_proposed_scheme_exact_containment(self):
        """Task 5.9: Proposed scheme blocks_wrong == blocks_corrupted for M1 and M3."""
        records = encrypt_blocks(self.blocks, self.key, (32, 80, 3))
        
        # M1: In-place bit flip on blocks 1, 3, 7
        m1_records = list(records)
        for idx in [1, 3, 7]:
            r = bytearray(m1_records[idx])
            r[20] ^= 0xFF
            m1_records[idx] = bytes(r)
            
        dec_m1 = decrypt_blocks(m1_records, self.key, (32, 80, 3), self.block_shape, 10)
        self.assertEqual(dec_m1['failed_blocks'], 3)
        # Exactly 3 blocks wrong
        wrong_m1 = sum(1 for orig, d in zip(self.blocks, dec_m1['blocks']) if not np.array_equal(orig, d))
        self.assertEqual(wrong_m1, 3)

        # M3: Deletion of blocks 0, 4, 9
        m3_records = [r for idx, r in enumerate(records) if idx not in [0, 4, 9]]
        dec_m3 = decrypt_blocks(m3_records, self.key, (32, 80, 3), self.block_shape, 10)
        self.assertEqual(dec_m3['missing_blocks'], 3)
        wrong_m3 = sum(1 for orig, d in zip(self.blocks, dec_m3['blocks']) if not np.array_equal(orig, d))
        self.assertEqual(wrong_m3, 3)

if __name__ == '__main__':
    unittest.main()

