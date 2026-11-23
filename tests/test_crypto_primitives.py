import unittest
import numpy as np

from src.config import BLOCK_SIZE
from src.image_processor import pad_image, unpad_image, split_into_blocks, merge_blocks
from src.encryption import encrypt_blocks
from src.decryption import decrypt_blocks
from src.record_format import unpack_record
from src.key_manager import (
    generate_session_key,
    generate_salt,
    derive_key,
    get_device_id,
    best_effort_zeroize
)

class TestCryptoPrimitives(unittest.TestCase):
    def setUp(self):
        self.device_id = get_device_id()
        self.passphrase = "PrimarySecret987!"
        self.sess = generate_session_key()
        self.hs = generate_salt()
        self.ps = generate_salt()
        self.key = derive_key(self.sess, self.hs, self.ps, self.passphrase, self.device_id, epoch=0)

    def test_nonce_uniqueness_large_image(self):
        # 1024x1024 RGB image -> 4096 blocks
        dummy_blocks = [np.zeros((BLOCK_SIZE, BLOCK_SIZE, 3), dtype=np.uint8) for _ in range(4096)]
        enc_records = encrypt_blocks(dummy_blocks, self.key, (1024, 1024, 3), epoch=0)
        self.assertEqual(len(enc_records), 4096)
        
        nonces = set()
        for rec in enc_records:
            idx, nonce, ct, tag = unpack_record(rec)
            self.assertNotIn(nonce, nonces, f"Duplicate nonce detected at block {idx}!")
            nonces.add(nonce)
        self.assertEqual(len(nonces), 4096)

    def test_non_multiple_of_16_round_trip(self):
        # Odd dimensions: 460 x 1199 x 3 (matches Submarine)
        orig_img = np.random.randint(0, 256, (460, 1199, 3), dtype=np.uint8)
        padded, orig_shape = pad_image(orig_img)
        self.assertEqual(padded.shape, (464, 1200, 3))
        
        blocks = split_into_blocks(padded)
        self.assertEqual(len(blocks), (464 // 16) * (1200 // 16))  # 29 * 75 = 2175 blocks
        
        enc = encrypt_blocks(blocks, self.key, padded.shape, epoch=0)
        dec_res = decrypt_blocks(enc, self.key, padded.shape, (BLOCK_SIZE, BLOCK_SIZE, 3), len(blocks), epoch=0)
        self.assertEqual(dec_res['failed_count'], 0)
        
        merged = merge_blocks(dec_res['blocks'], padded.shape)
        recovered = unpad_image(merged, orig_shape)
        self.assertEqual(recovered.shape, orig_img.shape)
        np.testing.assert_array_equal(orig_img, recovered)

    def test_grayscale_round_trip(self):
        # Grayscale image 256x256
        gray_img = np.random.randint(0, 256, (256, 256), dtype=np.uint8)
        # Convert to RGB representation for pipeline standard
        rgb_equiv = np.stack([gray_img] * 3, axis=-1)
        padded, orig_shape = pad_image(rgb_equiv)
        blocks = split_into_blocks(padded)
        enc = encrypt_blocks(blocks, self.key, padded.shape, epoch=0)
        dec_res = decrypt_blocks(enc, self.key, padded.shape, (BLOCK_SIZE, BLOCK_SIZE, 3), len(blocks), epoch=0)
        self.assertEqual(dec_res['failed_count'], 0)
        recovered = unpad_image(merge_blocks(dec_res['blocks'], padded.shape), orig_shape)
        np.testing.assert_array_equal(rgb_equiv, recovered)

    def test_zeroization_helper(self):
        secret = bytearray(b"HighlySensitiveKeyMaterial123456")
        self.assertNotEqual(secret, bytearray(len(secret)))
        best_effort_zeroize(secret)
        self.assertEqual(secret, bytearray(len(secret)))

if __name__ == "__main__":
    unittest.main()

