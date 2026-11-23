import os
import sys
import unittest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.chaotic_ciphers import (
    zhou_1d_encrypt,
    zhou_1d_decrypt,
    hua_2d_slmm_encrypt,
    hua_2d_slmm_decrypt,
    msb_selective_encrypt,
    msb_selective_decrypt
)

class TestChaoticCiphers(unittest.TestCase):
    def setUp(self):
        np.random.seed(42)
        self.test_img_gray = np.random.randint(0, 256, (32, 32), dtype=np.uint8)
        self.test_img_rgb = np.random.randint(0, 256, (32, 32, 3), dtype=np.uint8)
        self.aes_key = os.urandom(32)

    def test_zhou_1d_roundtrip_gray(self):
        cipher = zhou_1d_encrypt(self.test_img_gray)
        self.assertFalse(np.array_equal(self.test_img_gray, cipher))
        recovered = zhou_1d_decrypt(cipher)
        np.testing.assert_array_equal(self.test_img_gray, recovered)

    def test_zhou_1d_roundtrip_rgb(self):
        cipher = zhou_1d_encrypt(self.test_img_rgb)
        self.assertFalse(np.array_equal(self.test_img_rgb, cipher))
        recovered = zhou_1d_decrypt(cipher)
        np.testing.assert_array_equal(self.test_img_rgb, recovered)

    def test_hua_2d_roundtrip_gray(self):
        cipher = hua_2d_slmm_encrypt(self.test_img_gray)
        self.assertFalse(np.array_equal(self.test_img_gray, cipher))
        recovered = hua_2d_slmm_decrypt(cipher)
        np.testing.assert_array_equal(self.test_img_gray, recovered)

    def test_hua_2d_roundtrip_rgb(self):
        cipher = hua_2d_slmm_encrypt(self.test_img_rgb)
        self.assertFalse(np.array_equal(self.test_img_rgb, cipher))
        recovered = hua_2d_slmm_decrypt(cipher)
        np.testing.assert_array_equal(self.test_img_rgb, recovered)

    def test_msb_selective_roundtrip(self):
        cipher = msb_selective_encrypt(self.test_img_rgb, self.aes_key)
        self.assertFalse(np.array_equal(self.test_img_rgb, cipher))
        recovered = msb_selective_decrypt(cipher, self.aes_key)
        np.testing.assert_array_equal(self.test_img_rgb, recovered)

    def test_msb_selective_preserves_lsb(self):
        cipher = msb_selective_encrypt(self.test_img_rgb, self.aes_key)
        # Check that the 4 LSBs are identical
        np.testing.assert_array_equal(self.test_img_rgb & 0x0F, cipher & 0x0F)
        # Check that MSBs are modified
        self.assertFalse(np.array_equal(self.test_img_rgb & 0xF0, cipher & 0xF0))

if __name__ == "__main__":
    unittest.main()

