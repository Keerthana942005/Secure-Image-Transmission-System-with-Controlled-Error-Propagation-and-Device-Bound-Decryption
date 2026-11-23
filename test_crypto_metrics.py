import unittest
import numpy as np
from image_crypto_metrics import (
    calculate_entropy,
    calculate_npcr,
    calculate_uaci,
    calculate_correlation,
    calculate_psnr,
    calculate_ssim
)

class TestCryptoMetrics(unittest.TestCase):
    def test_entropy_uniform_distribution(self):
        # A completely uniform array of all byte values 0..255 should have entropy ~8.0
        data = np.repeat(np.arange(256, dtype=np.uint8), 100)
        entropy = calculate_entropy(data)
        self.assertAlmostEqual(entropy, 8.0, places=3)

    def test_npcr_identical_images(self):
        img1 = np.ones((64, 64, 3), dtype=np.uint8) * 128
        img2 = img1.copy()
        self.assertEqual(calculate_npcr(img1, img2), 0.0)

    def test_npcr_different_images(self):
        img1 = np.zeros((32, 32), dtype=np.uint8)
        img2 = np.ones((32, 32), dtype=np.uint8)
        self.assertEqual(calculate_npcr(img1, img2), 100.0)

    def test_uaci_bounds(self):
        img1 = np.zeros((32, 32), dtype=np.uint8)
        img2 = np.ones((32, 32), dtype=np.uint8) * 255
        self.assertAlmostEqual(calculate_uaci(img1, img2), 100.0, places=2)

    def test_psnr_identical(self):
        img = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        self.assertEqual(calculate_psnr(img, img), float("inf"))

    def test_ssim_identical(self):
        img = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        self.assertAlmostEqual(calculate_ssim(img, img), 1.0, places=3)

if __name__ == "__main__":
    unittest.main()

