import unittest
import numpy as np
from src.image_crypto_metrics import (
    calculate_entropy,
    calculate_npcr,
    calculate_uaci,
    calculate_correlation,
    calculate_psnr,
    calculate_ssim,
    calculate_chi_square
)

class TestMetricsExact(unittest.TestCase):
    def test_uniform_entropy_and_chi_square(self):
        # A perfectly balanced distribution of 256 byte values repeated 500 times
        data = np.repeat(np.arange(256, dtype=np.uint8), 500)
        h = calculate_entropy(data)
        self.assertAlmostEqual(h['overall'], 8.0, places=4)
        
        chi = calculate_chi_square(data)
        self.assertAlmostEqual(chi, 0.0, places=4)

    def test_npcr_uaci_identical_and_opposite(self):
        a = np.zeros((32, 32, 3), dtype=np.uint8)
        self.assertEqual(calculate_npcr(a, a), 0.0)
        self.assertEqual(calculate_uaci(a, a), 0.0)
        
        b = np.full((32, 32, 3), 255, dtype=np.uint8)
        self.assertEqual(calculate_npcr(a, b), 100.0)
        self.assertAlmostEqual(calculate_uaci(a, b), 100.0, places=4)

    def test_correlation_fixed_seed_determinism(self):
        img = np.random.RandomState(42).randint(0, 256, (64, 64, 3), dtype=np.uint8)
        corr1 = calculate_correlation(img, seed=42)
        corr2 = calculate_correlation(img, seed=42)
        self.assertEqual(corr1, corr2)

    def test_psnr_and_ssim_identity(self):
        img = np.random.randint(0, 256, (64, 64, 3), dtype=np.uint8)
        self.assertEqual(calculate_psnr(img, img), float("inf"))
        self.assertAlmostEqual(calculate_ssim(img, img), 1.0, places=4)

if __name__ == "__main__":
    unittest.main()

