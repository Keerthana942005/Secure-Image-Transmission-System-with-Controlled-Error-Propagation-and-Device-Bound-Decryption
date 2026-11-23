import unittest
import numpy as np
from error_concealment import conceal_failed_blocks

class TestErrorConcealment(unittest.TestCase):
    def test_single_block_concealment(self):
        # 3x3 grid of 16x16x3 blocks
        bh, bw, c = 16, 16, 3
        grid_shape = (3, 3)
        block_shape = (bh, bw, c)
        
        # Fill blocks with known gradient
        blocks = [np.full(block_shape, i * 20, dtype=np.uint8) for i in range(9)]
        
        # Corrupt center block (index 4)
        corrupted_blocks = [b.copy() for b in blocks]
        corrupted_blocks[4] = np.zeros(block_shape, dtype=np.uint8)
        
        # Conceal
        reconstructed = conceal_failed_blocks(corrupted_blocks, [4], grid_shape, block_shape)
        
        # Check that center block is restored to non-zero values close to neighbors
        self.assertGreater(np.mean(reconstructed[4]), 0)
        self.assertLess(np.mean(reconstructed[4]), 255)
        # Check that uncorrupted blocks were untouched
        for idx in [0, 1, 2, 3, 5, 6, 7, 8]:
            np.testing.assert_array_equal(reconstructed[idx], blocks[idx])

if __name__ == "__main__":
    unittest.main()

