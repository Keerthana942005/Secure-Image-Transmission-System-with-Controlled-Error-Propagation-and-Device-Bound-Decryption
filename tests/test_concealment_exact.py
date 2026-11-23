import unittest
import numpy as np
from src.error_concealment import conceal_failed_blocks, mean_color_fill

class TestConcealmentExact(unittest.TestCase):
    def test_hand_calculated_2x2_block(self):
        """Unit test for Eq. (10)/(11) weights on an exact hand-computed 2x2-block example."""
        bh, bw, c = 2, 2, 1
        grid = (3, 3)
        block_shape = (bh, bw, c)
        
        # 3x3 grid of 2x2 blocks:
        # Index 4 is center (failed)
        blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(9)]
        
        # Block 1 (Top): bottom edge has pixels [10, 20]
        blocks[1] = np.zeros(block_shape, dtype=np.uint8)
        blocks[1][1, 0, 0] = 10
        blocks[1][1, 1, 0] = 20
        
        # Block 7 (Bottom): top edge has pixels [30, 40]
        blocks[7] = np.zeros(block_shape, dtype=np.uint8)
        blocks[7][0, 0, 0] = 30
        blocks[7][0, 1, 0] = 40
        
        # Block 3 (Left): right edge has pixels [50, 60]
        blocks[3] = np.zeros(block_shape, dtype=np.uint8)
        blocks[3][0, 1, 0] = 50
        blocks[3][1, 1, 0] = 60
        
        # Block 5 (Right): left edge has pixels [70, 80]
        blocks[5] = np.zeros(block_shape, dtype=np.uint8)
        blocks[5][0, 0, 0] = 70
        blocks[5][1, 0, 0] = 80
        
        concealed = conceal_failed_blocks(blocks, [4], grid, block_shape)
        c_block = concealed[4]
        
        # Hand-calculated expected values:
        # (0, 0) = (1.0*10 + 0.5*30 + 1.0*50 + 0.5*70) / (1.0+0.5+1.0+0.5) = 110 / 3 = 36.67 -> 37
        # (0, 1) = (1.0*20 + 0.5*40 + 0.5*50 + 1.0*70) / (1.0+0.5+0.5+1.0) = 135 / 3 = 45.0 -> 45
        # (1, 0) = (0.5*10 + 1.0*30 + 1.0*60 + 0.5*80) / (0.5+1.0+1.0+0.5) = 135 / 3 = 45.0 -> 45
        # (1, 1) = (0.5*20 + 1.0*40 + 0.5*60 + 1.0*80) / (0.5+1.0+0.5+1.0) = 160 / 3 = 53.33 -> 53
        self.assertEqual(c_block[0, 0, 0], 37)
        self.assertEqual(c_block[0, 1, 0], 45)
        self.assertEqual(c_block[1, 0, 0], 45)
        self.assertEqual(c_block[1, 1, 0], 53)

    def test_8_neighbor_fallback(self):
        """Unit test for 8-neighbor fallback when all 4 orthogonal neighbors are missing."""
        bh, bw, c = 16, 16, 1
        grid = (3, 3)
        block_shape = (bh, bw, c)
        
        # All orthogonal neighbors (1, 3, 5, 7) and center (4) are failed
        failed_indices = [1, 3, 4, 5, 7]
        blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(9)]
        
        # Diagonals: 0, 2, 6, 8
        blocks[0] = np.full(block_shape, 20, dtype=np.uint8)
        blocks[2] = np.full(block_shape, 40, dtype=np.uint8)
        blocks[6] = np.full(block_shape, 60, dtype=np.uint8)
        blocks[8] = np.full(block_shape, 80, dtype=np.uint8)
        
        concealed = conceal_failed_blocks(blocks, failed_indices, grid, block_shape)
        c_block = concealed[4]
        
        # Mean of diagonals: (20 + 40 + 60 + 80) / 4 = 50
        np.testing.assert_array_equal(c_block, np.full(block_shape, 50, dtype=np.uint8))

    def test_all_four_orthogonal_neighbors_symmetric(self):
        bh, bw, c = 16, 16, 1
        grid = (3, 3)
        block_shape = (bh, bw, c)
        
        blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(9)]
        blocks[1] = np.full(block_shape, 100, dtype=np.uint8)
        blocks[7] = np.full(block_shape, 200, dtype=np.uint8)
        blocks[3] = np.full(block_shape, 50, dtype=np.uint8)
        blocks[5] = np.full(block_shape, 150, dtype=np.uint8)
        
        concealed = conceal_failed_blocks(blocks, [4], grid, block_shape)
        c_block = concealed[4]
        
        # Exact center average should be (100 + 200 + 50 + 150) / 4 = 125
        center_val = np.mean(c_block[7:9, 7:9, :])
        self.assertAlmostEqual(center_val, 125.0, delta=2.0)

    def test_mean_fill_fallback(self):
        bh, bw, c = 16, 16, 3
        grid = (2, 2)
        block_shape = (bh, bw, c)
        blocks = [
            np.full(block_shape, 50, dtype=np.uint8),
            np.full(block_shape, 100, dtype=np.uint8),
            np.full(block_shape, 150, dtype=np.uint8),
            np.zeros(block_shape, dtype=np.uint8)
        ]
        filled = mean_color_fill(blocks, [3], grid, block_shape)
        np.testing.assert_array_equal(filled[3], np.full(block_shape, 125, dtype=np.uint8))

    def test_2_neighbor_corner_case(self):
        """Corner block (0,0) in 2x2 grid: only right (0,1) and bottom (1,0) neighbors exist."""
        bh, bw, c = 4, 4, 1
        grid = (2, 2)
        block_shape = (bh, bw, c)
        blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(4)]
        # Block 1 (Right): left edge has pixel value 100
        blocks[1] = np.full(block_shape, 100, dtype=np.uint8)
        # Block 2 (Bottom): top edge has pixel value 200
        blocks[2] = np.full(block_shape, 200, dtype=np.uint8)
        
        # Conceal block 0
        concealed = conceal_failed_blocks(blocks, [0], grid, block_shape)
        c0 = concealed[0]
        self.assertEqual(c0.shape, block_shape)
        # Corner interpolation should produce values strictly bounded between 100 and 200
        self.assertTrue(np.all(c0 >= 100))
        self.assertTrue(np.all(c0 <= 200))
        # Top-left pixel (0,0): closest to boundary weights
        self.assertGreater(c0[3, 0, 0], c0[0, 3, 0])

    def test_3_neighbor_edge_case(self):
        """Edge block (0,1) in 3x3 grid: top is boundary, only left, right, and bottom exist."""
        bh, bw, c = 4, 4, 1
        grid = (3, 3)
        block_shape = (bh, bw, c)
        blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(9)]
        # Left neighbor (block 0)
        blocks[0] = np.full(block_shape, 60, dtype=np.uint8)
        # Right neighbor (block 2)
        blocks[2] = np.full(block_shape, 120, dtype=np.uint8)
        # Bottom neighbor (block 4)
        blocks[4] = np.full(block_shape, 180, dtype=np.uint8)
        
        concealed = conceal_failed_blocks(blocks, [1], grid, block_shape)
        c1 = concealed[1]
        self.assertEqual(c1.shape, block_shape)
        self.assertTrue(np.all(c1 >= 60))
        self.assertTrue(np.all(c1 <= 180))

    def test_0_neighbor_diagonal_or_empty_fallback(self):
        """Isolated failed block where all 4 orthogonal neighbors are unverified."""
        bh, bw, c = 4, 4, 1
        grid = (3, 3)
        block_shape = (bh, bw, c)
        blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(9)]
        # Center is block 4, orthogonal neighbors 1, 3, 5, 7 are also failed
        failed_indices = [1, 3, 4, 5, 7]
        # Diagonal neighbors: 0, 2, 6, 8
        blocks[0] = np.full(block_shape, 40, dtype=np.uint8)
        blocks[2] = np.full(block_shape, 60, dtype=np.uint8)
        blocks[6] = np.full(block_shape, 80, dtype=np.uint8)
        blocks[8] = np.full(block_shape, 100, dtype=np.uint8)
        
        concealed = conceal_failed_blocks(blocks, failed_indices, grid, block_shape)
        # Expected diagonal mean = (40 + 60 + 80 + 100) / 4 = 70
        np.testing.assert_array_equal(concealed[4], np.full(block_shape, 70, dtype=np.uint8))

if __name__ == "__main__":
    unittest.main()
