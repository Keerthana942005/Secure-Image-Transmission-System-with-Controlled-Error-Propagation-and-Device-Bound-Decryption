import unittest
import numpy as np

from image_processor import split_into_blocks, merge_blocks
from config import BLOCK_SIZE

class TestBlocks(unittest.TestCase):
    def test_split_and_merge(self):
        # Image shape should be a multiple of BLOCK_SIZE after padding
        padded_shape = (BLOCK_SIZE * 3, BLOCK_SIZE * 4, 3)
        padded_img = np.random.randint(0, 256, padded_shape, dtype=np.uint8)
        
        blocks = split_into_blocks(padded_img)
        
        expected_num_blocks = (padded_shape[0] // BLOCK_SIZE) * (padded_shape[1] // BLOCK_SIZE)
        self.assertEqual(len(blocks), expected_num_blocks)
        
        merged_img = merge_blocks(blocks, padded_shape)
        np.testing.assert_array_equal(padded_img, merged_img)

if __name__ == '__main__':
    unittest.main()
