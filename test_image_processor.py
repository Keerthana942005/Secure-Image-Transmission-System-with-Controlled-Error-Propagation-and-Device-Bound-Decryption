import unittest
import numpy as np
from PIL import Image
import os

from image_processor import pad_image, unpad_image, split_into_blocks, merge_blocks
from config import BLOCK_SIZE

class TestImageProcessor(unittest.TestCase):
    def setUp(self):
        # Create a dummy image array (35x35 RGB)
        self.original_shape = (35, 35, 3)
        self.img_arr = np.random.randint(0, 256, self.original_shape, dtype=np.uint8)

    def test_pad_and_unpad(self):
        padded_img, shape = pad_image(self.img_arr)
        
        # Check if padded dimensions are multiples of BLOCK_SIZE
        self.assertEqual(padded_img.shape[0] % BLOCK_SIZE, 0)
        self.assertEqual(padded_img.shape[1] % BLOCK_SIZE, 0)
        
        # Check unpadding
        unpadded_img = unpad_image(padded_img, shape)
        self.assertEqual(unpadded_img.shape, self.original_shape)
        np.testing.assert_array_equal(self.img_arr, unpadded_img)

if __name__ == '__main__':
    unittest.main()
