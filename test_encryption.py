import unittest
import numpy as np

from encryption import encrypt_blocks
from key_manager import generate_session_key
from config import BLOCK_SIZE

class TestEncryption(unittest.TestCase):
    def test_encrypt_blocks(self):
        key = generate_session_key()
        
        # Create dummy blocks
        block_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
        blocks = [np.random.randint(0, 256, block_shape, dtype=np.uint8) for _ in range(5)]
        
        encrypted_blocks = encrypt_blocks(blocks, key)
        
        self.assertEqual(len(encrypted_blocks), 5)
        # Each encrypted block should have 12 bytes nonce + 16 bytes auth tag + payload
        expected_len = 12 + 16 + (BLOCK_SIZE * BLOCK_SIZE * 3)
        for eb in encrypted_blocks:
            self.assertEqual(len(eb), expected_len)

if __name__ == '__main__':
    unittest.main()
