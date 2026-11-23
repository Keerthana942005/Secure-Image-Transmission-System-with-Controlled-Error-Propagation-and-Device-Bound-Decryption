import unittest
import numpy as np

from encryption import encrypt_blocks
from decryption import decrypt_blocks
from error_simulator import corrupt_blocks
from key_manager import generate_session_key
from config import BLOCK_SIZE

class TestErrorSimulation(unittest.TestCase):
    def test_corrupt_blocks(self):
        key = generate_session_key()
        block_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
        blocks = [np.random.randint(0, 256, block_shape, dtype=np.uint8) for _ in range(5)]
        
        encrypted_blocks = encrypt_blocks(blocks, key)
        
        # Corrupt 2 blocks
        corrupted = corrupt_blocks(encrypted_blocks, 2)
        
        # Check that exactly 2 blocks differ
        diff_count = sum(1 for e, c in zip(encrypted_blocks, corrupted) if e != c)
        self.assertEqual(diff_count, 2)
        
        # Try decrypting corrupted blocks
        decrypted_blocks, failed = decrypt_blocks(corrupted, key, block_shape)
        self.assertEqual(failed, 2)

if __name__ == '__main__':
    unittest.main()
