import unittest
import numpy as np

from encryption import encrypt_blocks
from decryption import decrypt_blocks
from key_manager import generate_session_key
from config import BLOCK_SIZE

class TestDecryption(unittest.TestCase):
    def test_decrypt_blocks_success(self):
        key = generate_session_key()
        block_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
        blocks = [np.random.randint(0, 256, block_shape, dtype=np.uint8) for _ in range(3)]
        
        encrypted_blocks = encrypt_blocks(blocks, key)
        decrypted_blocks, failed = decrypt_blocks(encrypted_blocks, key, block_shape)
        
        self.assertEqual(failed, 0)
        self.assertEqual(len(decrypted_blocks), 3)
        
        for orig, dec in zip(blocks, decrypted_blocks):
            np.testing.assert_array_equal(orig, dec)

    def test_decrypt_blocks_wrong_key(self):
        key1 = generate_session_key()
        key2 = generate_session_key()
        
        block_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
        blocks = [np.random.randint(0, 256, block_shape, dtype=np.uint8)]
        
        encrypted_blocks = encrypt_blocks(blocks, key1)
        decrypted_blocks, failed = decrypt_blocks(encrypted_blocks, key2, block_shape)
        
        self.assertEqual(failed, 1)
        self.assertEqual(len(decrypted_blocks), 1)
        # Check if it was replaced with black block
        np.testing.assert_array_equal(decrypted_blocks[0], np.zeros(block_shape, dtype=np.uint8))

if __name__ == '__main__':
    unittest.main()
