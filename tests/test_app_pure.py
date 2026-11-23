import unittest
import numpy as np
from src.config import BLOCK_SIZE, DEFAULT_TAU, MIN_PASSPHRASE_LENGTH
from src.key_manager import (
    validate_passphrase,
    get_device_id,
    generate_session_key,
    generate_salt,
    derive_key
)
from src.image_processor import pad_image, unpad_image, split_into_blocks, merge_blocks
from src.error_simulator import corrupt_blocks, drop_blocks, swap_blocks
from src.decryption import (
    ACTION_CONCEALED,
    ACTION_REJECTED_OVER_THRESHOLD,
    ACTION_DUPLICATE_IGNORED,
    ACTION_DETECTED_AND_QUARANTINED
)

class TestAppPureFunctions(unittest.TestCase):
    def test_passphrase_policy(self):
        """Passphrase policy must enforce length >= 16 and character diversity."""
        # Short passphrase
        valid, msg = validate_passphrase("Short1!")
        self.assertFalse(valid)
        self.assertIn("16", msg)
        
        # Only 1 class (only lowercase)
        valid, msg = validate_passphrase("alllowercasepassphraseonly")
        self.assertFalse(valid)
        self.assertIn("3 character classes", msg)
        
        # Only 2 classes (uppercase and lowercase only, no digits, no symbols)
        valid, msg = validate_passphrase("AllCharactersNoNumbersNoSymbolsHere")
        self.assertFalse(valid)
        self.assertIn("3 character classes", msg)
        
        # Valid strong passphrase (>= 16 chars with 3 or more classes)
        valid, msg = validate_passphrase("AlphaSecureKey2026!Protected")
        self.assertTrue(valid)

    def test_image_split_merge_identity(self):
        """Pure image partitioning and unpadding must preserve exact byte identity."""
        rng = np.random.RandomState(42)
        arr = rng.randint(0, 256, (73, 89, 3), dtype=np.uint8)
        padded, orig_shape = pad_image(arr, BLOCK_SIZE)
        blocks = split_into_blocks(padded, BLOCK_SIZE)
        merged = merge_blocks(blocks, padded.shape, block_size=BLOCK_SIZE)
        recovered = unpad_image(merged, orig_shape)
        np.testing.assert_array_equal(arr, recovered)

    def test_error_simulators(self):
        """Test pure M1, M2, and M3 simulators."""
        dummy_records = [b"\x00" * 800 for _ in range(10)]
        
        # M1: In-place corruption
        corrupted = corrupt_blocks(dummy_records, 3, seed=42)
        self.assertEqual(len(corrupted), 10)
        diff_count = sum(1 for orig, c in zip(dummy_records, corrupted) if orig != c)
        self.assertEqual(diff_count, 3)
            
        # M3: Dropped records
        dropped = drop_blocks(dummy_records, 2, seed=42)
        self.assertEqual(len(dropped), 8)
        
        # Swap blocks
        swapped = swap_blocks(dummy_records, pair_indices=(0, 1))
        self.assertEqual(len(swapped), 10)

if __name__ == "__main__":
    unittest.main()

