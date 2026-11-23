import unittest

from key_manager import generate_session_key, generate_hkdf_nonce, derive_key

class TestKeyManager(unittest.TestCase):
    def test_key_generation(self):
        session_key = generate_session_key()
        self.assertEqual(len(session_key), 32)
        
        nonce = generate_hkdf_nonce()
        self.assertEqual(len(nonce), 16)
        
    def test_key_derivation(self):
        session_key = generate_session_key()
        nonce = generate_hkdf_nonce()
        device_id = "test_device_id_123"
        
        key1 = derive_key(session_key, nonce, device_id)
        key2 = derive_key(session_key, nonce, device_id)
        
        # Keys should be identical with the same inputs
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 32)
        
        # Keys should differ with different device ID
        key3 = derive_key(session_key, nonce, "different_device_id")
        self.assertNotEqual(key1, key3)

if __name__ == '__main__':
    unittest.main()
