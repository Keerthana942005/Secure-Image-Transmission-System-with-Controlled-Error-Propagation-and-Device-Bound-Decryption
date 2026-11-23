import unittest
from key_manager import (
    generate_session_key,
    generate_hkdf_nonce,
    derive_key,
    verify_device,
    revoke_device,
    unrevoke_device,
    is_device_revoked
)
from show_device_id import get_device_id

class TestSessionRevocation(unittest.TestCase):
    def test_epoch_key_ratcheting(self):
        sess_key = generate_session_key()
        nonce = generate_hkdf_nonce()
        dev_id = get_device_id()
        
        k_epoch0 = derive_key(sess_key, nonce, dev_id, epoch=0)
        k_epoch1 = derive_key(sess_key, nonce, dev_id, epoch=1)
        
        # Keys from different epochs must be distinct
        self.assertNotEqual(k_epoch0, k_epoch1)
        self.assertEqual(len(k_epoch0), 32)
        self.assertEqual(len(k_epoch1), 32)

    def test_device_revocation(self):
        dev_id = get_device_id()
        
        # Before revocation
        self.assertFalse(is_device_revoked(dev_id))
        self.assertTrue(verify_device(dev_id))
        
        # Revoke device
        revoke_device(dev_id)
        self.assertTrue(is_device_revoked(dev_id))
        self.assertFalse(verify_device(dev_id))
        
        # Unrevoke device
        unrevoke_device(dev_id)
        self.assertFalse(is_device_revoked(dev_id))
        self.assertTrue(verify_device(dev_id))

if __name__ == "__main__":
    unittest.main()

