import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.key_manager import (
    sign_drl,
    verify_and_load_drl,
    is_fingerprint_revoked,
    reset_drl_tracker,
    DRLSignatureError,
    DRLRollbackError
)

class TestDeviceRevocationList(unittest.TestCase):
    def setUp(self):
        reset_drl_tracker()
        self.drl_priv = ed25519.Ed25519PrivateKey.generate()
        self.drl_pub = self.drl_priv.public_key()
        self.fingerprint_1 = "4a5d9d5ba4ce2de1728e3bf480350f25"
        self.fingerprint_2 = "8520f0098930a754748b7ddcb43ef75a"

    def test_valid_drl_verification(self):
        drl = sign_drl(self.drl_priv, version=1, entries=[self.fingerprint_1])
        verified = verify_and_load_drl(drl, self.drl_pub)
        self.assertEqual(verified["version"], 1)
        self.assertTrue(is_fingerprint_revoked(self.fingerprint_1))
        self.assertFalse(is_fingerprint_revoked(self.fingerprint_2))

    def test_tampered_drl_entry_rejected(self):
        drl = sign_drl(self.drl_priv, version=1, entries=[self.fingerprint_1])
        # Tamper with entry
        drl["entries"].append(self.fingerprint_2)
        with self.assertRaises(DRLSignatureError):
            verify_and_load_drl(drl, self.drl_pub)

    def test_tampered_drl_version_rejected(self):
        drl = sign_drl(self.drl_priv, version=1, entries=[self.fingerprint_1])
        drl["version"] = 2  # Tampered version
        with self.assertRaises(DRLSignatureError):
            verify_and_load_drl(drl, self.drl_pub)

    def test_tampered_signature_rejected(self):
        drl = sign_drl(self.drl_priv, version=1, entries=[self.fingerprint_1])
        sig_bytes = bytearray.fromhex(drl["signature"])
        sig_bytes[0] ^= 0xFF
        drl["signature"] = sig_bytes.hex()
        with self.assertRaises(DRLSignatureError):
            verify_and_load_drl(drl, self.drl_pub)

    def test_drl_rollback_protection(self):
        drl_v2 = sign_drl(self.drl_priv, version=2, entries=[self.fingerprint_1])
        verify_and_load_drl(drl_v2, self.drl_pub)

        # Attempt to replay an older version 1
        drl_v1 = sign_drl(self.drl_priv, version=1, entries=[])
        with self.assertRaises(DRLRollbackError):
            verify_and_load_drl(drl_v1, self.drl_pub)

    def test_multi_entry_revocation(self):
        drl = sign_drl(self.drl_priv, version=3, entries=[self.fingerprint_1, self.fingerprint_2])
        verify_and_load_drl(drl, self.drl_pub)
        self.assertTrue(is_fingerprint_revoked(self.fingerprint_1))
        self.assertTrue(is_fingerprint_revoked(self.fingerprint_2))

if __name__ == '__main__':
    unittest.main()

