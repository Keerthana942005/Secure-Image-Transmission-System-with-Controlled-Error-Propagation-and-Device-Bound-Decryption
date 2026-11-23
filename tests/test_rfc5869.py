import unittest
import binascii
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class TestRFC5869HKDF(unittest.TestCase):
    """Verifies HKDF implementation directly against official RFC 5869 test vectors."""

    def test_case_1(self):
        # RFC 5869 Test Case 1 (SHA-256)
        ikm = binascii.unhexlify("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt = binascii.unhexlify("000102030405060708090a0b0c")
        info = binascii.unhexlify("f0f1f2f3f4f5f6f7f8f9")
        l = 42
        expected_okm = binascii.unhexlify(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
        hkdf = HKDF(algorithm=hashes.SHA256(), length=l, salt=salt, info=info, backend=default_backend())
        okm = hkdf.derive(ikm)
        self.assertEqual(okm, expected_okm)

    def test_case_2(self):
        # RFC 5869 Test Case 2 (SHA-256)
        ikm = binascii.unhexlify("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
        salt = binascii.unhexlify("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        info = binascii.unhexlify("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
        l = 82
        expected_okm = binascii.unhexlify(
            "d1de0fbf70ca52cbaf574da981f39e25c8a63c520dcd058d7fed2637782fb9adf6044d9c324fa55cf09b69ac2b5d339d9738247b4f8c54b184551dbbe2429b960fa2e82686ced41e01906dac37ef28f695ed"
        )
        hkdf = HKDF(algorithm=hashes.SHA256(), length=l, salt=salt, info=info, backend=default_backend())
        okm = hkdf.derive(ikm)
        self.assertEqual(okm, expected_okm)

if __name__ == "__main__":
    unittest.main()
