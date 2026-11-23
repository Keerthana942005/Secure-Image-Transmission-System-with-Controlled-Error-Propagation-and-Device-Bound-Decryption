import os
import unittest
import struct
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.record_format import (
    create_session_header,
    parse_session_header_fields,
    verify_session_header_hmac,
    HeaderAuthenticationError,
    SESSION_HEADER_LEN
)
from src.key_manager import (
    generate_receiver_static_keypair,
    get_key_fingerprint,
    derive_session_keys,
    stretch_passphrase,
    verify_and_update_epoch,
    reset_epoch_tracker,
    validate_passphrase
)

class TestKeyTransport(unittest.TestCase):
    def setUp(self):
        reset_epoch_tracker(clean_disk=True)
        self.rx_priv, self.rx_pub = generate_receiver_static_keypair()
        self.rx_pub_bytes = self.rx_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.fingerprint = get_key_fingerprint(self.rx_pub)
        
        # Sender generates ephemeral key
        self.tx_priv, self.tx_pub = generate_receiver_static_keypair()
        self.tx_pub_bytes = self.tx_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        
        self.salt_hkdf = os.urandom(16)
        self.salt_pbkdf2 = os.urandom(16)
        self.passphrase = "UltraSecureKeyPassphrase2026!#"
        self.device_id = "mock_device_id_hash_1234567890abcdef"
        self.epoch = 1
        self.H = 512
        self.W = 512
        self.N = 1024
        
        # Shared secret on sender side
        self.shared_tx = self.tx_priv.exchange(self.rx_pub)
        self.k_aes_tx, self.k_hdr_tx, self.k_session_tx = derive_session_keys(
            self.shared_tx, self.tx_pub_bytes, self.rx_pub_bytes,
            self.salt_hkdf, self.salt_pbkdf2, self.passphrase, self.device_id, self.epoch,
            iterations=1000  # fast iterations for unit tests
        )

    def test_header_round_trip(self):
        header = create_session_header(
            self.epoch, self.H, self.W, self.N,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint,
            self.k_hdr_tx
        )
        self.assertEqual(len(header), SESSION_HEADER_LEN)
        self.assertEqual(len(header), 134)

        # Receiver side
        parsed = parse_session_header_fields(header)
        self.assertEqual(parsed['epoch'], self.epoch)
        self.assertEqual(parsed['height'], self.H)
        self.assertEqual(parsed['width'], self.W)
        self.assertEqual(parsed['total_blocks'], self.N)
        self.assertEqual(parsed['receiver_fingerprint'], self.fingerprint)

        # Receiver derives keys
        eph_pub_obj = x25519.X25519PublicKey.from_public_bytes(parsed['eph_pub'])
        shared_rx = self.rx_priv.exchange(eph_pub_obj)
        k_aes_rx, k_hdr_rx, k_session_rx = derive_session_keys(
            shared_rx, parsed['eph_pub'], self.rx_pub_bytes,
            parsed['salt_hkdf'], parsed['salt_pbkdf2'], self.passphrase, self.device_id, parsed['epoch'],
            iterations=1000
        )
        self.assertEqual(self.k_hdr_tx, k_hdr_rx)
        self.assertEqual(self.k_aes_tx, k_aes_rx)

        # Verify HMAC
        is_valid = verify_session_header_hmac(parsed['header_body'], parsed['hmac_tag'], k_hdr_rx)
        self.assertTrue(is_valid)

    def test_single_bit_flip_rejected(self):
        header = bytearray(create_session_header(
            self.epoch, self.H, self.W, self.N,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint,
            self.k_hdr_tx
        ))
        
        # Test flips across diverse byte positions (magic, epoch, dimensions, salts, pubkey, HMAC)
        test_positions = [0, 4, 10, 20, 40, 70, 95, 110, 130]
        for pos in test_positions:
            corrupted = bytearray(header)
            corrupted[pos] ^= 0x01
            
            # If magic or version flipped, parse fails; otherwise HMAC verification fails
            try:
                parsed = parse_session_header_fields(bytes(corrupted))
                with self.assertRaises(HeaderAuthenticationError):
                    verify_session_header_hmac(parsed['header_body'], parsed['hmac_tag'], self.k_hdr_tx)
            except HeaderAuthenticationError:
                pass  # Successfully rejected before processing

    def test_wrong_static_key_fails(self):
        wrong_priv, _ = generate_receiver_static_keypair()
        header = create_session_header(
            self.epoch, self.H, self.W, self.N,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint,
            self.k_hdr_tx
        )
        parsed = parse_session_header_fields(header)
        eph_pub_obj = x25519.X25519PublicKey.from_public_bytes(parsed['eph_pub'])
        
        # Wrong private key produces different shared secret and different K_hdr
        wrong_shared = wrong_priv.exchange(eph_pub_obj)
        _, wrong_k_hdr, _ = derive_session_keys(
            wrong_shared, parsed['eph_pub'], self.rx_pub_bytes,
            parsed['salt_hkdf'], parsed['salt_pbkdf2'], self.passphrase, self.device_id, parsed['epoch'],
            iterations=1000
        )
        with self.assertRaises(HeaderAuthenticationError):
            verify_session_header_hmac(parsed['header_body'], parsed['hmac_tag'], wrong_k_hdr)

    def test_substituted_ephemeral_key_fails(self):
        header = create_session_header(
            self.epoch, self.H, self.W, self.N,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint,
            self.k_hdr_tx
        )
        # Substitute another ephemeral public key in the header
        _, other_pub = generate_receiver_static_keypair()
        other_pub_bytes = other_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        
        # Replace bytes 54:86 with other_pub_bytes
        corrupted = bytearray(header)
        corrupted[54:86] = other_pub_bytes
        parsed = parse_session_header_fields(bytes(corrupted))
        
        eph_pub_obj = x25519.X25519PublicKey.from_public_bytes(parsed['eph_pub'])
        shared_rx = self.rx_priv.exchange(eph_pub_obj)
        _, k_hdr_rx, _ = derive_session_keys(
            shared_rx, parsed['eph_pub'], self.rx_pub_bytes,
            parsed['salt_hkdf'], parsed['salt_pbkdf2'], self.passphrase, self.device_id, parsed['epoch'],
            iterations=1000
        )
        with self.assertRaises(HeaderAuthenticationError):
            verify_session_header_hmac(parsed['header_body'], parsed['hmac_tag'], k_hdr_rx)

    def test_wrong_passphrase_fails(self):
        header = create_session_header(
            self.epoch, self.H, self.W, self.N,
            self.salt_hkdf, self.salt_pbkdf2,
            self.tx_pub_bytes, self.fingerprint,
            self.k_hdr_tx
        )
        parsed = parse_session_header_fields(header)
        eph_pub_obj = x25519.X25519PublicKey.from_public_bytes(parsed['eph_pub'])
        shared_rx = self.rx_priv.exchange(eph_pub_obj)
        
        # Wrong passphrase alters IKM and K_hdr
        _, wrong_k_hdr, _ = derive_session_keys(
            shared_rx, parsed['eph_pub'], self.rx_pub_bytes,
            parsed['salt_hkdf'], parsed['salt_pbkdf2'], "WrongPassword123456!", self.device_id, parsed['epoch'],
            iterations=1000
        )
        with self.assertRaises(HeaderAuthenticationError):
            verify_session_header_hmac(parsed['header_body'], parsed['hmac_tag'], wrong_k_hdr)

    def test_wrong_device_id_alters_k_aes(self):
        shared_rx = self.rx_priv.exchange(self.tx_pub)
        k_aes_1, _, _ = derive_session_keys(
            shared_rx, self.tx_pub_bytes, self.rx_pub_bytes,
            self.salt_hkdf, self.salt_pbkdf2, self.passphrase, "legitimate_device_id", self.epoch,
            iterations=1000
        )
        k_aes_2, _, _ = derive_session_keys(
            shared_rx, self.tx_pub_bytes, self.rx_pub_bytes,
            self.salt_hkdf, self.salt_pbkdf2, self.passphrase, "spoofed_device_id", self.epoch,
            iterations=1000
        )
        self.assertNotEqual(k_aes_1, k_aes_2)

    def test_epoch_replay_rejection(self):
        sender = "sender_endpoint_alpha"
        self.assertTrue(verify_and_update_epoch(sender, 1))
        self.assertTrue(verify_and_update_epoch(sender, 2))
        self.assertFalse(verify_and_update_epoch(sender, 2))  # Equal rejected
        self.assertFalse(verify_and_update_epoch(sender, 1))  # Stale rejected
        self.assertTrue(verify_and_update_epoch(sender, 5))   # Higher accepted

    def test_epoch_persistence_across_restart(self):
        sender = "persistent_sender_node"
        self.assertTrue(verify_and_update_epoch(sender, 10, persist=True))
        
        # Simulate process restart by resetting in-memory dictionary
        reset_epoch_tracker(clean_disk=False)
        
        # Old or equal epoch must still be rejected by disk-backed store
        self.assertFalse(verify_and_update_epoch(sender, 10, persist=True))
        self.assertFalse(verify_and_update_epoch(sender, 8, persist=True))
        self.assertTrue(verify_and_update_epoch(sender, 11, persist=True))

    def test_rfc7748_curve25519_test_vector(self):
        """Official RFC 7748 Section 6.1 test vector."""
        alice_priv_bytes = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        bob_priv_bytes = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
        bob_pub_expected = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
        shared_expected = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')

        alice_priv = x25519.X25519PrivateKey.from_private_bytes(alice_priv_bytes)
        bob_priv = x25519.X25519PrivateKey.from_private_bytes(bob_priv_bytes)

        self.assertEqual(bob_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw), bob_pub_expected)
        ss_alice = alice_priv.exchange(bob_priv.public_key())
        self.assertEqual(ss_alice, shared_expected)

    def test_pbkdf2_known_answer(self):
        """Standard PBKDF2-HMAC-SHA256 test vectors."""
        res = hashlib.pbkdf2_hmac('sha256', b'password', b'salt', 4096, 32)
        expected = bytes.fromhex('c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a')
        self.assertEqual(res, expected)

if __name__ == '__main__':
    unittest.main()

