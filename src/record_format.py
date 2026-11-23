import struct
import hmac
import hashlib
from src.config import (
    SESSION_HEADER_LEN,
    SESSION_HEADER_MAGIC,
    SESSION_HEADER_VERSION
)

class HeaderAuthenticationError(Exception):
    """Raised when session header authentication or integrity check fails."""
    pass

def build_aad(index: int, height: int, width: int, total_blocks: int, epoch: int) -> bytes:
    """Builds a 20-byte Additional Authenticated Data (AAD) binding:
    - Block spatial index (4 bytes, uint32)
    - Image height (4 bytes, uint32)
    - Image width (4 bytes, uint32)
    - Total block count (4 bytes, uint32)
    - Session epoch (4 bytes, uint32)
    This prevents block reordering, cross-session splicing, dimension tampering, and truncation.
    """
    return struct.pack(">IIIII", index, height, width, total_blocks, epoch)

def pack_record(index: int, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Packs an authenticated block record:
    Header: index (4 bytes, big-endian)
    Nonce: 12 bytes
    Ciphertext: 768 bytes (for 16x16x3)
    Tag: 16 bytes
    Total record length = 800 bytes.
    """
    header = struct.pack(">I", index)
    return header + nonce + ciphertext + tag

def unpack_record(record: bytes) -> tuple[int, bytes, bytes, bytes]:
    """Unpacks a record into (index, nonce, ciphertext, tag)."""
    if len(record) < 32:  # 4 header + 12 nonce + 16 tag minimum
        raise ValueError(f"Record too short: {len(record)} bytes")
    index = struct.unpack(">I", record[:4])[0]
    nonce = record[4:16]
    ciphertext = record[16:-16]
    tag = record[-16:]
    return index, nonce, ciphertext, tag

# ---------------------------------------------------------------------------
# Session Header Layout (134 Bytes Fixed Format, Big-Endian)
# ---------------------------------------------------------------------------
# magic (4B): b"SIT1"
# version (1B): 0x01
# flags (1B): 0x00
# epoch (4B): uint32
# height (4B): uint32
# width (4B): uint32
# total_blocks (4B): uint32
# S_hkdf (16B): HKDF salt
# S_pbkdf2 (16B): PBKDF2 salt
# eph_pub (32B): Ephemeral X25519 public key
# receiver_key_fingerprint (16B): First 16 bytes of SHA-256(receiver_static_pub)
# ---------------------------------------------------------------------------
# Subtotal before HMAC: 102 bytes
# HMAC-SHA256 (32B): Keyed with K_hdr over all preceding 102 bytes
# Total header length: 134 bytes
# ---------------------------------------------------------------------------

HEADER_BODY_FORMAT = ">4sBBIIII16s16s32s16s"
HEADER_BODY_LEN = struct.calcsize(HEADER_BODY_FORMAT)  # exactly 102 bytes
HEADER_HMAC_LEN = 32

assert HEADER_BODY_LEN == 102, f"Expected 102 bytes body, got {HEADER_BODY_LEN}"
assert HEADER_BODY_LEN + HEADER_HMAC_LEN == SESSION_HEADER_LEN, "Expected 134 bytes total header"

def create_session_header(epoch: int, height: int, width: int, total_blocks: int,
                          salt_hkdf: bytes, salt_pbkdf2: bytes,
                          eph_pub: bytes, receiver_fingerprint: bytes,
                          key_hdr: bytes, flags: int = 0) -> bytes:
    """Creates a 134-byte authenticated session header."""
    if len(salt_hkdf) != 16:
        raise ValueError("salt_hkdf must be exactly 16 bytes")
    if len(salt_pbkdf2) != 16:
        raise ValueError("salt_pbkdf2 must be exactly 16 bytes")
    if len(eph_pub) != 32:
        raise ValueError("eph_pub must be exactly 32 bytes")
    if len(receiver_fingerprint) != 16:
        raise ValueError("receiver_fingerprint must be exactly 16 bytes")
    if len(key_hdr) != 32:
        raise ValueError("key_hdr must be exactly 32 bytes")

    body = struct.pack(
        HEADER_BODY_FORMAT,
        SESSION_HEADER_MAGIC,
        SESSION_HEADER_VERSION,
        flags,
        epoch,
        height,
        width,
        total_blocks,
        salt_hkdf,
        salt_pbkdf2,
        eph_pub,
        receiver_fingerprint
    )
    hmac_tag = hmac.new(key_hdr, body, hashlib.sha256).digest()
    return body + hmac_tag

def parse_session_header_fields(header_bytes: bytes) -> dict:
    """Parses unauthenticated fields from the 134-byte session header.
    Note: Fields must NOT be trusted until verify_session_header_hmac succeeds!
    """
    if len(header_bytes) != SESSION_HEADER_LEN:
        raise HeaderAuthenticationError(
            f"Invalid session header length: expected {SESSION_HEADER_LEN} bytes, got {len(header_bytes)}"
        )
    body = header_bytes[:HEADER_BODY_LEN]
    hmac_tag = header_bytes[HEADER_BODY_LEN:]

    (magic, version, flags, epoch, height, width, total_blocks,
     salt_hkdf, salt_pbkdf2, eph_pub, receiver_fingerprint) = struct.unpack(HEADER_BODY_FORMAT, body)

    if magic != SESSION_HEADER_MAGIC:
        raise HeaderAuthenticationError(f"Invalid session header magic: {magic}")
    if version != SESSION_HEADER_VERSION:
        raise HeaderAuthenticationError(f"Unsupported session header version: {version}")

    return {
        'magic': magic,
        'version': version,
        'flags': flags,
        'epoch': epoch,
        'height': height,
        'width': width,
        'total_blocks': total_blocks,
        'salt_hkdf': salt_hkdf,
        'salt_pbkdf2': salt_pbkdf2,
        'eph_pub': eph_pub,
        'receiver_fingerprint': receiver_fingerprint,
        'hmac_tag': hmac_tag,
        'header_body': body
    }

def verify_session_header_hmac(header_body: bytes, hmac_tag: bytes, key_hdr: bytes) -> bool:
    """Verifies session header HMAC in constant time.
    Raises HeaderAuthenticationError on verification failure.
    """
    if len(key_hdr) != 32:
        raise HeaderAuthenticationError("Invalid header authentication key length")
    expected_hmac = hmac.new(key_hdr, header_body, hashlib.sha256).digest()
    if not hmac.compare_digest(hmac_tag, expected_hmac):
        raise HeaderAuthenticationError("Session header HMAC verification failed: header corrupted or tampered.")
    return True
