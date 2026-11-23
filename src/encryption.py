import os
import struct
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.record_format import build_aad, pack_record
from src.config import USE_DETERMINISTIC_NONCE
from src.key_manager import best_effort_zeroize

class KeyRolloverLimitExceeded(Exception):
    """Raised when the number of AES-GCM invocations under a single key exceeds NIST SP 800-38D limits."""
    pass

# NIST SP 800-38D specifies a maximum of 2^32 invocations per key
MAX_GCM_INVOCATIONS_PER_KEY = 2**32

KEY_INVOCATION_COUNTER = {}

def reset_key_invocation_counter() -> None:
    """Resets key invocation tracker (for unit testing)."""
    KEY_INVOCATION_COUNTER.clear()

def encrypt_blocks(blocks: list[np.ndarray], key: bytes, image_shape: tuple, epoch: int = 0,
                   deterministic_nonce: bool = USE_DETERMINISTIC_NONCE) -> list[bytes]:
    """Encrypts each image block independently using AES-256-GCM.
    
    Guards (Task 4):
    - Tracks GCM invocations per key against NIST SP 800-38D limit (2^32).
    - Random 96-bit nonce by default; optional deterministic salt32 || uint64(index) flag.
    - Explicit 800-byte record packing with 20-byte multi-attribute AAD.
    - Best-effort buffer zeroization.
    """
    total_blocks = len(blocks)
    current_count = KEY_INVOCATION_COUNTER.get(key, 0)
    if current_count + total_blocks > MAX_GCM_INVOCATIONS_PER_KEY:
        raise KeyRolloverLimitExceeded(
            f"NIST SP 800-38D encryption limit exceeded for this key: "
            f"{current_count} + {total_blocks} > {MAX_GCM_INVOCATIONS_PER_KEY}. Rekeying required."
        )
    KEY_INVOCATION_COUNTER[key] = current_count + total_blocks

    aesgcm = AESGCM(key)
    h, w = image_shape[0], image_shape[1]
    encrypted_records = []

    # 32-bit salt for deterministic nonce mode if enabled
    det_salt = os.urandom(4) if deterministic_nonce else None

    for index, block in enumerate(blocks):
        if deterministic_nonce:
            # Deterministic: salt (4 B) || index (8 B, uint64) = 12 bytes
            nonce = det_salt + struct.pack(">Q", index)
        else:
            # Cryptographic random 96-bit nonce
            nonce = os.urandom(12)

        block_bytes = block.tobytes()
        aad = build_aad(index, h, w, total_blocks, epoch)

        # aesgcm.encrypt returns ciphertext + 16-byte tag
        ct_and_tag = aesgcm.encrypt(nonce, block_bytes, aad)
        ciphertext = ct_and_tag[:-16]
        tag = ct_and_tag[-16:]

        record = pack_record(index, nonce, ciphertext, tag)
        encrypted_records.append(record)

        # Best effort zeroization of plaintext buffer copy
        bb_ba = bytearray(block_bytes)
        best_effort_zeroize(bb_ba)

    return encrypted_records
