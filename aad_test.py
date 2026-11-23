"""
Demonstrates block-index-bound AAD for AES-256-GCM image blocks.

Run this standalone first to confirm the swap-detection behavior,
then port encrypt_block_with_index / decrypt_block_with_index into
your Streamlit app's encryption/decryption modules.
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(KEY)


def encrypt_block_with_index(plaintext_block: bytes, block_index: int) -> dict:
    """Encrypts one image block, binding its position as AAD.
    Record format: nonce (12B) + ciphertext+tag (unchanged length).
    The AAD itself is NOT stored -- it's recomputed from the block's
    position at decrypt time, which is exactly what makes a swap fail.
    """
    nonce = os.urandom(12)
    aad = block_index.to_bytes(4, "big")
    ct = aesgcm.encrypt(nonce, plaintext_block, aad)
    return {"nonce": nonce, "ciphertext": ct}


def decrypt_block_with_index(record: dict, expected_index: int) -> bytes:
    """Decrypts using the block's CURRENT (received) position as AAD.
    If the block was moved from its original position, expected_index
    won't match the index it was encrypted with -> InvalidTag.
    """
    aad = expected_index.to_bytes(4, "big")
    return aesgcm.decrypt(record["nonce"], record["ciphertext"], aad)


if __name__ == "__main__":
    from cryptography.exceptions import InvalidTag

    # Simulate two adjacent 768-byte image blocks
    block_a = b"A" * 768
    block_b = b"B" * 768

    rec_a = encrypt_block_with_index(block_a, block_index=0)
    rec_b = encrypt_block_with_index(block_b, block_index=1)

    print("=== Normal decryption (correct positions) ===")
    print("Block 0 OK:", decrypt_block_with_index(rec_a, 0) == block_a)
    print("Block 1 OK:", decrypt_block_with_index(rec_b, 1) == block_b)

    print("\n=== Simulated block-reordering attack (swap records) ===")
    swapped = {0: rec_b, 1: rec_a}  # someone swapped the two ciphertext records
    for idx, rec in swapped.items():
        try:
            decrypt_block_with_index(rec, idx)
            print(f"Block {idx}: DECRYPTED (BAD -- should have failed)")
        except InvalidTag:
            print(f"Block {idx}: InvalidTag raised (correctly detected as tampered)")

    print("\n=== For comparison: WITHOUT AAD binding, a swap succeeds silently ===")
    aesgcm2 = AESGCM(KEY)
    nonce_a, nonce_b = os.urandom(12), os.urandom(12)
    ct_a = aesgcm2.encrypt(nonce_a, block_a, None)
    ct_b = aesgcm2.encrypt(nonce_b, block_b, None)
    swapped_noaad = {0: (nonce_b, ct_b), 1: (nonce_a, ct_a)}
    for idx, (nonce, ct) in swapped_noaad.items():
        pt = aesgcm2.decrypt(nonce, ct, None)
        print(f"Block {idx}: decrypted successfully to wrong content "
              f"(silently misplaced, EPR would show 0 failures)")