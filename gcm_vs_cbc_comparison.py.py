"""
gcm_vs_cbc_comparison.py

End-to-end experiment comparing error-propagation behaviour of:
  (A) the paper's block-independent AES-256-GCM pipeline, and
  (B) a standard chained AES-256-CBC pipeline (single IV, whole image
      encrypted as one continuous stream),

on the SAME test image, at the SAME corruption levels used in Table II
of the paper (10, 25, 50, 100, 200 corrupted image-blocks).

For GCM, corruption = single-byte bit-flip in a targeted block's ciphertext
(matches the paper's existing corrupt_blocks() function).
For CBC, corruption = deletion of the AES sub-block(s) belonging to a
targeted image-block, which desynchronizes every CBC block after it -
this is what actually produces "unbounded" propagation in chained modes,
not a same-position bit-flip (which CBC self-heals from after ~2 blocks).

Usage:
    python gcm_vs_cbc_comparison.py path/to/test_image.png

Output:
    A results table (printed + saved as CSV) with columns:
    mode, corrupted_blocks, failed_blocks, epr, affected_pct, psnr_db
"""

import os
import sys
import csv
import random

import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BLOCK = 16          # image block size (16x16 pixels, matches the paper)
CORRUPTION_LEVELS = [10, 25, 50, 100, 200]
RANDOM_SEED = None    # set to None for a fresh random run each time


# --------------------------------------------------------------------------- #
# Image preprocessing (shared by both pipelines)
# --------------------------------------------------------------------------- #

def load_and_pad_image(path: str) -> tuple[np.ndarray, tuple[int, int, int]]:
    """Loads an image as RGB, pads H and W to multiples of BLOCK."""
    img = Image.open(path).convert("RGB")
    arr = np.array(img)
    h, w, c = arr.shape
    pad_h = (-h) % BLOCK
    pad_w = (-w) % BLOCK
    padded = np.pad(arr, ((0, pad_h), (0, pad_w), (0, 0)), mode="constant")
    return padded, arr.shape


def split_into_blocks(padded: np.ndarray) -> list[np.ndarray]:
    h, w, c = padded.shape
    blocks = []
    for y in range(0, h, BLOCK):
        for x in range(0, w, BLOCK):
            blocks.append(padded[y:y + BLOCK, x:x + BLOCK, :].copy())
    return blocks


def blocks_to_image(blocks: list[np.ndarray], padded_shape: tuple[int, int, int],
                     original_shape: tuple[int, int, int]) -> np.ndarray:
    h, w, c = padded_shape
    out = np.zeros(padded_shape, dtype=np.uint8)
    i = 0
    for y in range(0, h, BLOCK):
        for x in range(0, w, BLOCK):
            out[y:y + BLOCK, x:x + BLOCK, :] = blocks[i]
            i += 1
    oh, ow, oc = original_shape
    return out[:oh, :ow, :]


def psnr(original: np.ndarray, reconstructed: np.ndarray) -> float:
    """Standard PSNR: 10*log10(MAX^2 / MSE). Returns inf for identical images."""
    original = original.astype(np.float64)
    reconstructed = reconstructed.astype(np.float64)
    mse = np.mean((original - reconstructed) ** 2)
    if mse == 0:
        return float("inf")
    max_pixel = 255.0
    return 10 * np.log10((max_pixel ** 2) / mse)


# --------------------------------------------------------------------------- #
# Pipeline A: block-independent AES-256-GCM (matches the paper)
# --------------------------------------------------------------------------- #

def gcm_encrypt_blocks(blocks: list[np.ndarray], key: bytes) -> list[bytes]:
    aesgcm = AESGCM(key)
    records = []
    for block in blocks:
        nonce = os.urandom(12)
        plaintext = block.tobytes()
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
        records.append(nonce + ciphertext_and_tag)
    return records


def corrupt_blocks_gcm(encrypted_blocks: list[bytes], indices: list[int]) -> list[bytes]:
    """Single-byte bit-flip in the targeted blocks' ciphertext (first byte
    after the 12-byte nonce) - matches the paper's corrupt_blocks()."""
    corrupted = encrypted_blocks.copy()
    for idx in indices:
        block = bytearray(corrupted[idx])
        if len(block) > 12:
            block[12] ^= 0xFF
        corrupted[idx] = bytes(block)
    return corrupted


def gcm_decrypt_blocks(records: list[bytes], key: bytes, block_shape: tuple[int, int, int]
                        ) -> tuple[list[np.ndarray], int]:
    aesgcm = AESGCM(key)
    decrypted_blocks = []
    failed = 0
    for record in records:
        nonce, ct_and_tag = record[:12], record[12:]
        try:
            plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
            decrypted_blocks.append(
                np.frombuffer(plaintext, dtype=np.uint8).reshape(block_shape)
            )
        except Exception:
            failed += 1
            decrypted_blocks.append(np.zeros(block_shape, dtype=np.uint8))
    return decrypted_blocks, failed


# --------------------------------------------------------------------------- #
# Pipeline B: chained AES-256-CBC (comparison baseline)
# --------------------------------------------------------------------------- #

def cbc_encrypt_image(plaintext_bytes: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext_bytes) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def simulate_block_loss_cbc(ciphertext: bytes, block_byte_size: int,
                             corrupted_image_block_indices: list[int]) -> bytes:
    """Deletes one 16-byte AES sub-block from within each targeted image
    block's ciphertext span, desynchronizing every CBC block after it."""
    aes_block = 16
    out = bytearray(ciphertext)
    for block_idx in sorted(corrupted_image_block_indices, reverse=True):
        start = block_idx * block_byte_size
        # delete the first AES sub-block within this image block's span
        del out[start:start + aes_block]
    return bytes(out)


def cbc_decrypt_image(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    # truncate to a multiple of 16 (deletions can misalign the final length)
    usable_len = (len(ciphertext) // 16) * 16
    ciphertext = ciphertext[:usable_len]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError:
        return padded  # padding breaks after desync; keep raw bytes for comparison


def bytes_to_blocks(data: bytes, block_byte_size: int, num_blocks: int,
                     block_shape: tuple[int, int, int]) -> list[np.ndarray]:
    """Slices a flat byte stream back into image blocks, padding/truncating
    the tail with zeros if desync shifted the stream length."""
    blocks = []
    needed = num_blocks * block_byte_size
    if len(data) < needed:
        data = data + b"\x00" * (needed - len(data))
    for i in range(num_blocks):
        start = i * block_byte_size
        chunk = data[start:start + block_byte_size]
        blocks.append(np.frombuffer(chunk, dtype=np.uint8).reshape(block_shape))
    return blocks


def count_failed_blocks_cbc(original_blocks: list[np.ndarray],
                             decrypted_blocks: list[np.ndarray]) -> int:
    return sum(
        1 for o, d in zip(original_blocks, decrypted_blocks) if not np.array_equal(o, d)
    )


# --------------------------------------------------------------------------- #
# Experiment runner
# --------------------------------------------------------------------------- #

def run_experiment(image_path: str) -> list[dict]:
    if RANDOM_SEED is not None:
        random.seed(RANDOM_SEED)

    padded, original_shape = load_and_pad_image(image_path)
    blocks = split_into_blocks(padded)
    total_blocks = len(blocks)
    block_shape = blocks[0].shape          # (16, 16, 3)
    block_byte_size = blocks[0].nbytes     # 768 for a 16x16x3 uint8 block

    print(f"Image: {image_path}")
    print(f"Original shape: {original_shape}  Padded shape: {padded.shape}")
    print(f"Total blocks: {total_blocks}  (block byte size: {block_byte_size})\n")

    key = os.urandom(32)  # AES-256 key, shared by both pipelines for fair comparison

    # --- one-time encryption for each pipeline --- #
    gcm_records = gcm_encrypt_blocks(blocks, key)

    flat_plaintext = b"".join(b.tobytes() for b in blocks)
    cbc_iv, cbc_ciphertext = cbc_encrypt_image(flat_plaintext, key)

    results = []

    for n_corrupt in CORRUPTION_LEVELS:
        n_corrupt = min(n_corrupt, total_blocks)
        indices = random.sample(range(total_blocks), n_corrupt)

        # ---------------- GCM run ---------------- #
        corrupted_gcm = corrupt_blocks_gcm(gcm_records, indices)
        decrypted_gcm_blocks, failed_gcm = gcm_decrypt_blocks(corrupted_gcm, key, block_shape)
        recon_gcm = blocks_to_image(decrypted_gcm_blocks, padded.shape, original_shape)
        original_img = padded[:original_shape[0], :original_shape[1], :]
        psnr_gcm = psnr(original_img, recon_gcm)
        epr_gcm = failed_gcm / n_corrupt if n_corrupt else float("nan")

        results.append({
            "mode": "AES-GCM (block-independent)",
            "corrupted_blocks": n_corrupt,
            "failed_blocks": failed_gcm,
            "epr": round(epr_gcm, 4),
            "affected_pct": round(100 * failed_gcm / total_blocks, 2),
            "psnr_db": round(psnr_gcm, 2) if psnr_gcm != float("inf") else "inf",
        })

        # ---------------- CBC run ---------------- #
        corrupted_cbc_ct = simulate_block_loss_cbc(cbc_ciphertext, block_byte_size, indices)
        decrypted_bytes = cbc_decrypt_image(cbc_iv, corrupted_cbc_ct, key)
        decrypted_cbc_blocks = bytes_to_blocks(decrypted_bytes, block_byte_size,
                                                total_blocks, block_shape)
        failed_cbc = count_failed_blocks_cbc(blocks, decrypted_cbc_blocks)
        recon_cbc = blocks_to_image(decrypted_cbc_blocks, padded.shape, original_shape)
        psnr_cbc = psnr(original_img, recon_cbc)
        epr_cbc = failed_cbc / n_corrupt if n_corrupt else float("nan")

        results.append({
            "mode": "AES-CBC (chained)",
            "corrupted_blocks": n_corrupt,
            "failed_blocks": failed_cbc,
            "epr": round(epr_cbc, 4),
            "affected_pct": round(100 * failed_cbc / total_blocks, 2),
            "psnr_db": round(psnr_cbc, 2) if psnr_cbc != float("inf") else "inf",
        })

    return results


def print_table(results: list[dict]) -> None:
    header = f"{'Mode':<28}{'Corrupted':>10}{'Failed':>10}{'EPR':>10}{'Affected%':>12}{'PSNR(dB)':>10}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(f"{r['mode']:<28}{r['corrupted_blocks']:>10}{r['failed_blocks']:>10}"
              f"{r['epr']:>10}{r['affected_pct']:>12}{r['psnr_db']:>10}")


def save_csv(results: list[dict], out_path: str) -> None:
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved results to {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python gcm_vs_cbc_comparison.py path/to/test_image.png")
        sys.exit(1)

    results = run_experiment(sys.argv[1])
    print()
    print_table(results)
    save_csv(results, "gcm_vs_cbc_results.csv")