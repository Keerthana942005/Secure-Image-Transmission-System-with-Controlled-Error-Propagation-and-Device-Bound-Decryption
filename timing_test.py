"""
Measures encryption/decryption throughput for Table I, using your
actual encrypt_blocks / decrypt_blocks functions and the real image.

Usage:
    python timing_test.py submarine.jpg
"""
import os
import time
import random
import numpy as np
from PIL import Image

from encryption import encrypt_blocks
from decryption import decrypt_blocks
from config import BLOCK_SIZE


def load_and_split(image_path: str):
    img = Image.open(image_path).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    h, w, _ = arr.shape
    pad_h = (-h) % BLOCK_SIZE
    pad_w = (-w) % BLOCK_SIZE
    padded = np.pad(arr, ((0, pad_h), (0, pad_w), (0, 0)), mode="constant")
    ph, pw, _ = padded.shape
    blocks = []
    for row in range(0, ph, BLOCK_SIZE):
        for col in range(0, pw, BLOCK_SIZE):
            blocks.append(padded[row:row + BLOCK_SIZE, col:col + BLOCK_SIZE, :])
    return blocks, (BLOCK_SIZE, BLOCK_SIZE, 3), arr.shape, padded.shape


def corrupt_n_blocks(encrypted_blocks: list, n: int, rng: random.Random) -> list:
    """Flips the first ciphertext byte (right after the 12-byte nonce)
    for n randomly chosen blocks -- matches your app's corruption method."""
    corrupted = encrypted_blocks.copy()
    indices = rng.sample(range(len(corrupted)), n)
    for idx in indices:
        rec = bytearray(corrupted[idx])
        rec[12] ^= 0xFF
        corrupted[idx] = bytes(rec)
    return corrupted


def run(image_path: str):
    blocks, block_shape, orig_shape, padded_shape = load_and_split(image_path)
    total_blocks = len(blocks)
    print(f"Image: {image_path}")
    print(f"Original shape: {orig_shape}  Padded shape: {padded_shape}")
    print(f"Total blocks: {total_blocks}\n")

    key = os.urandom(32)  # timing-only test; bypasses HKDF/device flow
    NUM_TRIALS = 20  # average over multiple runs to smooth OS/GC jitter

    enc_times = []
    for _ in range(NUM_TRIALS):
        t0 = time.perf_counter()
        encrypted_blocks = encrypt_blocks(blocks, key)
        enc_times.append(time.perf_counter() - t0)
    print(f"Encryption ({total_blocks} blocks): "
          f"{np.mean(enc_times) * 1000:.4f} ms avg  "
          f"(min {min(enc_times)*1000:.4f}, max {max(enc_times)*1000:.4f}, n={NUM_TRIALS})")

    rng = random.Random(42)
    for n in [0, 10, 50, 100, 200]:
        test_blocks = encrypted_blocks if n == 0 else corrupt_n_blocks(encrypted_blocks, n, rng)
        dec_times = []
        failed = None
        for _ in range(NUM_TRIALS):
            t0 = time.perf_counter()
            _, failed = decrypt_blocks(test_blocks, key, block_shape)
            dec_times.append(time.perf_counter() - t0)
        print(f"Decryption, {n} corruptions: "
              f"{np.mean(dec_times) * 1000:.4f} ms avg  "
              f"(min {min(dec_times)*1000:.4f}, max {max(dec_times)*1000:.4f}, "
              f"n={NUM_TRIALS}, failed={failed})")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python timing_test.py path/to/image.png")
        sys.exit(1)
    run(sys.argv[1])