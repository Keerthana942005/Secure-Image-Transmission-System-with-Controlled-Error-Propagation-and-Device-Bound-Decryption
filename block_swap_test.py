"""
Block-reordering resilience test for the AAD-bound AES-256-GCM pipeline.

Runs the encrypt/decrypt pipeline at several swap counts and records
how many blocks fail authentication -- expected result with AAD binding:
failed_blocks == 2 * num_swaps at every level (each block in a swapped
pair fails independently, since its AAD no longer matches its position).

Usage:
    python block_swap_test.py path/to/your_test_image.png

Adjust the import lines below to match your actual project structure
(these assume encryption.py / decryption.py / config.py sit alongside
this script, same as your existing gcm_vs_cbc_comparison.py setup).
"""
import os
import csv
import random
import numpy as np
from PIL import Image

from encryption import encrypt_blocks
from decryption import decrypt_blocks
from config import BLOCK_SIZE  # assumed to be e.g. 16

RANDOM_SEED = 42
SWAP_COUNTS = [1, 5, 10, 20]  # number of PAIRS to swap at each level


def load_and_split(image_path: str):
    """Loads an image, zero-pads to a multiple of BLOCK_SIZE, and splits
    into a list of (BLOCK_SIZE, BLOCK_SIZE, 3) uint8 blocks, raster order."""
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


def simulate_block_swap(encrypted_blocks: list, num_swap_pairs: int, rng: random.Random) -> list:
    """Returns a NEW list with num_swap_pairs disjoint pairs of entries swapped.
    Disjoint sampling ensures no block is involved in more than one swap,
    so failed-block count is exactly predictable (2 * num_swap_pairs)."""
    swapped = encrypted_blocks.copy()
    indices = rng.sample(range(len(swapped)), num_swap_pairs * 2)
    for i in range(0, len(indices), 2):
        a, b = indices[i], indices[i + 1]
        swapped[a], swapped[b] = swapped[b], swapped[a]
    return swapped


def run(image_path: str):
    blocks, block_shape, orig_shape, padded_shape = load_and_split(image_path)
    total_blocks = len(blocks)
    print(f"Image: {image_path}")
    print(f"Original shape: {orig_shape}  Padded shape: {padded_shape}")
    print(f"Total blocks: {total_blocks}")
    print()

    key = os.urandom(32)  # standalone block-level test; bypasses full HKDF/device flow
    encrypted_blocks = encrypt_blocks(blocks, key)

    rng = random.Random(RANDOM_SEED)
    results = []

    print(f"{'Swap pairs':<12}{'Failed':<10}{'Expected':<10}{'Match':<8}")
    print("-" * 42)
    for n in SWAP_COUNTS:
        tampered = simulate_block_swap(encrypted_blocks, n, rng)
        _, failed = decrypt_blocks(tampered, key, block_shape)
        expected = 2 * n
        match = "YES" if failed == expected else "NO"
        results.append({
            "swap_pairs": n,
            "blocks_swapped": expected,
            "failed_blocks": failed,
            "total_blocks": total_blocks,
            "epr": round(failed / expected, 4) if expected else None,
        })
        print(f"{n:<12}{failed:<10}{expected:<10}{match:<8}")

    with open("block_swap_results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print("\nSaved results to block_swap_results.csv")


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python block_swap_test.py path/to/image.png")
        sys.exit(1)
    run(sys.argv[1])