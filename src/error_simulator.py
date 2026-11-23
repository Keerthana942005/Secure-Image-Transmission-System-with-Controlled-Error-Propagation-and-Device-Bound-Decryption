import random

def corrupt_blocks(encrypted_blocks: list[bytes], num_corruptions: int, seed: int = None) -> list[bytes]:
    """Simulates transmission errors by randomly corrupting a specified number of blocks."""
    if num_corruptions == 0:
        return encrypted_blocks
        
    rng = random.Random(seed) if seed is not None else random.Random()
    corrupted_blocks = list(encrypted_blocks)
    indices_to_corrupt = rng.sample(range(len(corrupted_blocks)), min(num_corruptions, len(corrupted_blocks)))
    
    for idx in indices_to_corrupt:
        block = bytearray(corrupted_blocks[idx])
        if len(block) > 16:
            # Flip a byte in the ciphertext payload (byte offset 16, just after 4B index + 12B IV)
            block[16] ^= 0xFF
        corrupted_blocks[idx] = bytes(block)
        
    return corrupted_blocks

def drop_blocks(encrypted_blocks: list[bytes], num_drops: int, seed: int = None) -> list[bytes]:
    """Simulates packet loss in transit by omitting records."""
    if num_drops == 0:
        return encrypted_blocks
    rng = random.Random(seed) if seed is not None else random.Random()
    indices_to_drop = set(rng.sample(range(len(encrypted_blocks)), min(num_drops, len(encrypted_blocks))))
    return [b for i, b in enumerate(encrypted_blocks) if i not in indices_to_drop]

def swap_blocks(encrypted_blocks: list[bytes], pair_indices: tuple[int, int] = (0, 1)) -> list[bytes]:
    """Simulates adversarial block swapping / reordering attack."""
    swapped = list(encrypted_blocks)
    i, j = pair_indices
    if i < len(swapped) and j < len(swapped):
        swapped[i], swapped[j] = swapped[j], swapped[i]
    return swapped
