import numpy as np
from PIL import Image
from src.config import BLOCK_SIZE

def load_image(file_or_path) -> np.ndarray:
    """Loads an image and returns it as a uint8 NumPy array (RGB)."""
    img = Image.open(file_or_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    return np.array(img, dtype=np.uint8)

def pad_image(img_arr: np.ndarray, block_size: int = BLOCK_SIZE) -> tuple[np.ndarray, tuple]:
    """Zero-pads image array so dimensions are multiples of block_size.
    Returns (padded_array, original_shape).
    """
    orig_shape = img_arr.shape
    h, w = orig_shape[0], orig_shape[1]
    
    pad_h = (-h) % block_size
    pad_w = (-w) % block_size
    
    if img_arr.ndim == 3:
        padded = np.pad(img_arr, ((0, pad_h), (0, pad_w), (0, 0)), mode='constant', constant_values=0)
    else:
        padded = np.pad(img_arr, ((0, pad_h), (0, pad_w)), mode='constant', constant_values=0)
        
    return padded, orig_shape

def unpad_image(padded_arr: np.ndarray, orig_shape: tuple) -> np.ndarray:
    """Crops zero-padding to restore the original image shape."""
    h, w = orig_shape[0], orig_shape[1]
    if padded_arr.ndim == 3:
        return padded_arr[:h, :w, :]
    return padded_arr[:h, :w]

def split_into_blocks(padded_arr: np.ndarray, block_size: int = BLOCK_SIZE) -> list[np.ndarray]:
    """Splits a padded image into non-overlapping block_size x block_size patches."""
    h, w = padded_arr.shape[0], padded_arr.shape[1]
    blocks = []
    for y in range(0, h, block_size):
        for x in range(0, w, block_size):
            if padded_arr.ndim == 3:
                blocks.append(padded_arr[y:y+block_size, x:x+block_size, :].copy())
            else:
                blocks.append(padded_arr[y:y+block_size, x:x+block_size].copy())
    return blocks

def merge_blocks(blocks: list[np.ndarray], padded_shape: tuple, block_size: int = BLOCK_SIZE) -> np.ndarray:
    """Reassembles a list of blocks into a full padded image array."""
    out = np.zeros(padded_shape, dtype=np.uint8)
    h, w = padded_shape[0], padded_shape[1]
    idx = 0
    for y in range(0, h, block_size):
        for x in range(0, w, block_size):
            if idx < len(blocks):
                if out.ndim == 3:
                    out[y:y+block_size, x:x+block_size, :] = blocks[idx]
                else:
                    out[y:y+block_size, x:x+block_size] = blocks[idx]
            idx += 1
    return out

