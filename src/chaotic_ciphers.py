"""Chaotic and Selective Image Encryption Baselines.

Faithful reference implementations of:
1. Zhou et al. (2014): 1D Chaotic System for Image Encryption (Signal Processing 97, 172-182).
   Combination chaotic system:
     x_{n+1} = (4 * mu * x_n * (1 - x_n) + (4 - mu) * (x_n / 2)) mod 1.0
   Followed by chaotic permutation and sequential XOR diffusion.
2. Hua et al. (2015): 2D Sine-Logistic-Modulation Map (2D-SLMM) (Information Sciences 297, 80-94).
   Coupled 2D map:
     x_{i+1} = alpha * (sin(pi * y_i) + beta) * x_i * (1 - x_i) mod 1.0
     y_{i+1} = alpha * (sin(pi * x_{i+1}) + beta) * y_i * (1 - y_i) mod 1.0
   Followed by chaotic permutation and forward modular addition diffusion.
3. MSB Selective Encryption (AES-256-CTR on 4 MSBs):
   Applies AES-256-CTR strictly to the 4 Most Significant Bits (MSBs) of each pixel byte,
   leaving the 4 Least Significant Bits (LSBs) unencrypted in plaintext.
"""

import os
import math
from functools import lru_cache
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# -----------------------------------------------------------------------------
# 1. Zhou et al. (2014) 1D Chaotic Map & Cipher
# -----------------------------------------------------------------------------
@lru_cache(maxsize=16)
def zhou_1d_generate_keystream(n_bytes: int, x0: float = 0.3541829, mu: float = 3.99, discard: int = 1000) -> tuple[np.ndarray, np.ndarray]:
    """Generates permutation indices and diffusion keystream using Zhou et al. (2014) 1D chaotic system.
    Returns (perm_indices, diffusion_keystream) of shape (n_bytes,).
    """
    total_iters = discard + n_bytes
    x = np.empty(total_iters, dtype=np.float64)
    curr = x0
    for i in range(total_iters):
        # x_{n+1} = (4 * mu * x_n * (1 - x_n) + (4 - mu) * (x_n / 2)) mod 1.0
        val = 4.0 * mu * curr * (1.0 - curr) + (4.0 - mu) * (curr / 2.0)
        curr = val - math.floor(val)
        x[i] = curr
        
    seq = x[discard:]
    # Permutation indices derived from sorting chaotic values
    perm_indices = np.argsort(seq)
    # Diffusion keystream derived by scaling to 0..255
    diffusion_bytes = np.floor(seq * 256.0).astype(np.uint8)
    return perm_indices, diffusion_bytes

def zhou_1d_encrypt(image_array: np.ndarray, x0: float = 0.3541829, mu: float = 3.99) -> np.ndarray:
    """Encrypts an image using Zhou et al. (2014) permutation + sequential XOR diffusion."""
    orig_shape = image_array.shape
    flat = image_array.flatten()
    n_bytes = len(flat)
    
    perm_indices, diff_key = zhou_1d_generate_keystream(n_bytes, x0=x0, mu=mu)
    permuted = flat[perm_indices]
    
    # Sequential XOR diffusion: C[i] = P_perm[i] ^ K[i] ^ C[i-1]
    cipher = np.empty(n_bytes, dtype=np.uint8)
    prev = 0xAA  # initial vector constant
    for i in range(n_bytes):
        curr = permuted[i] ^ diff_key[i] ^ prev
        cipher[i] = curr
        prev = curr
        
    return cipher.reshape(orig_shape)

def zhou_1d_decrypt(cipher_array: np.ndarray, x0: float = 0.3541829, mu: float = 3.99) -> np.ndarray:
    """Decrypts an image encrypted with Zhou et al. (2014)."""
    orig_shape = cipher_array.shape
    cipher_flat = cipher_array.flatten()
    n_bytes = len(cipher_flat)
    
    perm_indices, diff_key = zhou_1d_generate_keystream(n_bytes, x0=x0, mu=mu)
    
    # Invert diffusion: P_perm[i] = C[i] ^ K[i] ^ C[i-1]
    permuted = np.empty(n_bytes, dtype=np.uint8)
    prev = 0xAA
    for i in range(n_bytes):
        curr = cipher_flat[i]
        permuted[i] = curr ^ diff_key[i] ^ prev
        prev = curr
        
    # Invert permutation
    plain_flat = np.empty(n_bytes, dtype=np.uint8)
    plain_flat[perm_indices] = permuted
    return plain_flat.reshape(orig_shape)


# -----------------------------------------------------------------------------
# 2. Hua et al. (2015) 2D Sine-Logistic-Modulation Map (2D-SLMM) & Cipher
# -----------------------------------------------------------------------------
@lru_cache(maxsize=16)
def hua_2d_slmm_generate_keystream(n_bytes: int, x0: float = 0.28471, y0: float = 0.61938, 
                                   alpha: float = 0.999, beta: float = 3.0, discard: int = 1000) -> tuple[np.ndarray, np.ndarray]:
    """Generates permutation and diffusion sequences using Hua et al. (2015) 2D-SLMM.
    2D-SLMM:
      x_{i+1} = alpha * (sin(pi * y_i) + beta) * x_i * (1 - x_i) mod 1.0
      y_{i+1} = alpha * (sin(pi * x_{i+1}) + beta) * y_i * (1 - y_i) mod 1.0
    """
    total_iters = discard + n_bytes
    x = np.empty(total_iters, dtype=np.float64)
    y = np.empty(total_iters, dtype=np.float64)
    
    cx, cy = x0, y0
    pi = math.pi
    for i in range(total_iters):
        nx = alpha * (math.sin(pi * cy) + beta) * cx * (1.0 - cx)
        nx = nx - math.floor(nx)
        ny = alpha * (math.sin(pi * nx) + beta) * cy * (1.0 - cy)
        ny = ny - math.floor(ny)
        x[i] = nx
        y[i] = ny
        cx, cy = nx, ny
        
    x_seq = x[discard:]
    y_seq = y[discard:]
    
    perm_indices = np.argsort(x_seq)
    diff_key = np.floor(y_seq * 256.0).astype(np.uint8)
    return perm_indices, diff_key

def hua_2d_slmm_encrypt(image_array: np.ndarray, x0: float = 0.28471, y0: float = 0.61938) -> np.ndarray:
    """Encrypts an image using Hua et al. (2015) 2D-SLMM with modular addition diffusion:
    C[i] = (P_perm[i] + K[i] + C[i-1]) mod 256.
    """
    orig_shape = image_array.shape
    flat = image_array.flatten()
    n_bytes = len(flat)
    
    perm_indices, diff_key = hua_2d_slmm_generate_keystream(n_bytes, x0=x0, y0=y0)
    permuted = flat[perm_indices]
    
    cipher = np.empty(n_bytes, dtype=np.uint8)
    prev = 0x55
    for i in range(n_bytes):
        curr = (int(permuted[i]) + int(diff_key[i]) + prev) & 0xFF
        cipher[i] = curr
        prev = curr
        
    return cipher.reshape(orig_shape)

def hua_2d_slmm_decrypt(cipher_array: np.ndarray, x0: float = 0.28471, y0: float = 0.61938) -> np.ndarray:
    """Decrypts an image encrypted with Hua et al. (2015) 2D-SLMM."""
    orig_shape = cipher_array.shape
    cipher_flat = cipher_array.flatten()
    n_bytes = len(cipher_flat)
    
    perm_indices, diff_key = hua_2d_slmm_generate_keystream(n_bytes, x0=x0, y0=y0)
    
    permuted = np.empty(n_bytes, dtype=np.uint8)
    prev = 0x55
    for i in range(n_bytes):
        curr = int(cipher_flat[i])
        val = (curr - int(diff_key[i]) - prev) & 0xFF
        permuted[i] = val
        prev = curr
        
    plain_flat = np.empty(n_bytes, dtype=np.uint8)
    plain_flat[perm_indices] = permuted
    return plain_flat.reshape(orig_shape)


# -----------------------------------------------------------------------------
# 3. MSB Selective Encryption (AES-256-CTR on 4 MSBs)
# -----------------------------------------------------------------------------
def msb_selective_encrypt(image_array: np.ndarray, key: bytes, nonce: bytes = b"\x00" * 16) -> np.ndarray:
    """Encrypts strictly the 4 MSBs of each pixel byte using AES-256-CTR,
    leaving the 4 LSBs untouched in plaintext.
    """
    orig_shape = image_array.shape
    flat = image_array.flatten()
    n = len(flat)
    
    # Extract MSB nibbles and LSB nibbles
    msb_nibbles = (flat >> 4) & 0x0F
    lsb_nibbles = flat & 0x0F
    
    # Pack two 4-bit MSB nibbles into one byte for AES-CTR processing
    n_packed = (n + 1) // 2
    packed = np.zeros(n_packed, dtype=np.uint8)
    packed[:n // 2] = (msb_nibbles[0::2][:n // 2] << 4) | msb_nibbles[1::2][:n // 2]
    if n % 2 == 1:
        packed[-1] = msb_nibbles[-1] << 4
        
    # Encrypt packed MSBs with AES-256-CTR
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    enc_packed_bytes = encryptor.update(packed.tobytes()) + encryptor.finalize()
    enc_packed = np.frombuffer(enc_packed_bytes, dtype=np.uint8)
    
    # Unpack encrypted MSB nibbles
    enc_msb = np.empty(n, dtype=np.uint8)
    enc_msb[0::2] = (enc_packed[:(n + 1) // 2] >> 4) & 0x0F
    if n > 1:
        enc_msb[1::2] = enc_packed[:n // 2] & 0x0F
        
    # Combine encrypted MSBs with plaintext LSBs
    cipher_flat = ((enc_msb << 4) | lsb_nibbles).astype(np.uint8)
    return cipher_flat.reshape(orig_shape)

def msb_selective_decrypt(cipher_array: np.ndarray, key: bytes, nonce: bytes = b"\x00" * 16) -> np.ndarray:
    """Decrypts an image encrypted with MSB selective encryption (symmetric CTR mode)."""
    # Since AES-CTR is symmetric, decryption of the packed MSBs is identical to encryption
    return msb_selective_encrypt(cipher_array, key, nonce=nonce)
