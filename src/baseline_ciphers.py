import os
import struct
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding, hmac, hashes
from src.config import BLOCK_SIZE

def ecb_encrypt(flat_bytes: bytes, key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(flat_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def ecb_decrypt(ct: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    pt_padded = dec.update(ct) + dec.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(pt_padded) + unpadder.finalize()
    except Exception:
        return pt_padded

def cbc_encrypt_monolithic(flat_bytes: bytes, key: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(flat_bytes) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv, ct

def cbc_decrypt_monolithic(iv: bytes, ct: bytes, key: bytes) -> bytes:
    # Truncate to multiple of 16
    usable = (len(ct) // 16) * 16
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    pt_padded = dec.update(ct[:usable]) + dec.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(pt_padded) + unpadder.finalize()
    except Exception:
        return pt_padded

def ctr_encrypt_monolithic(flat_bytes: bytes, key: bytes) -> tuple[bytes, bytes]:
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    ct = enc.update(flat_bytes) + enc.finalize()
    return nonce, ct

def ctr_decrypt_monolithic(nonce: bytes, ct: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    dec = cipher.decryptor()
    return dec.update(ct) + dec.finalize()

def gcm_encrypt_monolithic(flat_bytes: bytes, key: bytes) -> tuple[bytes, bytes, bytes]:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_and_tag = aesgcm.encrypt(nonce, flat_bytes, None)
    return nonce, ct_and_tag[:-16], ct_and_tag[-16:]

def gcm_decrypt_monolithic(nonce: bytes, ct: bytes, tag: bytes, key: bytes) -> tuple[bytes, bool]:
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct + tag, None)
        return pt, True
    except Exception:
        # Monolithic failure: entire payload discarded
        return b"\x00" * len(ct), False

def cbc_block_hmac_encrypt(blocks: list[np.ndarray], enc_key: bytes, mac_key: bytes,
                           image_shape: tuple = None, epoch: int = 0) -> list[bytes]:
    """Fair block + integrity baseline: each 16x16 block encrypted with CBC + HMAC-SHA256
    (Encrypt-then-MAC with AAD-equivalent binding of index/H/W/N/epoch).
    """
    records = []
    total_blocks = len(blocks)
    h_dim = image_shape[0] if image_shape else 0
    w_dim = image_shape[1] if image_shape else 0

    for idx, b in enumerate(blocks):
        b_bytes = b.tobytes()
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(b_bytes) + padder.finalize()
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        
        # Authenticate with HMAC-SHA256 (32 bytes)
        h = hmac.HMAC(mac_key, hashes.SHA256())
        header = struct.pack(">I", idx)
        if image_shape:
            from src.record_format import build_aad
            aad = build_aad(idx, h_dim, w_dim, total_blocks, epoch)
            h.update(aad + iv + ct)
        else:
            h.update(header + iv + ct)
        tag = h.finalize()  # 32-byte HMAC
        
        records.append(header + iv + ct + tag)
    return records

def cbc_block_hmac_decrypt(records: list[bytes], enc_key: bytes, mac_key: bytes,
                           block_shape: tuple, total_blocks: int,
                           image_shape: tuple = None, epoch: int = 0) -> dict:
    decrypted_blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(total_blocks)]
    failed_indices = []
    arrived_indices = set()
    h_dim = image_shape[0] if image_shape else 0
    w_dim = image_shape[1] if image_shape else 0
    
    for rec in records:
        if len(rec) < 4 + 16 + 32:
            continue
        idx = struct.unpack(">I", rec[:4])[0]
        if idx < 0 or idx >= total_blocks:
            continue
        arrived_indices.add(idx)
        
        iv = rec[4:20]
        tag = rec[-32:]
        ct = rec[20:-32]
        
        # Verify HMAC
        h = hmac.HMAC(mac_key, hashes.SHA256())
        if image_shape:
            from src.record_format import build_aad
            aad = build_aad(idx, h_dim, w_dim, total_blocks, epoch)
            h.update(aad + iv + ct)
        else:
            h.update(rec[:4] + iv + ct)
        try:
            h.verify(tag)
        except Exception:
            failed_indices.append(idx)
            decrypted_blocks[idx] = np.zeros(block_shape, dtype=np.uint8)
            continue
            
        # Decrypt CBC
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        try:
            unpadder = padding.PKCS7(128).unpadder()
            pt = unpadder.update(padded) + unpadder.finalize()
            decrypted_blocks[idx] = np.frombuffer(pt, dtype=np.uint8).reshape(block_shape)
        except Exception:
            failed_indices.append(idx)
            decrypted_blocks[idx] = np.zeros(block_shape, dtype=np.uint8)
            
    missing_indices = [i for i in range(total_blocks) if i not in arrived_indices]
    return {
        'blocks': decrypted_blocks,
        'failed_indices': failed_indices,
        'missing_indices': missing_indices,
        'failed_count': len(failed_indices),
        'missing_count': len(missing_indices)
    }



def cbc_block_framed_encrypt(blocks: list[np.ndarray], enc_key: bytes) -> list[bytes]:
    """Framed CBC baseline: each 16x16 block carries an explicit 4-byte sequence header
    and 16-byte IV, but NO integrity tag. Block payload is exactly 768 bytes (48 AES blocks).
    """
    records = []
    for idx, b in enumerate(blocks):
        b_bytes = b.tobytes()  # 768 bytes
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        enc = cipher.encryptor()
        ct = enc.update(b_bytes) + enc.finalize()
        header = struct.pack(">I", idx)
        records.append(header + iv + ct)
    return records

def cbc_block_framed_decrypt(records: list[bytes], enc_key: bytes,
                             block_shape: tuple, total_blocks: int) -> dict:
    """Decrypts framed CBC records. Identifies missing records via header sequence gaps,
    but cannot detect in-place ciphertext tampering due to lack of MAC/tag.
    """
    decrypted_blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(total_blocks)]
    arrived_indices = set()
    
    for rec in records:
        if len(rec) < 20:
            continue
        idx = struct.unpack(">I", rec[:4])[0]
        if idx < 0 or idx >= total_blocks:
            continue
        arrived_indices.add(idx)
        iv = rec[4:20]
        ct = rec[20:]
        usable = (len(ct) // 16) * 16
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        dec = cipher.decryptor()
        pt = dec.update(ct[:usable]) + dec.finalize()
        if len(pt) >= 768:
            decrypted_blocks[idx] = np.frombuffer(pt[:768], dtype=np.uint8).reshape(block_shape)
            
    missing_indices = [i for i in range(total_blocks) if i not in arrived_indices]
    return {
        'blocks': decrypted_blocks,
        'failed_indices': [],  # CBC cannot detect tampering
        'missing_indices': missing_indices,
        'failed_count': 0,
        'missing_count': len(missing_indices)
    }
