import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.config import DEFAULT_TAU, BLOCK_SIZE
from src.record_format import (
    build_aad,
    unpack_record,
    parse_session_header_fields,
    verify_session_header_hmac,
    HeaderAuthenticationError
)
from src.key_manager import (
    get_key_fingerprint,
    derive_session_keys,
    is_fingerprint_revoked,
    is_device_revoked,
    check_epoch_monotonicity,
    commit_epoch,
    verify_and_update_epoch
)
from src.error_concealment import conceal_failed_blocks

# Permitted action labels per Task 2.7
ACTION_CONCEALED = "concealed"
ACTION_REJECTED_OVER_THRESHOLD = "rejected_over_threshold"
ACTION_DUPLICATE_IGNORED = "duplicate_ignored"
ACTION_SESSION_REJECTED = "session_rejected"
ACTION_DETECTED_AND_QUARANTINED = "detected_and_quarantined"
ACTION_AUTHENTIC = "authentic"

def decrypt_blocks(records: list[bytes], key: bytes, image_shape: tuple,
                   block_shape: tuple, total_blocks: int, epoch: int = 0,
                   enable_concealment: bool = False,
                   concealment_tau: float = DEFAULT_TAU) -> dict:
    """Decrypts block records using explicit header index and verifies AAD.
    Enforces the explicit receiver policy (Task 2):
    - Missing records (gaps/truncation): treated as missing.
    - Tag failure: treated as failed/quarantined.
    - Duplicates: first authentic record kept, later copies ignored.
    - Threshold tau: if (failed + missing) / total > tau -> action = "rejected_over_threshold"
    
    Returns structured result:
    {
        'blocks': list of blocks,
        'authentic_blocks': int,
        'failed_blocks': int,
        'missing_blocks': int,
        'duplicate_blocks_ignored': int,
        'concealed_block_mask': np.ndarray (bool),
        'failed_fraction': float,
        'action': str,
        'failed_indices': list[int],
        'missing_indices': list[int],
        'concealment_applied': bool,
        'concealment_mask': np.ndarray (bool)  # backward compatibility alias
    }
    """
    aesgcm = AESGCM(key)
    h, w = image_shape[0], image_shape[1]
    bh, bw, c = block_shape
    grid_rows = h // bh
    grid_cols = w // bw

    decrypted_blocks = [np.zeros(block_shape, dtype=np.uint8) for _ in range(total_blocks)]
    accepted_indices = set()
    failed_indices = []
    duplicate_count = 0

    for rec in records:
        try:
            index, nonce, ciphertext, tag = unpack_record(rec)
        except Exception:
            # Corrupted framing
            continue

        if index < 0 or index >= total_blocks:
            # Index out of bounds
            continue

        if index in accepted_indices:
            # Duplicate record received: keep first authentic, ignore later copies
            duplicate_count += 1
            continue

        expected_aad = build_aad(index, h, w, total_blocks, epoch)
        try:
            pt = aesgcm.decrypt(nonce, ciphertext + tag, expected_aad)
            block = np.frombuffer(pt, dtype=np.uint8).reshape(block_shape)
            decrypted_blocks[index] = block
            accepted_indices.add(index)
        except InvalidTag:
            failed_indices.append(index)
            decrypted_blocks[index] = np.zeros(block_shape, dtype=np.uint8)

    # Detect missing blocks (packets dropped in transit or truncated stream)
    missing_indices = [i for i in range(total_blocks) if (i not in accepted_indices and i not in failed_indices)]

    failed_count = len(failed_indices)
    missing_count = len(missing_indices)
    authentic_count = len(accepted_indices)
    all_unusable = sorted(failed_indices + missing_indices)
    unusable_count = len(all_unusable)
    failed_fraction = unusable_count / total_blocks if total_blocks > 0 else 0.0

    concealment_mask = np.zeros((grid_rows, grid_cols), dtype=bool)
    for idx in all_unusable:
        r = idx // grid_cols
        col = idx % grid_cols
        concealment_mask[r, col] = True

    concealment_applied = False
    action = ACTION_AUTHENTIC

    if unusable_count > 0:
        if failed_fraction > concealment_tau:
            action = ACTION_REJECTED_OVER_THRESHOLD
            concealment_applied = False
        else:
            if enable_concealment:
                decrypted_blocks = conceal_failed_blocks(
                    decrypted_blocks, all_unusable, (grid_rows, grid_cols), block_shape
                )
                concealment_applied = True
                action = ACTION_CONCEALED
            else:
                action = ACTION_DETECTED_AND_QUARANTINED
    elif duplicate_count > 0:
        action = ACTION_DUPLICATE_IGNORED

    return {
        'blocks': decrypted_blocks,
        'authentic_blocks': authentic_count,
        'failed_blocks': failed_count,
        'missing_blocks': missing_count,
        'failed_count': failed_count,
        'missing_count': missing_count,
        'duplicate_blocks_ignored': duplicate_count,
        'concealed_block_mask': concealment_mask,
        'failed_fraction': failed_fraction,
        'action': action,
        'failed_indices': failed_indices,
        'missing_indices': missing_indices,
        'concealment_applied': concealment_applied,
        'concealment_mask': concealment_mask  # backward compatibility alias
    }

def receive_and_decrypt_stream(header_bytes: bytes, records: list[bytes],
                               receiver_priv: x25519.X25519PrivateKey,
                               passphrase: str, device_id: str,
                               sender_id: str = "default_sender",
                               enable_concealment: bool = True,
                               tau: float = DEFAULT_TAU,
                               persist_epoch: bool = False,
                               iterations: int = None) -> dict:
    """End-to-end receiver pipeline executing full authentication gates:
    1. Parse and validate 134-byte session header
    2. Check receiver key fingerprint & DRL
    3. Verify epoch monotonicity
    4. Compute X25519 shared secret and two-factor KDF
    5. Verify HMAC in constant time BEFORE processing any block
    6. Decrypt and conceal blocks
    """
    empty_mask = np.zeros((1, 1), dtype=bool)
    failure_result = {
        'blocks': [],
        'authentic_blocks': 0,
        'failed_blocks': 0,
        'missing_blocks': 0,
        'duplicate_blocks_ignored': 0,
        'concealed_block_mask': empty_mask,
        'failed_fraction': 1.0,
        'action': ACTION_SESSION_REJECTED,
        'failed_indices': [],
        'missing_indices': [],
        'concealment_applied': False,
        'concealment_mask': empty_mask
    }

    # 1. Header parsing
    try:
        parsed = parse_session_header_fields(header_bytes)
    except HeaderAuthenticationError:
        return failure_result

    # 2. Receiver fingerprint check
    local_pub = receiver_priv.public_key()
    local_fingerprint = get_key_fingerprint(local_pub)
    if parsed['receiver_fingerprint'] != local_fingerprint:
        return failure_result

    if is_fingerprint_revoked(local_fingerprint) or is_device_revoked(device_id):
        return failure_result

    # 3. Epoch monotonicity check (READ-ONLY before HMAC)
    epoch = parsed['epoch']
    if not check_epoch_monotonicity(sender_id, epoch, persist=persist_epoch):
        return failure_result

    # 4. Key derivation
    try:
        eph_pub_obj = x25519.X25519PublicKey.from_public_bytes(parsed['eph_pub'])
        shared_secret = receiver_priv.exchange(eph_pub_obj)
        rx_pub_bytes = local_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        
        iter_count = iterations if iterations is not None else PBKDF2_ITERATIONS
        k_aes, k_hdr, _ = derive_session_keys(
            shared_secret, parsed['eph_pub'], rx_pub_bytes,
            parsed['salt_hkdf'], parsed['salt_pbkdf2'],
            passphrase, device_id, epoch, iterations=iter_count
        )
    except Exception:
        return failure_result

    # 5. Header HMAC verification in constant time
    try:
        verify_session_header_hmac(parsed['header_body'], parsed['hmac_tag'], k_hdr)
    except HeaderAuthenticationError:
        return failure_result

    # 5b. Commit epoch update atomically ONLY after HMAC verification passes
    commit_epoch(sender_id, epoch, persist=persist_epoch)

    # 6. Decrypt payload blocks
    image_shape = (parsed['height'], parsed['width'], 3)
    block_shape = (BLOCK_SIZE, BLOCK_SIZE, 3)
    total_blocks = parsed['total_blocks']

    return decrypt_blocks(
        records, k_aes, image_shape, block_shape, total_blocks,
        epoch=epoch, enable_concealment=enable_concealment, concealment_tau=tau
    )
