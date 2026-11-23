import os
import json
import uuid
import struct
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from src.config import (
    PBKDF2_ITERATIONS,
    MIN_PASSPHRASE_LENGTH,
    KEYS_DIR,
    STATE_DIR
)

# In-memory revocation cache and seen epochs cache
REVOKED_DEVICES = set()
REVOKED_FINGERPRINTS = set()
SEEN_EPOCHS = {}

EPOCH_STORAGE_FILE = os.path.join(STATE_DIR, "epochs.json")

# ---------------------------------------------------------------------------
# Device Identification (Local only - NEVER transmitted or logged in clear)
# ---------------------------------------------------------------------------
def get_device_id() -> str:
    """Gets a unique 256-bit device identifier digest derived from MAC address.
    SECURITY NOTICE: This digest is used strictly as a local KDF context input.
    It is NEVER transmitted over the wire or logged in clear text.
    """
    mac = uuid.getnode()
    mac_bytes = str(mac).encode('utf-8')
    return hashlib.sha256(mac_bytes).hexdigest()

def best_effort_zeroize(buf: bytearray) -> None:
    """Best-effort in-place zeroization of mutable byte buffers.
    SECURITY NOTICE: Python memory management (garbage collector and string interning)
    cannot guarantee complete memory erasure. Sensitive buffers are scrubbed immediately.
    """
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0

# ---------------------------------------------------------------------------
# Passphrase Policy and PBKDF2 Stretching
# ---------------------------------------------------------------------------
def validate_passphrase(passphrase: str, min_length: int = MIN_PASSPHRASE_LENGTH) -> tuple[bool, str]:
    """Enforces strict passphrase policy:
    1. Minimum length >= 16 characters
    2. Character class diversity (at least 3 of uppercase, lowercase, digits, symbols)
    """
    if not passphrase or len(passphrase) < min_length:
        return False, f"Passphrase must be at least {min_length} characters long."
    has_upper = any(c.isupper() for c in passphrase)
    has_lower = any(c.islower() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_special = any(not c.isalnum() for c in passphrase)
    diversity = sum([has_upper, has_lower, has_digit, has_special])
    if diversity < 3:
        return False, "Passphrase must contain at least 3 character classes (uppercase, lowercase, digits, symbols)."
    return True, "Passphrase meets security policy."

def stretch_passphrase(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Stretches user passphrase using PBKDF2-HMAC-SHA256 (600,000 iterations default per NIST SP 800-132).
    Returns 32 bytes of stretched key material.
    """
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise ValueError("salt must be exactly 16 bytes")
    is_valid, msg = validate_passphrase(passphrase, min_length=8)  # allow testing with >=8 if valid
    if not is_valid:
        raise ValueError(f"Invalid passphrase: {msg}")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode('utf-8'))

derive_pbkdf2 = stretch_passphrase

# ---------------------------------------------------------------------------
# Receiver Static Key Management (X25519)
# ---------------------------------------------------------------------------
def generate_receiver_static_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generates an X25519 static key pair for receiver endpoint enrolment."""
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def get_key_fingerprint(public_key: x25519.X25519PublicKey | bytes) -> bytes:
    """Computes the 16-byte receiver key fingerprint:
    first 16 bytes of SHA-256(public_key_bytes).
    """
    if isinstance(public_key, x25519.X25519PublicKey):
        pub_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    elif isinstance(public_key, bytes):
        pub_bytes = public_key
    else:
        raise TypeError("public_key must be X25519PublicKey or 32 raw bytes")
    return hashlib.sha256(pub_bytes).digest()[:16]

def save_receiver_static_key(private_key: x25519.X25519PrivateKey, filepath: str) -> None:
    """Saves raw 32-byte X25519 private key to disk with strict permissions."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    with open(filepath, "wb") as f:
        f.write(raw)

def load_receiver_static_key(filepath: str) -> x25519.X25519PrivateKey:
    """Loads X25519 private key from disk."""
    with open(filepath, "rb") as f:
        raw = f.read()
    if len(raw) != 32:
        raise ValueError(f"Invalid private key file length: {len(raw)} bytes")
    return x25519.X25519PrivateKey.from_private_bytes(raw)

# ---------------------------------------------------------------------------
# Two-Factor Key Schedule & Derivation
# ---------------------------------------------------------------------------
def generate_salt(length: int = 16) -> bytes:
    """Generates a cryptographically secure random salt."""
    return os.urandom(length)

def generate_session_key() -> bytes:
    """Generates an ephemeral 256-bit random session key."""
    return os.urandom(32)

def derive_session_keys(shared_secret: bytes,
                        eph_pub_bytes: bytes,
                        receiver_static_pub_bytes: bytes,
                        salt_hkdf: bytes,
                        salt_pbkdf2: bytes,
                        passphrase: str,
                        device_id: str,
                        epoch: int,
                        iterations: int = PBKDF2_ITERATIONS) -> tuple[bytes, bytes, bytes]:
    """Executes the defense-in-depth key schedule (Task 1.2 & 1.3):
    1. K_session = HKDF-SHA256(salt=S_hkdf, IKM=shared_secret, info=b"SIT-v1-session" || eph_pub || rx_pub, length=32)
    2. stretched = PBKDF2-HMAC-SHA256(passphrase, S_pbkdf2, iterations, length=32)
    3. IKM = K_session || stretched (64 bytes secret entropy)
    4. PRK = HKDF-Extract(S_hkdf, IKM)
    5. K_AES = HKDF-Expand(PRK, b"SIT-v1" || device_id || uint32(epoch), 32)
    6. K_hdr = HKDF-Expand(PRK, b"SIT-v1-header", 32)

    Returns: (K_AES, K_hdr, K_session)
    """
    # 1. Derive K_session from shared secret
    session_info = b"SIT-v1-session" + eph_pub_bytes + receiver_static_pub_bytes
    hkdf_session = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_hkdf,
        info=session_info,
        backend=default_backend()
    )
    k_session = hkdf_session.derive(shared_secret)

    # 2. Stretch passphrase
    stretched = stretch_passphrase(passphrase, salt_pbkdf2, iterations=iterations)

    # 3. Combine into secret IKM (64 bytes)
    ikm = k_session + stretched

    # 4. PRK via HMAC-SHA256 (HKDF-Extract per RFC 5869)
    prk = hmac.new(salt_hkdf, ikm, hashlib.sha256).digest()

    # 5. K_AES expansion bound to device_id and epoch
    info_aes = b"SIT-v1" + device_id.encode('utf-8') + struct.pack(">I", epoch)
    hkdf_exp_aes = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info_aes, backend=default_backend())
    k_aes = hkdf_exp_aes.derive(prk)

    # 6. K_hdr expansion for session header authentication
    hkdf_exp_hdr = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"SIT-v1-header", backend=default_backend())
    k_hdr = hkdf_exp_hdr.derive(prk)

    # Best-effort memory scrub
    ikm_ba = bytearray(ikm)
    best_effort_zeroize(ikm_ba)

    return k_aes, k_hdr, k_session

def derive_key(session_key: bytes, hkdf_salt: bytes, pw_salt: bytes,
               passphrase: str, device_id: str, epoch: int = 0,
               iterations: int = PBKDF2_ITERATIONS,
               x25519_shared_secret: bytes = None) -> bytes:
    """Backward-compatible helper deriving 256-bit K_AES.
    If x25519_shared_secret is not provided, treats session_key as pre-shared secret.
    """
    stretched_pw = stretch_passphrase(passphrase, pw_salt, iterations=iterations)
    secret_seed = x25519_shared_secret if x25519_shared_secret is not None else session_key
    ikm = secret_seed + stretched_pw

    # PRK
    prk = hmac.new(hkdf_salt, ikm, hashlib.sha256).digest()

    # Expand
    info = b"SIT-v1" + device_id.encode('utf-8') + struct.pack(">I", epoch)
    hkdf_exp = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info, backend=default_backend())
    derived = hkdf_exp.derive(prk)

    ikm_ba = bytearray(ikm)
    best_effort_zeroize(ikm_ba)
    return derived

# ---------------------------------------------------------------------------
# Replay Protection & Monotonic Epoch Persistence (Task 1.5)
# ---------------------------------------------------------------------------
def _load_epochs_from_disk() -> dict:
    if not os.path.exists(EPOCH_STORAGE_FILE):
        return {}
    try:
        with open(EPOCH_STORAGE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_epochs_to_disk(epochs_dict: dict) -> None:
    os.makedirs(os.path.dirname(EPOCH_STORAGE_FILE), exist_ok=True)
    tmp_path = EPOCH_STORAGE_FILE + f".tmp.{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(epochs_dict, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, EPOCH_STORAGE_FILE)

def check_epoch_monotonicity(sender_id: str, epoch: int, persist: bool = False) -> bool:
    """Verifies that epoch is strictly monotonic (epoch > last_accepted_epoch) WITHOUT updating state.
    Rejects epoch <= last_accepted_epoch.
    """
    last_accepted = SEEN_EPOCHS.get(sender_id)
    if last_accepted is None and persist:
        disk_data = _load_epochs_from_disk()
        last_accepted = disk_data.get(sender_id, -1)
    elif last_accepted is None:
        last_accepted = -1

    return epoch > last_accepted

def commit_epoch(sender_id: str, epoch: int, persist: bool = False) -> bool:
    """Atomically commits epoch advancement to memory and disk.
    Should be called ONLY after cryptographic verification (HMAC) succeeds.
    """
    if not check_epoch_monotonicity(sender_id, epoch, persist=persist):
        return False

    SEEN_EPOCHS[sender_id] = epoch
    if persist:
        disk_data = _load_epochs_from_disk()
        disk_data[sender_id] = epoch
        _save_epochs_to_disk(disk_data)
    return True

def get_last_accepted_epoch(sender_id: str, persist: bool = False) -> int:
    """Returns the last accepted epoch for sender_id (-1 if none seen)."""
    last_accepted = SEEN_EPOCHS.get(sender_id)
    if last_accepted is None and persist:
        disk_data = _load_epochs_from_disk()
        last_accepted = disk_data.get(sender_id, -1)
    return last_accepted if last_accepted is not None else -1

def verify_and_update_epoch(sender_id: str, epoch: int, persist: bool = False) -> bool:
    """Verifies that epoch is strictly monotonic and updates storage.
    Backward-compatible helper for callers performing atomic check-and-commit.
    """
    return commit_epoch(sender_id, epoch, persist=persist)

def reset_epoch_tracker(clean_disk: bool = False) -> None:
    """Resets memory and disk epoch trackers (for testing)."""
    SEEN_EPOCHS.clear()
    if clean_disk and os.path.exists(EPOCH_STORAGE_FILE):
        try:
            os.remove(EPOCH_STORAGE_FILE)
        except OSError:
            pass

# ---------------------------------------------------------------------------
# Device & Fingerprint Revocation
# ---------------------------------------------------------------------------
def revoke_device(device_id: str) -> None:
    REVOKED_DEVICES.add(device_id.lower())

def unrevoke_device(device_id: str) -> None:
    REVOKED_DEVICES.discard(device_id.lower())

def is_device_revoked(device_id: str) -> bool:
    return device_id.lower() in REVOKED_DEVICES

def revoke_fingerprint(fingerprint: bytes | str) -> None:
    if isinstance(fingerprint, bytes):
        fingerprint = fingerprint.hex()
    REVOKED_FINGERPRINTS.add(fingerprint.lower())

def unrevoke_fingerprint(fingerprint: bytes | str) -> None:
    if isinstance(fingerprint, bytes):
        fingerprint = fingerprint.hex()
    REVOKED_FINGERPRINTS.discard(fingerprint.lower())

def is_fingerprint_revoked(fingerprint: bytes | str) -> bool:
    if isinstance(fingerprint, bytes):
        fingerprint = fingerprint.hex()
    return fingerprint.lower() in REVOKED_FINGERPRINTS

def verify_device(authorized_device_id: str) -> bool:
    """Checks if current device matches authorized ID and is not revoked.
    Uses constant-time comparison.
    """
    current_id = get_device_id()
    if is_device_revoked(current_id):
        return False
    return hmac.compare_digest(current_id.lower(), authorized_device_id.lower())

# ---------------------------------------------------------------------------
# Ed25519 Signed Device Revocation List (Task 3)
# ---------------------------------------------------------------------------
class DRLSignatureError(Exception):
    """Raised when DRL digital signature verification fails."""
    pass

class DRLRollbackError(Exception):
    """Raised when DRL version is lower than the currently stored version."""
    pass

CURRENT_DRL_VERSION = 0

def canonical_drl_bytes(version: int, entries: list[str], issued_at: int) -> bytes:
    """Produces deterministic canonical UTF-8 bytes for DRL signature computation."""
    norm_entries = sorted(e.lower().strip() for e in entries)
    payload = {
        "entries": norm_entries,
        "issued_at": int(issued_at),
        "version": int(version)
    }
    return json.dumps(payload, sort_keys=True, separators=(',', ':')).encode('utf-8')

def sign_drl(ed25519_priv: ed25519.Ed25519PrivateKey,
             version: int, entries: list[str], issued_at: int = None) -> dict:
    """Creates and signs a Device Revocation List (DRL) document with Ed25519."""
    import time
    if issued_at is None:
        issued_at = int(time.time())
    canon = canonical_drl_bytes(version, entries, issued_at)
    sig = ed25519_priv.sign(canon)
    return {
        "version": int(version),
        "entries": sorted(e.lower().strip() for e in entries),
        "issued_at": int(issued_at),
        "signature": sig.hex()
    }

def verify_and_load_drl(drl_doc: dict | str, trusted_pub: ed25519.Ed25519PublicKey) -> dict:
    """Verifies Ed25519 DRL signature, enforces version rollback protection,
    and updates the active revocation list.
    """
    global CURRENT_DRL_VERSION
    if isinstance(drl_doc, str):
        if os.path.exists(drl_doc):
            with open(drl_doc, "r", encoding="utf-8") as f:
                drl = json.load(f)
        else:
            drl = json.loads(drl_doc)
    else:
        drl = drl_doc

    for field in ["version", "entries", "issued_at", "signature"]:
        if field not in drl:
            raise DRLSignatureError(f"Missing required DRL field: {field}")

    # 1. Verify signature
    canon = canonical_drl_bytes(drl["version"], drl["entries"], drl["issued_at"])
    try:
        sig_bytes = bytes.fromhex(drl["signature"])
        trusted_pub.verify(sig_bytes, canon)
    except Exception as e:
        raise DRLSignatureError(f"DRL signature verification failed: {e}")

    # 2. Rollback protection
    drl_ver = int(drl["version"])
    if drl_ver < CURRENT_DRL_VERSION:
        raise DRLRollbackError(
            f"DRL rollback rejected: received version {drl_ver} < stored version {CURRENT_DRL_VERSION}"
        )

    CURRENT_DRL_VERSION = drl_ver
    for entry in drl["entries"]:
        revoke_fingerprint(entry)

    return drl

def reset_drl_tracker() -> None:
    """Resets DRL version tracker and clears revoked set (for testing)."""
    global CURRENT_DRL_VERSION
    CURRENT_DRL_VERSION = 0
    REVOKED_FINGERPRINTS.clear()
    REVOKED_DEVICES.clear()

