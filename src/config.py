import os

GLOBAL_SEED = 42
BLOCK_SIZE = 16  # 16x16 pixels
CHANNELS = 3     # RGB

# Framing dimensions
HEADER_INDEX_LEN = 4   # 4 bytes for uint32 block index
NONCE_LEN = 12          # 12 bytes for 96-bit AES-GCM IV
TAG_LEN = 16            # 16 bytes for 128-bit GHASH tag
AAD_LEN = 20            # index(4) + H(4) + W(4) + total_blocks(4) + epoch(4)

# Session Header Layout: 134 bytes total
# magic(4) || ver(1) || flags(1) || epoch(4) || H(4) || W(4) || N(4) ||
# S_hkdf(16) || S_pbkdf2(16) || eph_pub(32) || fingerprint(16) || HMAC(32)
SESSION_HEADER_LEN = 134
SESSION_HEADER_MAGIC = b"SIT1"
SESSION_HEADER_VERSION = 1

# Cryptographic and policy parameters
PBKDF2_ITERATIONS = 600_000
MIN_PASSPHRASE_LENGTH = 16
DEFAULT_TAU = 0.25

# Deterministic nonce mode flag (optional alternative, default False)
USE_DETERMINISTIC_NONCE = False

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC_DIR = os.path.join(BASE_DIR, 'src')
INPUT_DIR = os.path.join(BASE_DIR, 'input')
ENCRYPTED_DIR = os.path.join(BASE_DIR, 'encrypted')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
RECEIVED_DIR = os.path.join(BASE_DIR, 'received')
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
TABLES_DIR = os.path.join(BASE_DIR, 'tables')
FIGURES_DIR = os.path.join(BASE_DIR, 'figures')
MODELS_DIR = os.path.join(BASE_DIR, 'models')
KEYS_DIR = os.path.join(BASE_DIR, 'keys')
STATE_DIR = os.path.join(BASE_DIR, 'state')
DATA_DIR = os.path.join(BASE_DIR, 'data')

PACKAGE_PATH = os.path.join(ENCRYPTED_DIR, 'encrypted_package.pkl')

for p in [INPUT_DIR, ENCRYPTED_DIR, OUTPUT_DIR, RECEIVED_DIR, RESULTS_DIR, TABLES_DIR, FIGURES_DIR, MODELS_DIR, KEYS_DIR, STATE_DIR, DATA_DIR]:
    os.makedirs(p, exist_ok=True)
