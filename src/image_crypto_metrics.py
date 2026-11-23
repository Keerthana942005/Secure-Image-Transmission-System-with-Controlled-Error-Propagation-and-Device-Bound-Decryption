import numpy as np

def calculate_entropy(image_array: np.ndarray) -> dict:
    """Calculates Shannon Information Entropy of an image array.
    Returns overall entropy, per-channel entropy, and sample size theoretical upper bound.
    """
    flat = image_array.flatten()
    total_pixels = len(flat)
    if total_pixels == 0:
        return {'overall': 0.0, 'channels': [], 'max_theoretical': 8.0}
        
    _, counts = np.unique(flat, return_counts=True)
    probs = counts / float(total_pixels)
    overall_h = -np.sum(probs * np.log2(probs))
    
    channel_entropies = []
    if image_array.ndim == 3:
        for c in range(image_array.shape[2]):
            c_flat = image_array[:, :, c].flatten()
            _, c_counts = np.unique(c_flat, return_counts=True)
            c_probs = c_counts / float(len(c_flat))
            channel_entropies.append(float(-np.sum(c_probs * np.log2(c_probs))))
            
    # Max possible entropy given finite distinct intensity levels (up to 256)
    max_h = np.log2(min(256, total_pixels))
    
    return {
        'overall': float(overall_h),
        'channels': channel_entropies,
        'max_theoretical': float(max_h)
    }

def calculate_npcr(c1: np.ndarray, c2: np.ndarray) -> float:
    """Number of Pixels Change Rate (NPCR) in percentage.
    Ideal theoretical expectation for uniform 8-bit randomness is ~99.6094%.
    """
    assert c1.shape == c2.shape, f"Shapes must match: {c1.shape} vs {c2.shape}"
    diff = (c1 != c2).astype(np.float64)
    return float((np.sum(diff) / diff.size) * 100.0)

def calculate_uaci(c1: np.ndarray, c2: np.ndarray) -> float:
    """Unified Average Changing Intensity (UACI) in percentage.
    Ideal theoretical expectation for uniform 8-bit randomness is ~33.4635%.
    """
    assert c1.shape == c2.shape, f"Shapes must match: {c1.shape} vs {c2.shape}"
    diff_abs = np.abs(c1.astype(np.float64) - c2.astype(np.float64))
    return float((np.sum(diff_abs) / (diff_abs.size * 255.0)) * 100.0)

def calculate_correlation(image_array: np.ndarray, seed: int = 42, num_samples: int = 4000) -> dict:
    """Adjacent pixel correlation along Horizontal, Vertical, and Diagonal directions.
    Uses a fixed seed for exact reproducibility across runs.
    """
    arr = image_array.astype(np.float64)
    if arr.ndim == 3:
        # Standard luminance conversion for RGB correlation
        arr = 0.2989 * arr[:, :, 0] + 0.5870 * arr[:, :, 1] + 0.1140 * arr[:, :, 2]
        
    h, w = arr.shape
    rng = np.random.RandomState(seed)
    
    # 1. Horizontal: (y, x) and (y, x+1)
    if w > 1:
        n_pairs = min(num_samples, h * (w - 1))
        x_coords = rng.randint(0, w - 1, size=n_pairs)
        y_coords = rng.randint(0, h, size=n_pairs)
        x_vals = arr[y_coords, x_coords]
        y_vals = arr[y_coords, x_coords + 1]
        r_h = float(np.corrcoef(x_vals, y_vals)[0, 1]) if (np.std(x_vals) > 0 and np.std(y_vals) > 0) else 0.0
    else:
        r_h = 0.0

    # 2. Vertical: (y, x) and (y+1, x)
    if h > 1:
        n_pairs = min(num_samples, (h - 1) * w)
        x_coords = rng.randint(0, w, size=n_pairs)
        y_coords = rng.randint(0, h - 1, size=n_pairs)
        x_vals = arr[y_coords, x_coords]
        y_vals = arr[y_coords + 1, x_coords]
        r_v = float(np.corrcoef(x_vals, y_vals)[0, 1]) if (np.std(x_vals) > 0 and np.std(y_vals) > 0) else 0.0
    else:
        r_v = 0.0

    # 3. Diagonal: (y, x) and (y+1, x+1)
    if h > 1 and w > 1:
        n_pairs = min(num_samples, (h - 1) * (w - 1))
        x_coords = rng.randint(0, w - 1, size=n_pairs)
        y_coords = rng.randint(0, h - 1, size=n_pairs)
        x_vals = arr[y_coords, x_coords]
        y_vals = arr[y_coords + 1, x_coords + 1]
        r_d = float(np.corrcoef(x_vals, y_vals)[0, 1]) if (np.std(x_vals) > 0 and np.std(y_vals) > 0) else 0.0
    else:
        r_d = 0.0

    return {
        'horizontal': float(r_h),
        'vertical': float(r_v),
        'diagonal': float(r_d)
    }

def calculate_psnr(orig: np.ndarray, recon: np.ndarray) -> float:
    """Peak Signal-to-Noise Ratio (PSNR) in dB."""
    orig_f = orig.astype(np.float64)
    recon_f = recon.astype(np.float64)
    mse = np.mean((orig_f - recon_f) ** 2)
    if mse == 0:
        return float("inf")
    return float(10.0 * np.log10((255.0 ** 2) / mse))

def calculate_ssim(img1: np.ndarray, img2: np.ndarray) -> float:
    """Mean Structural Similarity Index (SSIM) across channels."""
    img1_f = img1.astype(np.float64)
    img2_f = img2.astype(np.float64)
    
    c1 = (0.01 * 255.0) ** 2
    c2 = (0.03 * 255.0) ** 2
    
    def _channel_ssim(c1_arr, c2_arr):
        mu1 = np.mean(c1_arr)
        mu2 = np.mean(c2_arr)
        # Use population variance and covariance for exact identity when c1_arr == c2_arr
        sigma1_sq = np.mean((c1_arr - mu1) ** 2)
        sigma2_sq = np.mean((c2_arr - mu2) ** 2)
        sigma12 = np.mean((c1_arr - mu1) * (c2_arr - mu2))
        
        num = (2 * mu1 * mu2 + c1) * (2 * sigma12 + c2)
        den = (mu1 ** 2 + mu2 ** 2 + c1) * (sigma1_sq + sigma2_sq + c2)
        return num / den
        
    if img1_f.ndim == 3:
        ssims = [_channel_ssim(img1_f[:, :, c], img2_f[:, :, c]) for c in range(img1_f.shape[2])]
        return float(np.mean(ssims))
    else:
        return float(_channel_ssim(img1_f, img2_f))

def calculate_chi_square(image_array: np.ndarray) -> float:
    """Chi-square goodness-of-fit test statistic against uniform distribution (0..255).
    For significance alpha=0.05 with df=255, critical value is 293.25.
    A chi-square value < 293.25 indicates uniform distribution.
    """
    flat = image_array.flatten()
    n = len(flat)
    counts = np.bincount(flat, minlength=256)
    expected = n / 256.0
    chi_sq = np.sum((counts - expected) ** 2 / expected)
    return float(chi_sq)
