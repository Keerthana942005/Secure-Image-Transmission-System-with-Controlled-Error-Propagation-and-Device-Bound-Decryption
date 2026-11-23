import numpy as np

try:
    import cv2
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False

def conceal_failed_blocks(decrypted_blocks: list[np.ndarray], failed_indices: list[int], 
                           grid_shape: tuple[int, int], block_shape: tuple[int, int, int],
                           tau: float = 1.0, return_mask: bool = False):
    """Applies boundary-directed spatial interpolation to reconstruct corrupted or missing blocks
    from verified orthogonal neighbors, matching Eq. (10) and Eq. (11).
    
    Weights:
      w_top(y)    = (bh - y) / bh
      w_bottom(y) = (y + 1) / bh
      w_left(x)   = (bw - x) / bw
      w_right(x)  = (x + 1) / bw
      
    Fallback: If all 4 orthogonal neighbors are unverified, uses 8-neighborhood diagonal average.
    
    Args:
      decrypted_blocks: List of decrypted block numpy arrays.
      failed_indices: List of integer block indices that failed verification or were missing.
      grid_shape: (n_rows, n_cols) grid dimensions.
      block_shape: (bh, bw, channels) block dimensions.
      tau: Threshold fraction of failed blocks above which concealment refuses to output.
      return_mask: If True, returns (concealed_blocks, concealed_block_mask).
           
    Returns:
      concealed_blocks (or tuple if return_mask=True).
    """
    n_rows, n_cols = grid_shape
    total_blocks = n_rows * n_cols
    failed_fraction = len(failed_indices) / float(total_blocks) if total_blocks > 0 else 0.0
    
    concealed_mask = np.zeros(grid_shape, dtype=bool)
    for idx in failed_indices:
        r = idx // n_cols
        c = idx % n_cols
        if 0 <= r < n_rows and 0 <= c < n_cols:
            concealed_mask[r, c] = True
            
    if failed_fraction > tau:
        raise ValueError(f"Corruption fraction ({failed_fraction:.2%}) exceeds recovery threshold tau ({tau:.2%}).")

    bh, bw, channels = block_shape
    concealed = [b.copy() for b in decrypted_blocks]
    failed_set = set(failed_indices)
    
    # Precompute 1D weight vectors
    y_idx = np.arange(bh, dtype=np.float64)
    x_idx = np.arange(bw, dtype=np.float64)
    w_top_vec = ((bh - y_idx) / float(bh))[:, None, None]       # (bh, 1, 1)
    w_bottom_vec = ((y_idx + 1.0) / float(bh))[:, None, None]   # (bh, 1, 1)
    w_left_vec = ((bw - x_idx) / float(bw))[None, :, None]       # (1, bw, 1)
    w_right_vec = ((x_idx + 1.0) / float(bw))[None, :, None]    # (1, bw, 1)
    
    for idx in sorted(failed_indices):
        r = idx // n_cols
        c = idx % n_cols
        
        neighbors = []
        
        # 1. Top neighbor
        if r > 0 and (idx - n_cols) not in failed_set:
            top_block = concealed[idx - n_cols]
            top_edge = top_block[-1, :, :]  # bottom boundary of top block
            neighbors.append(('top', top_edge))
            
        # 2. Bottom neighbor
        if r < n_rows - 1 and (idx + n_cols) not in failed_set:
            bottom_block = concealed[idx + n_cols]
            bottom_edge = bottom_block[0, :, :]  # top boundary of bottom block
            neighbors.append(('bottom', bottom_edge))
            
        # 3. Left neighbor
        if c > 0 and (idx - 1) not in failed_set:
            left_block = concealed[idx - 1]
            left_edge = left_block[:, -1, :]  # right boundary of left block
            neighbors.append(('left', left_edge))
            
        # 4. Right neighbor
        if c < n_cols - 1 and (idx + 1) not in failed_set:
            right_block = concealed[idx + 1]
            right_edge = right_block[:, 0, :]  # left boundary of right block
            neighbors.append(('right', right_edge))
            
        recon = np.zeros(block_shape, dtype=np.float64)
        weight_sum = np.zeros(block_shape, dtype=np.float64)
        
        if len(neighbors) == 0:
            diag_samples = []
            for dr, dc in [(-1,-1), (-1,1), (1,-1), (1,1)]:
                nr, nc = r + dr, c + dc
                n_idx = nr * n_cols + nc
                if 0 <= nr < n_rows and 0 <= nc < n_cols and n_idx not in failed_set:
                    diag_samples.append(np.mean(concealed[n_idx], axis=(0, 1)))
            if diag_samples:
                mean_val = np.mean(diag_samples, axis=0)
                recon[:] = mean_val
                concealed[idx] = np.clip(np.round(recon), 0, 255).astype(np.uint8)
            continue
            
        # Vectorized directional boundary weighting
        for direction, edge in neighbors:
            edge_f = edge.astype(np.float64)
            if direction == 'top':
                recon += edge_f[None, :, :] * w_top_vec
                weight_sum += w_top_vec
            elif direction == 'bottom':
                recon += edge_f[None, :, :] * w_bottom_vec
                weight_sum += w_bottom_vec
            elif direction == 'left':
                recon += edge_f[:, None, :] * w_left_vec
                weight_sum += w_left_vec
            elif direction == 'right':
                recon += edge_f[:, None, :] * w_right_vec
                weight_sum += w_right_vec
                    
        weight_sum[weight_sum == 0] = 1.0
        concealed[idx] = np.clip(np.round(recon / weight_sum), 0, 255).astype(np.uint8)
        
    if return_mask:
        return concealed, concealed_mask
    return concealed

def mean_color_fill(decrypted_blocks: list[np.ndarray], failed_indices: list[int],
                    grid_shape: tuple[int, int], block_shape: tuple[int, int, int]) -> list[np.ndarray]:
    """Baseline: Replaces failed blocks with average color of valid neighbors."""
    n_rows, n_cols = grid_shape
    filled = [b.copy() for b in decrypted_blocks]
    failed_set = set(failed_indices)
    
    valid_blocks = [b for i, b in enumerate(decrypted_blocks) if i not in failed_set]
    global_mean = np.mean(valid_blocks, axis=(0, 1, 2)) if valid_blocks else np.zeros(block_shape[2])
    
    for idx in failed_indices:
        r = idx // n_cols
        c = idx % n_cols
        neighbor_means = []
        for dr, dc in [(-1, 0), (1, 0), (0, -1), (0, 1)]:
            nr, nc = r + dr, c + dc
            n_idx = nr * n_cols + nc
            if 0 <= nr < n_rows and 0 <= nc < n_cols and n_idx not in failed_set:
                neighbor_means.append(np.mean(filled[n_idx], axis=(0, 1)))
        if neighbor_means:
            m = np.mean(neighbor_means, axis=0)
        else:
            m = global_mean
        filled[idx] = np.full(block_shape, np.round(m), dtype=np.uint8)
    return filled

def inpaint_telea(image: np.ndarray, mask: np.ndarray, radius: int = 3) -> np.ndarray:
    """Baseline: Alexandru Telea Fast Marching Inpainting."""
    if HAS_CV2:
        return cv2.inpaint(image, mask.astype(np.uint8) * 255, inpaintRadius=radius, flags=cv2.INPAINT_TELEA)
    return image.copy()

def inpaint_navier_stokes(image: np.ndarray, mask: np.ndarray, radius: int = 3) -> np.ndarray:
    """Baseline: Navier-Stokes Fluid Dynamics Inpainting (Bertalmio et al.)."""
    if HAS_CV2:
        return cv2.inpaint(image, mask.astype(np.uint8) * 255, inpaintRadius=radius, flags=cv2.INPAINT_NS)
    return image.copy()
