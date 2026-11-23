import json

with open('results/crypto_metrics.json', 'r') as f:
    data = json.load(f)

print("Keys in first image entry:", list(data[0].keys()))

all_r = []
for entry in data:
    img = entry['image']
    c_rh = entry.get('cipher_corr_h')
    c_rv = entry.get('cipher_corr_v')
    c_rd = entry.get('cipher_corr_d')
    p_rh = entry.get('plain_corr_h')
    p_rv = entry.get('plain_corr_v')
    p_rd = entry.get('plain_corr_d')
    print(f"\n{img}:")
    print(f"  Plain Entropy: {entry.get('plain_entropy')}, Cipher Entropy: {entry.get('cipher_entropy')}")
    print(f"  Entropy R/G/B: {entry.get('cipher_entropy_r')}, {entry.get('cipher_entropy_g')}, {entry.get('cipher_entropy_b')}")
    print(f"  Plain corr (H, V, D): {p_rh}, {p_rv}, {p_rd}")
    print(f"  Cipher corr (H, V, D): {c_rh}, {c_rv}, {c_rd}")
    print(f"  Chi-Square: {entry.get('chi_square_stat')} (pass: {entry.get('chi_square_pass')})")
    print(f"  NPCR fresh: {entry.get('npcr_fresh_mean')}% +/- {entry.get('npcr_fresh_std')}")
    print(f"  UACI fresh: {entry.get('uaci_fresh_mean')}% +/- {entry.get('uaci_fresh_std')}")
    print(f"  NPCR fixed: {entry.get('npcr_fixed_mean')}% +/- {entry.get('npcr_fixed_std')}")
    print(f"  UACI fixed: {entry.get('uaci_fixed_mean')}% +/- {entry.get('uaci_fixed_std')}")
    print(f"  Key sensitivity: {entry.get('key_sensitivity_npcr')}%")
    all_r.extend([(abs(c_rh), c_rh, img, 'H'), (abs(c_rv), c_rv, img, 'V'), (abs(c_rd), c_rd, img, 'D')])

max_r_item = max(all_r, key=lambda x: x[0])
print(f"\nMax |r| across all images: {max_r_item[0]:.4f} (actual value: {max_r_item[1]}, image: {max_r_item[2]}, direction: {max_r_item[3]})")

