import json
import numpy as np

with open('results/crypto_metrics_cbc.json', 'r') as f:
    data = json.load(f)

print(f"Number of images in crypto_metrics_cbc.json: {len(data)}")
images = [d['image'] for d in data]
print("Images:", images)

entropies = [d['cipher_entropy_overall'] for d in data]
npcrs = [d['npcr_mean'] for d in data]
uacis = [d['uaci_mean'] for d in data]

print(f"Mean Cipher Entropy over 6 images: {np.mean(entropies):.4f}")
print(f"Mean NPCR over 6 images: {np.mean(npcrs):.2f}%")
print(f"Mean UACI over 6 images: {np.mean(uacis):.2f}%")
