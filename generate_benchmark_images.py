import os
import shutil
import numpy as np
from PIL import Image

def generate_datasets():
    input_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'input')
    os.makedirs(input_dir, exist_ok=True)
    
    # 1. Submarine image (original)
    sub_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'submarine.jpg')
    sub_dst = os.path.join(input_dir, 'submarine.jpg')
    if os.path.exists(sub_src):
        shutil.copy(sub_src, sub_dst)
        print("Copied submarine.jpg to input/")
        
    # 2. High-contrast profile (256x256) - Cameraman representation
    h, w = 256, 256
    cam = np.zeros((h, w, 3), dtype=np.uint8)
    cam[:140, :] = [180, 200, 220]  # sky
    cam[140:, :] = [70, 90, 60]    # ground
    # silhouette
    cam[80:200, 100:150] = [30, 30, 30]
    cam[50:85, 115:135] = [40, 40, 40]
    cam[70:120, 140:190] = [20, 20, 20]  # tripod/camera
    Image.fromarray(cam).save(os.path.join(input_dir, 'cameraman_256.png'))
    print("Generated cameraman_256.png")

    # 3. High-frequency texture (512x512) - Baboon representation
    h, w = 512, 512
    np.random.seed(42)
    # create textured patterns with sine waves and high frequency harmonics
    x = np.linspace(0, 10 * np.pi, w)
    y = np.linspace(0, 10 * np.pi, h)
    xx, yy = np.meshgrid(x, y)
    tex_r = (np.sin(xx) * np.cos(yy) * 60 + 128 + np.random.normal(0, 25, (h, w))).clip(0, 255).astype(np.uint8)
    tex_g = (np.sin(xx * 1.5) * 50 + 128 + np.random.normal(0, 25, (h, w))).clip(0, 255).astype(np.uint8)
    tex_b = (np.cos(yy * 2.0) * 70 + 128 + np.random.normal(0, 25, (h, w))).clip(0, 255).astype(np.uint8)
    baboon = np.stack([tex_r, tex_g, tex_b], axis=-1)
    Image.fromarray(baboon).save(os.path.join(input_dir, 'baboon_texture_512.png'))
    print("Generated baboon_texture_512.png")

    # 4. Smooth multi-color gradient (512x512) - Peppers representation
    peppers = np.zeros((512, 512, 3), dtype=np.uint8)
    for i in range(512):
        for j in range(512):
            peppers[i, j, 0] = int(200 * np.sin(i / 80.0) ** 2 + 50)
            peppers[i, j, 1] = int(180 * np.cos(j / 70.0) ** 2 + 40)
            peppers[i, j, 2] = int(120 * np.sin((i + j) / 100.0) ** 2 + 30)
    Image.fromarray(peppers).save(os.path.join(input_dir, 'peppers_color_512.png'))
    print("Generated peppers_color_512.png")

    # 5. Medical MRI slice (512x512)
    mri = np.zeros((512, 512, 3), dtype=np.uint8)
    cy, cx = 256, 256
    y, x = np.ogrid[:512, :512]
    dist_from_center = np.sqrt((x - cx) ** 2 + (y - cy) ** 2)
    # skull bone
    skull_mask = (dist_from_center < 200) & (dist_from_center > 185)
    brain_mask = dist_from_center <= 185
    ventricle_mask = (dist_from_center < 50) & (np.abs(x - cx) < 25)
    
    mri[skull_mask] = 230
    brain_tissue = (140 + 30 * np.sin(x / 15.0) * np.cos(y / 15.0)).clip(0, 255).astype(np.uint8)
    mri[brain_mask] = np.stack([brain_tissue[brain_mask]] * 3, axis=-1)
    mri[ventricle_mask] = 20  # dark fluid
    Image.fromarray(mri).save(os.path.join(input_dir, 'medical_mri_512.png'))
    print("Generated medical_mri_512.png")

    # 6. Satellite Aerial terrain (1024x1024)
    h, w = 1024, 1024
    aerial = np.zeros((h, w, 3), dtype=np.uint8)
    x = np.linspace(0, 20 * np.pi, w)
    y = np.linspace(0, 20 * np.pi, h)
    xx, yy = np.meshgrid(x, y)
    elevation = (np.sin(xx / 3.0) + np.cos(yy / 3.0) + 0.5 * np.sin(xx) * np.cos(yy))
    aerial[:, :, 0] = ((elevation + 2.5) * 45).clip(0, 255).astype(np.uint8) # red/soil
    aerial[:, :, 1] = ((elevation + 2.5) * 55).clip(0, 255).astype(np.uint8) # green/vegetation
    aerial[:, :, 2] = ((elevation + 2.5) * 35).clip(0, 255).astype(np.uint8) # blue
    Image.fromarray(aerial).save(os.path.join(input_dir, 'satellite_aerial_1024.png'))
    print("Generated satellite_aerial_1024.png")

if __name__ == '__main__':
    generate_datasets()

