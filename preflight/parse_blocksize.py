import json

with open('results/blocksize_tradeoff.json', 'r') as f:
    data = json.load(f)

for d in data:
    print(f"{d['block_size']:<6} | Area: {d['area_fraction_label']:<5} | PSNR_conc: {d['psnr_conc_mean']:<6} | SSIM_conc: {d['ssim_conc_mean']:<6} | Tput: {d['throughput_decimal_mbps']:<6} | Overhead: {d['analytical_overhead_pct']}%")

