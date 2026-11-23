import json

with open('results/ml_downstream.json', 'r') as f:
    data = json.load(f)

print(f"Num images: {data.get('num_images')}")
print(f"Trials per level: {data.get('num_trials_per_level')}")
print(f"Num levels: {data.get('num_levels')}")
print(f"Total inferences: {data.get('total_inferences')}")
print(f"Total evaluations: {data.get('total_evaluations')}")

scenarios = set()
schemes = set()
levels = set()

for r in data.get('results', []):
    scenarios.add(r['scenario'])
    levels.add((r['corrupted_blocks'], r['corrupted_fraction_pct'], r['corruption_level']))

print("\nScenarios present:", scenarios)
print("Levels present:", sorted(list(levels), key=lambda x: x[0]))

print("\nSample S1 row at max corruption:")
for r in data.get('results', []):
    if r['scenario'] == 'S1_record_loss' and r['corrupted_blocks'] == 18:
        print(f"  Mono GCM: {r.get('mono_gcm_agreement_pct')}%")
        print(f"  CBC Unframed: {r.get('cbc_unframed_agreement_mean_pct')}% +/- {r.get('cbc_unframed_agreement_std_pct')}% (CI95: {r.get('cbc_unframed_ci95')})")
        print(f"  CBC Framed: {r.get('cbc_framed_agreement_mean_pct')}% +/- {r.get('cbc_framed_agreement_std_pct')}% (CI95: {r.get('cbc_framed_ci95')})")
        print(f"  Proposed Zero-Fill: {r.get('proposed_zero_agreement_mean_pct')}% +/- {r.get('proposed_zero_agreement_std_pct')}% (CI95: {r.get('proposed_zero_ci95')})")
        print(f"  Proposed Concealed: {r.get('proposed_conc_agreement_mean_pct')}% +/- {r.get('proposed_conc_agreement_std_pct')}% (CI95: {r.get('proposed_conc_ci95')})")
        print(f"  Gain over Zero-Fill: {r.get('gain_over_zero_pp')} pp")
        print(f"  Gain over Unframed CBC: {r.get('gain_over_cbc_pp')} pp")

print("\nSample S2 row at max corruption:")
for r in data.get('results', []):
    if r['scenario'] == 'S2_bit_flips' and r['corrupted_blocks'] == 18:
        print(f"  Mono GCM: {r.get('mono_gcm_agreement_pct')}%")
        print(f"  CBC Unframed: {r.get('cbc_unframed_agreement_mean_pct')}% +/- {r.get('cbc_unframed_agreement_std_pct')}% (CI95: {r.get('cbc_unframed_ci95')})")
        print(f"  CBC Framed: {r.get('cbc_framed_agreement_mean_pct')}% +/- {r.get('cbc_framed_agreement_std_pct')}% (CI95: {r.get('cbc_framed_ci95')})")
        print(f"  Proposed Zero-Fill: {r.get('proposed_zero_agreement_mean_pct')}% +/- {r.get('proposed_zero_agreement_std_pct')}% (CI95: {r.get('proposed_zero_ci95')})")
        print(f"  Proposed Concealed: {r.get('proposed_conc_agreement_mean_pct')}% +/- {r.get('proposed_conc_agreement_std_pct')}% (CI95: {r.get('proposed_conc_ci95')})")

