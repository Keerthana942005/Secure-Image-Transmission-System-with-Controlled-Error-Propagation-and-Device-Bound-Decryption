import json

with open('results/security_tests.json', 'r') as f:
    data = json.load(f)

print(f"Total vectors: {len(data)}")
total_trials = 0
for idx, v in enumerate(data, start=1):
    scenario = v.get('attack_scenario')
    trials = v.get('trials', 0)
    det_rate = v.get('detection_rate_pct', 0.0)
    action = v.get('observed_action')
    mechanism = v.get('detection_mechanism')
    total_trials += trials
    print(f"  T{idx:02d} | {scenario:<45} | Trials: {trials} | Det: {det_rate}% | Action: {action}")

print(f"Total trials across all vectors: {total_trials}")
