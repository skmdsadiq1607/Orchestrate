import pandas as pd
import json

sample_out = pd.read_csv("dataset/sample_output.csv")
sa = pd.read_csv("dataset/system_activity.csv")

sa_resources = set(sa['resource_id'].dropna())
# Also check details column
sa_details_text = " ".join(sa['details'].dropna().tolist())

all_steps = []
missing_in_sa_col = []
missing_in_sa_anywhere = []

for idx, r in sample_out.iterrows():
    steps = json.loads(r['steps_json'])
    for s in steps:
        res = s['resource_id']
        all_steps.append((r['case_id'], res, s['system_id'], s['operation']))
        if res not in sa_resources:
            missing_in_sa_col.append((r['case_id'], res))
            if res not in sa_details_text:
                missing_in_sa_anywhere.append((r['case_id'], res, s['system_id']))

print(f"Total steps across 32 sample cases: {len(all_steps)}")
print(f"Unique resources in sample outputs: {len(set(x[1] for x in all_steps))}")
print(f"Missing directly in sa['resource_id']: {len(missing_in_sa_col)}")
print(f"Missing in sa anywhere (including details): {len(missing_in_sa_anywhere)}")
if missing_in_sa_anywhere:
    print("Missing resources:")
    for c, res, sys_id in missing_in_sa_anywhere:
        print(f"  {c}: {res} ({sys_id})")
