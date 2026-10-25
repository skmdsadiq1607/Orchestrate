import os
import glob
import pandas as pd

target_id = "account_7566"
print(f"Searching for {target_id}...")

# Check system_activity.csv
sa = pd.read_csv("dataset/system_activity.csv")
matches_sa = sa[(sa['resource_id'] == target_id) | (sa['details'].str.contains(target_id, na=False))]
if len(matches_sa) > 0:
    print("Found in system_activity.csv:")
    print(matches_sa[['activity_id', 'event_time', 'event_type', 'resource_id', 'reported_result', 'details']])

# Check all evidence files
for root, dirs, files in os.walk("dataset/evidence"):
    for f in files:
        fpath = os.path.join(root, f)
        # Check text/sql/log/json
        if any(fpath.endswith(ext) for ext in ['.txt', '.sql', '.log', '.json']):
            try:
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fp:
                    content = fp.read()
                    if target_id in content:
                        print(f"Found in evidence: {fpath}")
            except Exception as e:
                pass
