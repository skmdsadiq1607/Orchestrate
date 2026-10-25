import os
import pandas as pd

manifest = pd.read_csv("dataset/evidence_files.csv")
targets = ['user_06', 'jonas.berg@outlook.com', 'Jonas Berg', 'search_001', 'account_006']

print("Searching for user_06 / jonas.berg across all evidence files...")
found_files = []
for idx, r in manifest.iterrows():
    p = os.path.join("dataset", r['file_path'])
    if not os.path.exists(p):
        continue
    # check text/sql/log/json
    if any(p.endswith(ext) for ext in ['.txt', '.sql', '.log', '.json']):
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            t = f.read()
            matched = [target for target in targets if target in t]
            if matched:
                found_files.append((r['file_id'], r['captured_at'], r['origin'], r['file_path'], matched))

for fid, cap, orig, fpath, m in found_files:
    print(f"{fid} ({cap}) [{orig}]: matched {m}")
