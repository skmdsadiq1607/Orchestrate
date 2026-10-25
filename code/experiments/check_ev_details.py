import json
import re

print("--- Checking evidence_03 (handover txt) ---")
with open("dataset/evidence/records/customer_account_handover_20261001.txt", "r", encoding="utf-8") as f:
    for line in f:
        if "4248" in line or "9394" in line or "2034" in line or "052" in line or "864" in line or "9522" in line:
            print(" ", line.strip())

print("\n--- Checking evidence_51 (bundle 20260915) ---")
with open("dataset/evidence/records/customer_data_snapshot_bundle_20260915.json", "r", encoding="utf-8") as f:
    d = json.load(f)
for snap in d['snapshots']:
    for rec in snap['records']:
        t = str(rec)
        if "4857" in t or "8858" in t or "user_541" in t or "user_542" in t:
            print(" ", snap['data_store'], rec)
