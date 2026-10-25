import json

with open("dataset/evidence/records/customer_data_snapshot_bundle_20260915.json", "r") as f:
    d = json.load(f)

for s in d['snapshots']:
    if s.get('data_store') == 'identity_service':
        for r in s['records']:
            print(r)
