import json

with open("dataset/evidence/records/customer_data_snapshot_bundle_20260915.json", "r") as f:
    d = json.load(f)

for s in d['snapshots']:
    print(f"data_store: {s.get('data_store')} | collection: {s.get('collection')} | records count: {len(s.get('records', []))}")
    if len(s.get('records', [])) > 0:
        print("  sample record:", s['records'][0])
