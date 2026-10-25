import json

print("=== connector_configurations_20260812.json ===")
with open("dataset/evidence/records/connector_configurations_20260812.json", "r") as f:
    d = json.load(f)
    print(json.dumps(d, indent=2)[:500])

print("\n=== customer_export_manifest_20260409.json ===")
with open("dataset/evidence/records/customer_export_manifest_20260409.json", "r") as f:
    d = json.load(f)
    print(json.dumps(d, indent=2)[:500])

print("\n=== search_index_diagnostic_20260906.log ===")
with open("dataset/evidence/logs/search_index_diagnostic_20260906.log", "r") as f:
    lines = f.readlines()
    for l in lines[:10]:
        print(l.strip())

print("\n=== customer_data_snapshot_bundle sample ===")
with open("dataset/evidence/records/customer_data_snapshot_bundle_20260915.json", "r") as f:
    d = json.load(f)
    if isinstance(d, dict):
        print("Keys:", d.keys())
        for k in list(d.keys())[:3]:
            print(f"  {k}:", str(d[k])[:150])
