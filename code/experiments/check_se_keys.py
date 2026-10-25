import json

with open("dataset/evidence/records/service_resource_export_20260915_114455.json", "r", encoding="utf-8") as f:
    data = json.load(f)

se = data['service_exports']
print("Services in export:", list(se.keys()))
for s, val in se.items():
    print(f"\n--- {s} ---")
    if isinstance(val, dict):
        for k2, v2 in val.items():
            print(f"  {k2}: type={type(v2)}, len={len(v2) if isinstance(v2, list) else 1}")
            if isinstance(v2, list) and len(v2) > 0:
                print(f"    sample[0]: {v2[0]}")
