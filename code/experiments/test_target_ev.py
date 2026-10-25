import json

# Check case_12: minjun.kim@gmail.com / user_12 / analytics_9914
target = "analytics_9914"

with open("dataset/evidence/logs/service_events_ap_south_20260915.log", "r", encoding="utf-8") as f:
    in_ev01 = target in f.read()

with open("dataset/evidence/records/service_resource_export_20260915_114455.json", "r", encoding="utf-8") as f:
    in_ev92 = target in f.read()

with open("dataset/evidence/records/customer_data_snapshot_bundle_20260915.json", "r", encoding="utf-8") as f:
    in_ev51 = target in f.read()

print(f"{target} in evidence_01: {in_ev01}")
print(f"{target} in evidence_92: {in_ev92}")
print(f"{target} in evidence_51: {in_ev51}")
