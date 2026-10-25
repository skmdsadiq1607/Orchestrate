import json

with open("dataset/evidence/records/service_resource_export_20260915_114455.json", "r", encoding="utf-8") as f:
    d = json.load(f)

se = d['service_exports']
sec = se.get('security_service', {}).get('audit_records', [])
print("Security records in evidence_92:")
for r in sec:
    print(" ", r)
