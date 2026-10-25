import json

print("=== security_audit_ledger_20261001.json ===")
with open("dataset/evidence/records/security_audit_ledger_20261001.json", "r") as f:
    d = json.load(f)
    print("Keys/len:", len(d) if isinstance(d, list) else d.keys())
    if isinstance(d, list):
        print(d[0])
    elif isinstance(d, dict):
        for k in list(d.keys())[:3]:
            print(k, str(d[k])[:100])

print("\n=== notification_delivery_20260315.log ===")
with open("dataset/evidence/logs/notification_delivery_20260315.log", "r") as f:
    for i in range(5):
        print(f.readline().strip())
