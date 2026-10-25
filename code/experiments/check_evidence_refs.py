import glob
import json

print("=== Checking service_resource_export files ===")
for p in glob.glob("dataset/evidence/records/service_resource_export_*.json"):
    with open(p, "r", encoding="utf-8") as f:
        d = json.load(f)
    se = d.get('service_exports', {})
    total_items = 0
    with_ref = 0
    for s_name, s_val in se.items():
        for k, v in s_val.items():
            if isinstance(v, list):
                for item in v:
                    total_items += 1
                    # check if any reference exists
                    ref = (item.get('customer_reference') or item.get('customer_email') or 
                           item.get('subject_reference') or item.get('owner_email') or 
                           item.get('requester_email') or item.get('query') or item.get('lookup_key'))
                    if ref:
                        with_ref += 1
    print(f"{p}: total={total_items}, with_ref={with_ref}")
