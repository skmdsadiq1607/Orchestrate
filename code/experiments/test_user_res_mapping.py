import os
import re
import json
import pandas as pd
from test_identity_index import identity_by_user, user_by_email

print("Mapping account_id and audit_record_id for each user across all participant files...")

user_to_account = {}
user_to_audit_rec = {}
user_to_tombstone = {}

# 1. Check system_activity.csv
sa = pd.read_csv("dataset/system_activity.csv")
for idx, r in sa.iterrows():
    details = str(r['details'])
    res = str(r['resource_id'])
    # check for user_id in details
    u_match = re.search(r'user_\d+', details)
    if u_match:
        uid = u_match.group(0)
        if res.startswith('account_'):
            user_to_account[uid] = res
        elif res.startswith('audit_record_'):
            user_to_audit_rec[uid] = res
        elif res.startswith('tombstone_'):
            user_to_tombstone[uid] = res

# 2. Check customer_data_snapshot_bundle files
import glob
for p in glob.glob("dataset/evidence/records/customer_data_snapshot_bundle_*.json"):
    with open(p, "r", encoding="utf-8") as f:
        d = json.load(f)
    for snap in d.get('snapshots', []):
        for rec in snap.get('records', []):
            uid = rec.get('subject_reference') or rec.get('user_id')
            res = rec.get('resource_id')
            if uid and res:
                if res.startswith('account_'): user_to_account[uid] = res
                elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# 3. Check service_resource_export files
for p in glob.glob("dataset/evidence/records/service_resource_export_*.json"):
    with open(p, "r", encoding="utf-8") as f:
        d = json.load(f)
    se = d.get('service_exports', {})
    for rec in se.get('security_service', {}).get('audit_records', []):
        uid = rec.get('subject_reference')
        res = rec.get('resource_id')
        if uid and res: user_to_audit_rec[uid] = res
        
# 4. Check SQL files
for p in glob.glob("dataset/evidence/databases/*.sql"):
    with open(p, "r", encoding="utf-8") as f:
        text = f.read()
    # matches like 'account_123','user_456'
    acc_matches = re.findall(r"'(account_\d+)',\s*'(user_\d+)'", text)
    for acc, uid in acc_matches:
        user_to_account[uid] = acc
    aud_matches = re.findall(r"'(audit_record_\d+)',\s*'(user_\d+)'", text)
    for aud, uid in aud_matches:
        user_to_audit_rec[uid] = aud

print(f"Mapped accounts: {len(user_to_account)} users")
print(f"Mapped audit records: {len(user_to_audit_rec)} users")
print(f"Mapped tombstones: {len(user_to_tombstone)} users")
