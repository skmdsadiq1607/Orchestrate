import os
import re
import json
import glob
import pandas as pd
from test_identity_index import identity_by_user, user_by_email

user_to_account = {}
user_to_audit_rec = {}
user_to_tombstone = {}

# 1. From logs (resource lookup trace, observability logs, handover txt)
# Check resource_lookup_trace
for p in glob.glob("dataset/evidence/logs/resource_lookup_trace_*.log"):
    with open(p, "r", encoding="utf-8") as f:
        for line in f:
            m_res = re.search(r'resource_id=([a-zA-Z0-9_\-]+)', line)
            if not m_res: continue
            res = m_res.group(1)
            # Find email or user_id
            m_email = re.search(r'[\w\.-]+@[\w\.-]+', line)
            m_user = re.search(r'user_\d+', line)
            uid = None
            if m_email and m_email.group(0).lower() in user_by_email:
                uid = user_by_email[m_email.group(0).lower()]
            elif m_user:
                uid = m_user.group(0)
            if uid:
                if res.startswith('account_'): user_to_account[uid] = res
                elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# Handover txt
with open("dataset/evidence/records/customer_account_handover_20261001.txt", "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("- ") and "|" in line:
            parts = [p.strip() for p in line[2:].split("|")]
            if len(parts) >= 6:
                res = parts[2]
                ident = parts[5].lower()
                uid = user_by_email.get(ident) or (ident if ident.startswith("user_") else None)
                if uid:
                    if res.startswith('account_'): user_to_account[uid] = res
                    elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                    elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# Observability logs (service_events_*.log, structured_*.log)
for p in glob.glob("dataset/evidence/logs/*.log"):
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m_res = re.search(r'resource_id=([a-zA-Z0-9_\-]+)', line)
            if not m_res:
                m_res = re.search(r'"resource_id"\s*:\s*"([a-zA-Z0-9_\-]+)"', line)
            if not m_res: continue
            res = m_res.group(1)
            m_email = re.search(r'[\w\.-]+@[\w\.-]+', line)
            m_user = re.search(r'user_\d+', line)
            uid = None
            if m_email and m_email.group(0).lower() in user_by_email:
                uid = user_by_email[m_email.group(0).lower()]
            elif m_user:
                uid = m_user.group(0)
            if uid:
                if res.startswith('account_'): user_to_account[uid] = res
                elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# 2. JSON files (service_resource_export, snapshot_bundle, ledger)
for p in glob.glob("dataset/evidence/records/*.json"):
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()
    try:
        data = json.loads(text)
    except Exception:
        continue
    # iterate records
    if 'service_exports' in data:
        for sname, sval in data['service_exports'].items():
            for coll, items in sval.items():
                if isinstance(items, list):
                    for item in items:
                        res = item.get('resource_id')
                        ref = item.get('customer_reference') or item.get('subject_reference') or item.get('owner_email') or item.get('requester_email') or item.get('query')
                        if ref and str(ref).lower() in user_by_email:
                            uid = user_by_email[str(ref).lower()]
                        elif ref and str(ref).startswith('user_'):
                            uid = str(ref)
                        else:
                            uid = None
                        if uid and res:
                            if res.startswith('account_'): user_to_account[uid] = res
                            elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                            elif res.startswith('tombstone_'): user_to_tombstone[uid] = res
    elif 'snapshots' in data:
        for snap in data['snapshots']:
            for rec in snap.get('records', []):
                res = rec.get('resource_id')
                ref = rec.get('subject_reference') or rec.get('user_id') or rec.get('email')
                if ref and str(ref).lower() in user_by_email:
                    uid = user_by_email[str(ref).lower()]
                elif ref and str(ref).startswith('user_'):
                    uid = str(ref)
                else:
                    uid = None
                if uid and res:
                    if res.startswith('account_'): user_to_account[uid] = res
                    elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                    elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# 3. SQL files
for p in glob.glob("dataset/evidence/databases/*.sql"):
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if 'INSERT INTO' not in line: continue
            m_res = re.search(r"'(account_\d+|audit_record_\d+|tombstone_\d+)'", line)
            if not m_res: continue
            res = m_res.group(1)
            m_email = re.search(r"'([\w\.-]+@[\w\.-]+)'", line)
            m_user = re.search(r"'(user_\d+)'", line)
            uid = None
            if m_email and m_email.group(1).lower() in user_by_email:
                uid = user_by_email[m_email.group(1).lower()]
            elif m_user:
                uid = m_user.group(1)
            if uid:
                if res.startswith('account_'): user_to_account[uid] = res
                elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

print(f"Mapped accounts: {len(user_to_account)} users")
print(f"Mapped audit records: {len(user_to_audit_rec)} users")
print(f"Mapped tombstones: {len(user_to_tombstone)} users")
