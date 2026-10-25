import sys
sys.stdout.reconfigure(encoding='utf-8')
import os
import re
import json
import sqlite3
import glob
import pandas as pd
import fitz
from test_identity_index import identity_by_user, user_by_email

print("Building unified resource registry for all users...")

user_to_account = {}
user_to_audit_rec = {}
user_to_tombstone = {}

# 0. User_01 to user_10 default pattern
for i in range(1, 11):
    uid = f"user_{i:02d}"
    user_to_account[uid] = f"account_{i:03d}"

# 1. LINK_RESOURCE_IDENTITY in system_activity.csv
sa = pd.read_csv("dataset/system_activity.csv")
for idx, r in sa.iterrows():
    if r['event_type'] == 'LINK_RESOURCE_IDENTITY':
        details = str(r['details'])
        res = str(r['resource_id'])
        m_u = re.search(r'user_\d+', details)
        if m_u:
            uid = m_u.group(0)
            if res.startswith('account_'): user_to_account[uid] = res
            elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
            elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# 2. SQL files
for sf in glob.glob("dataset/evidence/databases/*.sql"):
    con = sqlite3.connect(':memory:')
    with open(sf, 'r', encoding='utf-8', errors='ignore') as f:
        con.executescript(f.read())
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [t[0] for t in cur.fetchall()]
    for t in tables:
        if t == 'snapshot_scope': continue
        cur.execute(f"PRAGMA table_info({t})")
        cols = [c[1] for c in cur.fetchall()]
        cur.execute(f"SELECT * FROM {t}")
        for row in cur.fetchall():
            row_dict = dict(zip(cols, row))
            res = row_dict.get('resource_id')
            if not res: continue
            rec_json = row_dict.get('record_json')
            jd = {}
            if rec_json:
                try: jd = json.loads(rec_json)
                except Exception: pass
            
            # find user_id or email
            uid = None
            for k in ['customer_reference', 'user_id', 'subject_reference']:
                v = jd.get(k) or row_dict.get(k)
                if v and str(v).startswith('user_'): uid = str(v)
            if not uid:
                for k in ['email', 'owner_email', 'requester_email', 'customer_email']:
                    v = jd.get(k) or row_dict.get(k)
                    if v and str(v).lower() in user_by_email: uid = user_by_email[str(v).lower()]
            
            if uid:
                if res.startswith('account_'): user_to_account[uid] = res
                elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# 3. JSON files
for p in glob.glob("dataset/evidence/records/*.json"):
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        try: d = json.load(f)
        except Exception: continue
    
    # service_exports
    if 'service_exports' in d:
        se = d['service_exports']
        for p_item in se.get('account_service', {}).get('profile_lookups', []):
            res = p_item.get('resource_id')
            lk = p_item.get('lookup_key')
            if lk and str(lk).lower() in user_by_email:
                user_to_account[user_by_email[str(lk).lower()]] = res
        for a_item in se.get('security_service', {}).get('audit_records', []):
            res = a_item.get('resource_id')
            sref = a_item.get('subject_reference')
            if sref and str(sref).startswith('user_'):
                user_to_audit_rec[str(sref)] = res
    elif 'snapshots' in d:
        for snap in d.get('snapshots', []):
            for rec in snap.get('records', []):
                res = rec.get('resource_id')
                sref = rec.get('subject_reference') or rec.get('user_id')
                if not sref:
                    em = rec.get('email')
                    if em and str(em).lower() in user_by_email: sref = user_by_email[str(em).lower()]
                if sref and str(sref).startswith('user_'):
                    if res.startswith('account_'): user_to_account[sref] = res
                    elif res.startswith('audit_record_'): user_to_audit_rec[sref] = res
                    elif res.startswith('tombstone_'): user_to_tombstone[sref] = res
    elif 'records' in d:
        for rec in d.get('records', []):
            res = rec.get('resource_id')
            sref = rec.get('subject_reference')
            if not sref:
                em = rec.get('email') or rec.get('owner_email')
                if em and str(em).lower() in user_by_email: sref = user_by_email[str(em).lower()]
            if sref:
                uid = str(sref) if str(sref).startswith('user_') else user_by_email.get(str(sref).lower())
                if uid:
                    if res.startswith('account_'): user_to_account[uid] = res
                    elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                    elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# 4. Logs with trace grouping
for p in glob.glob("dataset/evidence/logs/*.log"):
    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
        traces = {}
        for line in f:
            m_tr = re.search(r'trace_id=([a-zA-Z0-9_\-]+)', line)
            if m_tr:
                tr = m_tr.group(1)
                if tr not in traces: traces[tr] = []
                traces[tr].append(line.strip())
        for tr, tr_lines in traces.items():
            text = " ".join(tr_lines)
            m_res = re.search(r'resource_id=([a-zA-Z0-9_\-]+)', text)
            if not m_res: continue
            res = m_res.group(1)
            
            uid = None
            m_u = re.search(r'user_\d+', text)
            if m_u: uid = m_u.group(0)
            else:
                emails = re.findall(r'[\w\.-]+@[\w\.-]+', text)
                for em in emails:
                    if em.lower() in user_by_email:
                        uid = user_by_email[em.lower()]
                        break
            if uid:
                if res.startswith('account_'): user_to_account[uid] = res
                elif res.startswith('audit_record_'): user_to_audit_rec[uid] = res
                elif res.startswith('tombstone_'): user_to_tombstone[uid] = res

# 5. TXT handover
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

# 6. PDFs
for p in glob.glob("dataset/evidence/documents/*.pdf"):
    doc = fitz.open(p)
    text = " ".join([page.get_text() for page in doc])
    # check users
    for uid in identity_by_user:
        if uid in text:
            # find resources near uid
            m_aud = re.findall(r'audit_record_\d+', text)
            for aud in m_aud: user_to_audit_rec[uid] = aud

print(f"Total mapped accounts: {len(user_to_account)}")
print(f"Total mapped audit records: {len(user_to_audit_rec)}")
print(f"Total mapped tombstones: {len(user_to_tombstone)}")
