import os
import json
import pandas as pd
from test_identity_index import identity_by_user, user_by_email

manifest = pd.read_csv("dataset/evidence_files.csv")
dr = pd.read_csv("dataset/deletion_requests.csv")
sa = pd.read_csv("dataset/system_activity.csv")

# Preload text
evidence_files = []
for idx, r in manifest.iterrows():
    p = os.path.join("dataset", r['file_path'])
    if not os.path.exists(p):
        continue
    content = ""
    if any(p.endswith(ext) for ext in ['.txt', '.sql', '.log', '.json']):
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    elif p.endswith('.pdf'):
        import fitz
        doc = fitz.open(p)
        content = " ".join([page.get_text() for page in doc])
    evidence_files.append({
        'file_id': r['file_id'],
        'captured_at': r['captured_at'],
        'origin': r['origin'],
        'path': r['file_path'],
        'content': content
    })

missed = []
for idx, r in dr.head(50).iterrows():
    em = r['email'].strip().lower()
    uid = user_by_email[em]
    u_info = identity_by_user[uid]
    audit_at = r['audit_at']
    rep_at = r['reported_at']
    
    hits = [ef['file_id'] for ef in evidence_files if ef['captured_at'] <= audit_at and any(i in ef['content'] for i in u_info['all_identifiers'] if len(i) > 4)]
    if not hits:
        missed.append((r['case_id'], em, uid, rep_at, audit_at, r['reported_status']))

print(f"Missed {len(missed)} cases:")
for c_id, em, uid, rep_at, aud_at, st in missed:
    # Check SA near rep_at
    sa['diff_min'] = (pd.to_datetime(sa['event_time']) - pd.to_datetime(rep_at)).abs().dt.total_seconds() / 60.0
    near = sa[sa['diff_min'] < 60]
    sa_res = near['resource_id'].dropna().tolist()
    print(f"[{c_id}] {em} ({uid}) reported: {rep_at} status={st} | near_sa_res: {sa_res}")
