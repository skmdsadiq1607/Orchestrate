import os
import json
import pandas as pd
from test_identity_index import identity_by_user, user_by_email

manifest = pd.read_csv("dataset/evidence_files.csv")
dr = pd.read_csv("dataset/deletion_requests.csv")

# Preload all evidence text in lowercase
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
        'content_lower': content.lower()
    })

print(f"Loaded {len(evidence_files)} evidence files.")

matched = 0
missed = []
for idx, r in dr.iterrows():
    em = r['email'].strip().lower()
    uid = user_by_email[em]
    u_info = identity_by_user[uid]
    audit_at = r['audit_at']
    
    # check identifiers (email, user_id, phone, name)
    idents = [i.lower() for i in u_info['all_identifiers'] if len(i) > 4]
    
    hits = [ef['file_id'] for ef in evidence_files if ef['captured_at'] <= audit_at and any(i in ef['content_lower'] for i in idents)]
    if hits:
        matched += 1
    else:
        missed.append((r['case_id'], em, uid, r['reported_status'], r['reported_at'], audit_at))

print(f"Matched {matched} / {len(dr)} cases directly via case-insensitive text search!")
print(f"Remaining {len(missed)} cases:")
for m in missed[:15]:
    print(" ", m)
