import os
import json
import pandas as pd
from test_identity_index import identity_by_user, user_by_email

manifest = pd.read_csv("dataset/evidence_files.csv")
dr = pd.read_csv("dataset/deletion_requests.csv")
sa = pd.read_csv("dataset/system_activity.csv")

# Preload all evidence text and dates
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

print(f"Loaded {len(evidence_files)} evidence files.")

matched_cases = 0
for idx, r in dr.head(50).iterrows():
    em = r['email'].strip().lower()
    uid = user_by_email[em]
    u_info = identity_by_user[uid]
    audit_at = r['audit_at']
    
    # Find matching evidence files at or before audit_at
    hits = []
    for ef in evidence_files:
        if ef['captured_at'] <= audit_at:
            matched_idents = [i for i in u_info['all_identifiers'] if len(i) > 4 and i in ef['content']]
            if matched_idents:
                hits.append((ef['file_id'], ef['captured_at'], ef['origin']))
                
    if hits:
        matched_cases += 1

print(f"Sample 50 cases: {matched_cases}/50 directly found evidence files containing user identifiers!")
