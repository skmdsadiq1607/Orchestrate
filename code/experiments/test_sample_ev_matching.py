import os
import pandas as pd
import json
from test_identity_index import identity_by_user, user_by_email

manifest = pd.read_csv("dataset/evidence_files.csv")
reqs = pd.read_csv("dataset/sample_deletion_requests.csv")
output = pd.read_csv("dataset/sample_output.csv")

# Preload all evidence text
evidence_texts = {}
for idx, r in manifest.iterrows():
    p = os.path.join("dataset", r['file_path'])
    if not os.path.exists(p):
        continue
    if any(p.endswith(ext) for ext in ['.txt', '.sql', '.log', '.json']):
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            evidence_texts[r['file_id']] = (r['captured_at'], f.read())
    elif p.endswith('.pdf'):
        import fitz
        doc = fitz.open(p)
        text = " ".join([page.get_text() for page in doc])
        evidence_texts[r['file_id']] = (r['captured_at'], text)

print(f"Preloaded {len(evidence_texts)} evidence files into memory.")

for idx, r in reqs.iterrows():
    c_id = r['case_id']
    em = r['email'].strip().lower()
    uid = user_by_email[em]
    u_info = identity_by_user[uid]
    audit_at = r['audit_at']
    
    out_row = output[output['case_id'] == c_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    gt_evs = sorted(list(set(s['evidence_id'] for s in steps if s['evidence_id'])))
    gt_res = [s['resource_id'] for s in steps]
    
    # Search which evidence files captured at or before audit_at match user's identifiers
    matched_evs = []
    for fid, (cap_at, text) in evidence_texts.items():
        if cap_at <= audit_at:
            # check if any identifier matches
            # direct check for email or user_id or specific names
            hits = [ident for ident in u_info['all_identifiers'] if len(ident) > 4 and ident in text]
            # also check if any gt_res is in text
            res_hits = [res for res in gt_res if res in text]
            if hits or res_hits:
                matched_evs.append((fid, cap_at, hits, res_hits))
                
    fids_matched = sorted(list(set(x[0] for x in matched_evs)))
    print(f"\n{c_id} ({uid}): GT_EVS={gt_evs} | MATCHED_EVS={fids_matched}")
