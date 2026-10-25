import json
import pandas as pd
from enhanced_evidence_parser import parse_enhanced_evidence
from test_identity_index import identity_by_user, user_by_email

sample_req = pd.read_csv("dataset/sample_deletion_requests.csv")
sample_out = pd.read_csv("dataset/sample_output.csv")

all_obs = parse_enhanced_evidence()

matches = 0
for idx, r in sample_req.iterrows():
    cid = r['case_id']
    em = r['email'].strip().lower()
    uid = user_by_email[em]
    u_info = identity_by_user[uid]
    aud_at = r['audit_at']
    
    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    gt_status = out_row['deletion_status']
    gt_steps = json.loads(out_row['steps_json'])
    gt_res = set(s['resource_id'] for s in gt_steps)
    gt_evs = set(s['evidence_id'] for s in gt_steps if s['evidence_id'])
    
    idents = set(i.lower() for i in u_info['all_identifiers'] if len(i) > 3)
    
    matching_obs = []
    for o in all_obs:
        if o['captured_at'] <= aud_at:
            if o['identifiers'].intersection(idents) or o['resource_id'] in gt_res:
                matching_obs.append(o)
                
    found_res = set(o['resource_id'] for o in matching_obs)
    found_evs = set(o['evidence_id'] for o in matching_obs)
    
    res_diff = gt_res - found_res
    ev_diff = gt_evs - found_evs
    
    status = "OK" if not res_diff and not ev_diff else f"MISSING res={res_diff} ev={ev_diff}"
    print(f"[{status}] {cid} ({uid}) audit_at={aud_at}")
    if res_diff or ev_diff:
        print(f"   GT res: {sorted(list(gt_res))} | Found: {sorted(list(found_res))}")
        print(f"   GT ev: {sorted(list(gt_evs))} | Found: {sorted(list(found_evs))}")
