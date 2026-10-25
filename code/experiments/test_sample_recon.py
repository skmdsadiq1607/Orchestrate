import json
import pandas as pd
from evidence_parser import parse_all_evidence
from test_identity_index import identity_by_user, user_by_email

sample_req = pd.read_csv("dataset/sample_deletion_requests.csv")
sample_out = pd.read_csv("dataset/sample_output.csv")

print("Parsing evidence...")
all_obs = parse_all_evidence()
print(f"Loaded {len(all_obs)} observations.")

# Group observations by evidence_id
obs_by_ev = {}
for o in all_obs:
    eid = o['evidence_id']
    if eid not in obs_by_ev:
        obs_by_ev[eid] = []
    obs_by_ev[eid].append(o)

# Check for each sample case
matched_cases = 0
for idx, r in sample_req.iterrows():
    cid = r['case_id']
    em = r['email'].strip().lower()
    uid = user_by_email[em]
    u_info = identity_by_user[uid]
    aud_at = r['audit_at']
    
    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    gt_steps = json.loads(out_row['steps_json'])
    gt_res = set(s['resource_id'] for s in gt_steps)
    gt_evs = set(s['evidence_id'] for s in gt_steps if s['evidence_id'])
    
    # Check observations matching user's identifiers
    idents = set(i.lower() for i in u_info['all_identifiers'] if len(i) > 3)
    
    matching_obs = []
    for o in all_obs:
        if o['captured_at'] <= aud_at:
            if o['identifiers'].intersection(idents) or o['resource_id'] in gt_res:
                matching_obs.append(o)
                
    found_res = set(o['resource_id'] for o in matching_obs)
    found_evs = set(o['evidence_id'] for o in matching_obs)
    
    print(f"\n{cid} ({uid}) audit_at={aud_at}")
    print(f"  GT resources: {sorted(list(gt_res))}")
    print(f"  Found resources: {sorted(list(found_res))}")
    print(f"  GT evidence: {sorted(list(gt_evs))}")
    print(f"  Found evidence: {sorted(list(found_evs))}")
