import pandas as pd
import json

sa = pd.read_csv("dataset/system_activity.csv")
reqs = pd.read_csv("dataset/sample_deletion_requests.csv")
out = pd.read_csv("dataset/sample_output.csv")

# Look at case_01 to case_10
for idx, r in reqs.head(10).iterrows():
    c_id = r['case_id']
    email = r['email']
    req_at = r['requested_at']
    rep_at = r['reported_at']
    aud_at = r['audit_at']
    out_row = out[out['case_id'] == c_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    res_list = [s['resource_id'] for s in steps]
    
    print(f"\n=== {c_id}: {email} (req: {req_at}, rep: {rep_at}, aud: {aud_at}) ===")
    print(f"Target resources: {res_list}")
    
    # Check matching rows in sa
    matching_sa = sa[sa['resource_id'].isin(res_list)]
    for _, sa_row in matching_sa.iterrows():
        print(f"  SA: {sa_row['activity_id']} | {sa_row['event_time']} | {sa_row['event_type']} | {sa_row['resource_id']} | {sa_row['reported_result']} | {sa_row['details']}")
