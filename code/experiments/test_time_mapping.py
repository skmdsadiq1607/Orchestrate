import pandas as pd
import json

sa = pd.read_csv("dataset/system_activity.csv")
reqs = pd.read_csv("dataset/sample_deletion_requests.csv")
out = pd.read_csv("dataset/sample_output.csv")
identities = pd.read_csv("dataset/user_identities.csv")
audit = pd.read_csv("dataset/user_audit_log.csv")

for idx, r in reqs.iterrows():
    c_id = r['case_id']
    email = r['email']
    req_at = r['requested_at']
    rep_at = r['reported_at']
    aud_at = r['audit_at']
    
    # Get user_id
    u_curr = identities[identities['email'].str.lower() == email.lower()]
    u_aud = audit[audit['old_value'].str.lower() == email.lower()]
    u_ids = set(u_curr['user_id']).union(set(u_aud['user_id']))
    uid = list(u_ids)[0] if u_ids else "UNKNOWN"
    
    out_row = out[out['case_id'] == c_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    res_list = [s['resource_id'] for s in steps]
    
    # Check what activities in SA happen within +/- 2 hours of reported_at
    sa['diff_min'] = (pd.to_datetime(sa['event_time']) - pd.to_datetime(rep_at)).abs().dt.total_seconds() / 60.0
    near_sa = sa[sa['diff_min'] < 60] # within 1 hour
    
    # How many of the target resources appear in near_sa?
    found_res = [res for res in res_list if res in set(near_sa['resource_id'])]
    
    print(f"{c_id} ({uid}): rep_at={rep_at} | target_res={res_list} | found_in_near_sa={found_res}")
