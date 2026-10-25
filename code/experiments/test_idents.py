import pandas as pd
import json
import os

requests = pd.read_csv("dataset/sample_deletion_requests.csv")
output = pd.read_csv("dataset/sample_output.csv")
manifest = pd.read_csv("dataset/evidence_files.csv")
identities = pd.read_csv("dataset/user_identities.csv")
audit = pd.read_csv("dataset/user_audit_log.csv")

# Preload manifest info
manifest_files = manifest.to_dict('records')

# Build user id and identifier lookup
def get_user_identifiers(email):
    u_curr = identities[identities['email'].str.lower() == email.lower()]
    u_aud_old = audit[audit['old_value'].str.lower() == email.lower()]
    u_aud_new = audit[audit['new_value'].str.lower() == email.lower()]
    
    u_ids = set(u_curr['user_id']).union(set(u_aud_old['user_id'])).union(set(u_aud_new['user_id']))
    if not u_ids:
        return None, set()
    uid = list(u_ids)[0]
    
    # Gather all identifiers for this user
    all_identifiers = {uid}
    u_rows = identities[identities['user_id'] == uid]
    for _, r in u_rows.iterrows():
        for col in ['name', 'email', 'phone', 'email_hash']:
            val = r.get(col)
            if pd.notna(val) and str(val).strip():
                all_identifiers.add(str(val).strip())
                
    a_rows = audit[audit['user_id'] == uid]
    for _, r in a_rows.iterrows():
        for col in ['old_value', 'new_value']:
            val = r.get(col)
            if pd.notna(val) and str(val).strip():
                all_identifiers.add(str(val).strip())
                
    return uid, all_identifiers

print("Testing identifier matches across evidence files...")
for idx, row in requests.head(10).iterrows():
    case_id = row['case_id']
    email = row['email']
    audit_at = row['audit_at']
    uid, idents = get_user_identifiers(email)
    
    # Ground truth evidence
    out_row = output[output['case_id'] == case_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    gt_evs = sorted(list(set(s.get('evidence_id') for s in steps if s.get('evidence_id'))))
    gt_res = [s.get('resource_id') for s in steps]
    
    print(f"\n{case_id}: uid={uid}, audit_at={audit_at}, gt_evs={gt_evs}, gt_res={gt_res}")
    print(f"  idents: {idents}")
