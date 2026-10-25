import pandas as pd
import json

requests = pd.read_csv('dataset/sample_deletion_requests.csv')
output = pd.read_csv('dataset/sample_output.csv')
identities = pd.read_csv('dataset/user_identities.csv')
audit = pd.read_csv('dataset/user_audit_log.csv')

print(f"Total samples: {len(requests)}")

for idx, row in requests.iterrows():
    email = row['email']
    u_curr = identities[identities['email'].str.lower() == email.lower()]
    u_aud = audit[audit['old_value'].str.lower() == email.lower()]
    u_aud_new = audit[audit['new_value'].str.lower() == email.lower()]
    
    u_ids = set(u_curr['user_id']).union(set(u_aud['user_id'])).union(set(u_aud_new['user_id']))
    
    out_row = output[output['case_id'] == row['case_id']].iloc[0]
    steps = json.loads(out_row['steps_json'])
    res_ids = [s.get('resource_id') for s in steps]
    
    print(f"{row['case_id']}: email={email} -> user_ids={u_ids} status={out_row['deletion_status']} res={res_ids}")
