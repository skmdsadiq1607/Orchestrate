import pandas as pd
import json

sample_req = pd.read_csv("dataset/sample_deletion_requests.csv")
sample_out = pd.read_csv("dataset/sample_output.csv")
sa = pd.read_csv("dataset/system_activity.csv")

# Filter deletion worker account events
sa_acc = sa[(sa['target_system'] == 'account_service') & (sa['resource_id'].str.startswith('account_'))]
sa_acc['time_dt'] = pd.to_datetime(sa_acc['event_time'])

matches = 0
total = 0
for idx, r in sample_req.iterrows():
    cid = r['case_id']
    rep_at = pd.to_datetime(r['reported_at'])
    req_at = pd.to_datetime(r['requested_at'])
    
    out_row = sample_out[sample_out['case_id'] == cid].iloc[0]
    steps = json.loads(out_row['steps_json'])
    acc_gt = [s['resource_id'] for s in steps if s['resource_id'].startswith('account_')]
    if not acc_gt: continue
    gt_acc = acc_gt[0]
    total += 1
    
    # Search in sa_acc between requested_at and reported_at + 30 mins
    cand = sa_acc[(sa_acc['time_dt'] >= req_at) & (sa_acc['time_dt'] <= rep_at + pd.Timedelta(minutes=30))]
    cand_ids = cand['resource_id'].tolist()
    
    # Or closest in time
    sa_acc['diff'] = (sa_acc['time_dt'] - rep_at).abs()
    closest = sa_acc.sort_values('diff').iloc[0]['resource_id']
    
    found = gt_acc in cand_ids
    if found: matches += 1
    print(f"{cid}: GT={gt_acc} | in_window={found} | closest={closest}")

print(f"\nAccount matching: {matches} / {total} cases within [requested_at, reported_at + 30m]")
