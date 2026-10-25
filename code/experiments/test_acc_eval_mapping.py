import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd
from test_identity_index import identity_by_user, user_by_email
from build_resource_registry import user_to_account, user_to_audit_rec, user_to_tombstone

dr = pd.read_csv("dataset/deletion_requests.csv")
sa = pd.read_csv("dataset/system_activity.csv")

del_acc = sa[(sa['event_type'] == 'DELETE_RECORD') & (sa['target_system'] == 'account_service')].copy()
del_acc['time_dt'] = pd.to_datetime(del_acc['event_time'])

mapped = 0
for idx, r in dr.iterrows():
    em = r['email'].strip().lower()
    uid = user_by_email[em]
    if uid in user_to_account:
        mapped += 1
    else:
        req_dt = pd.to_datetime(r['requested_at'])
        rep_dt = pd.to_datetime(r['reported_at'])
        cands = del_acc[(del_acc['time_dt'] >= req_dt - pd.Timedelta(hours=2)) & (del_acc['time_dt'] <= rep_dt + pd.Timedelta(hours=2))]
        if len(cands) > 0:
            # pick closest to reported_at
            cands = cands.copy()
            cands['diff'] = (cands['time_dt'] - rep_dt).abs()
            best = cands.sort_values('diff').iloc[0]['resource_id']
            user_to_account[uid] = best
            mapped += 1

print(f"Total evaluation cases mapped to an account: {mapped}/518")
