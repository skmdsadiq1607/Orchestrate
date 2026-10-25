import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")
dr = pd.read_csv("dataset/deletion_requests.csv")

cr = sa[sa['event_type'] == 'CLASSIFY_REQUEST']
for idx, r in cr.iterrows():
    acc = r['resource_id']
    t = r['event_time']
    print(f"{r['activity_id']} ({t}) -> {acc}: {r['details']}")
