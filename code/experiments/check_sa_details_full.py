import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")
for idx, r in sa[sa['resource_id'].isin(["account_4857", "account_8858"])].iterrows():
    print(r.to_dict())
