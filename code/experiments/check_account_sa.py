import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")
print(sa[sa['resource_id'].isin(["account_4857", "account_8858"])][['activity_id', 'event_time', 'event_type', 'source_system', 'target_system', 'resource_id', 'reported_result', 'details']])
