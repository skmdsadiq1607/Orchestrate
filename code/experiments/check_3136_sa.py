import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")
print(sa[sa['resource_id'] == 'account_3136'][['activity_id', 'event_time', 'source_system', 'target_system', 'resource_id', 'reported_result', 'details']].to_string())
