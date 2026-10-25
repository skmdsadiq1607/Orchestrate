import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")
print(sa.iloc[3675:3692][['activity_id', 'event_time', 'event_type', 'source_system', 'target_system', 'resource_id', 'reported_result', 'details']].to_string())
