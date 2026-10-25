import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")

print("=== CLASSIFY_REQUEST ===")
print(sa[sa['event_type'] == 'CLASSIFY_REQUEST'][['activity_id', 'event_time', 'source_system', 'target_system', 'resource_id', 'details']].to_string())

print("\n=== LINK_RESOURCE_IDENTITY ===")
print(sa[sa['event_type'] == 'LINK_RESOURCE_IDENTITY'][['activity_id', 'event_time', 'source_system', 'target_system', 'resource_id', 'details']].to_string())
