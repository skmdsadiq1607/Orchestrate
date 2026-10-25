import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")
print("Total rows:", len(sa))

m = sa[sa['details'].str.contains("user_43", na=False) | sa['details'].str.contains("l.fontaine46", na=False) | (sa['resource_id'].isin(["account_7566", "audit_record_2016", "analytics_9406"]))]
print(m[['activity_id', 'event_time', 'event_type', 'source_system', 'target_system', 'resource_id', 'reported_result', 'details']].to_string())
