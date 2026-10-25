import pandas as pd

sa = pd.read_csv("dataset/system_activity.csv")
reqs = pd.read_csv("dataset/sample_deletion_requests.csv")

# For case_06, let's see all SA events between requested_at and reported_at + 1 hour
c6 = reqs[reqs['case_id'] == 'case_06'].iloc[0]
t1 = c6['requested_at']
t2 = c6['reported_at']
print(f"case_06 requested: {t1}, reported: {t2}")

sa_c6 = sa[(sa['event_time'] >= t1) & (sa['event_time'] <= '2026-08-30T18:00:00Z')]
print(sa_c6[sa_c6['source_system'].isin(['deletion_worker', 'account_service', 'search_service'])][['activity_id', 'event_time', 'source_system', 'target_system', 'resource_id', 'event_type', 'reported_result', 'details']].to_string())
