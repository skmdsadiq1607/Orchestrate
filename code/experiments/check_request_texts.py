import pandas as pd

df = pd.read_csv("dataset/deletion_requests.csv")
print("Total deletion requests:", len(df))
print(df.head(10)[['case_id', 'email', 'reported_status', 'request_text']])

# Sample some non-English or varied texts
print("\nSample requests from different parts of the dataset:")
for i in [0, 50, 100, 150, 200, 250, 300, 350, 400, 450, 500]:
    row = df.iloc[i]
    print(f"{row['case_id']} ({row['reported_status']}): {row['request_text'][:150]}")
