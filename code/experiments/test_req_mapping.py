import pandas as pd
from test_identity_index import user_by_email

df_req = pd.read_csv("dataset/deletion_requests.csv")
unmapped = []
for idx, r in df_req.iterrows():
    em = r['email'].strip().lower()
    if em not in user_by_email:
        unmapped.append((r['case_id'], em))

print(f"Total requests: {len(df_req)}")
print(f"Unmapped requests: {len(unmapped)}")
if unmapped:
    print("Unmapped sample:", unmapped[:5])
