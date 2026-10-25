import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd

df = pd.read_csv("dataset/deletion_requests.csv")
print("Cases between 525 and 550:")
for idx, row in df[df['case_id'].str.extract(r'case_(\d+)', expand=False).astype(int) >= 525].iterrows():
    print(f"[{row['case_id']}] ({row['reported_status']}): {row['request_text']}")
