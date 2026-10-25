import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd
from collections import Counter

df = pd.read_csv("dataset/deletion_requests.csv")
print("Total rows:", len(df))

# Count occurrences of distinct request texts
counts = Counter(df['request_text'])
print("Unique request texts:", len(counts))

# Print unique texts and their counts
for text, cnt in counts.most_common():
    print(f"\n--- Count: {cnt} ---")
    print(text[:120] + "...")
