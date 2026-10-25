import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd

df = pd.read_csv("dataset/deletion_requests.csv")

not_del_phrases = [
    "leave the account active",
    "not asking for deletion",
    "keep the account as it is",
    "do not close the account",
    "without removing any of my records",
    "marketing lists only",
    "information request, not a request to erase",
    "leave my profile and purchase history in place",
    "continue using the service",
    "don't delete or change anything",
    "do not delete",
    "access request",
    "rectification"
]

found = []
for idx, row in df.iterrows():
    text = row['request_text'].lower()
    for phrase in not_del_phrases:
        if phrase in text:
            found.append((row['case_id'], row['email'], phrase, row['request_text']))
            break

print(f"Found {len(found)} explicitly non-deletion requests:")
for c, em, phr, txt in found:
    print(f"[{c}] (matched '{phr}'): {txt}")
