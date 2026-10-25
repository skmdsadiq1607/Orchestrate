"""
Indexer and Auditor Prototype for Ghost Data Still Exists.
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')
import os
import re
import json
import sqlite3
import pandas as pd

# Load participant tables
manifest = pd.read_csv("dataset/evidence_files.csv")
identities = pd.read_csv("dataset/user_identities.csv")
audit_log = pd.read_csv("dataset/user_audit_log.csv")
deletion_rules = pd.read_csv("dataset/deletion_rules.csv")
system_activity = pd.read_csv("dataset/system_activity.csv")

print("Building identity index...")
# Map every email, old email, phone, name to user_id
identity_by_user = {}
user_by_email = {}

for _, r in identities.iterrows():
    uid = r['user_id']
    identity_by_user[uid] = {
        'user_id': uid,
        'name': r['name'] if pd.notna(r['name']) else None,
        'email': r['email'].lower() if pd.notna(r['email']) else None,
        'phone': str(r['phone']).strip() if pd.notna(r['phone']) else None,
        'email_hash': str(r['email_hash']).strip() if pd.notna(r['email_hash']) else None,
        'historical_emails': set(),
        'all_identifiers': {uid}
    }
    if pd.notna(r['email']):
        em = r['email'].strip().lower()
        user_by_email[em] = uid
        identity_by_user[uid]['all_identifiers'].add(em)
    if pd.notna(r['name']):
        identity_by_user[uid]['all_identifiers'].add(r['name'].strip())
    if pd.notna(r['phone']):
        identity_by_user[uid]['all_identifiers'].add(str(r['phone']).strip())
    if pd.notna(r['email_hash']):
        identity_by_user[uid]['all_identifiers'].add(str(r['email_hash']).strip())

for _, r in audit_log.iterrows():
    uid = r['user_id']
    if uid in identity_by_user:
        for val in [r['old_value'], r['new_value']]:
            if pd.notna(val) and str(val).strip():
                sval = str(val).strip()
                identity_by_user[uid]['all_identifiers'].add(sval)
                if '@' in sval:
                    em = sval.lower()
                    identity_by_user[uid]['historical_emails'].add(em)
                    user_by_email[em] = uid

print(f"Total users indexed: {len(identity_by_user)}, Total emails mapped: {len(user_by_email)}")
