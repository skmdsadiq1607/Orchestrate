"""
Prototype Deletion Audit Agent Evaluator on Sample Requests.
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
sample_requests = pd.read_csv("dataset/sample_deletion_requests.csv")
sample_output = pd.read_csv("dataset/sample_output.csv")

# 1. Identity Index
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
                    user_by_email[em] = uid

print(f"Indexed {len(identity_by_user)} users, {len(user_by_email)} emails.")

# 2. Check each sample case
PHASE_ORDER = {'FINDING': 1, 'REMEDIATION': 2, 'VERIFICATION': 3}
OPERATION_ORDER = {
    'REPORT_REMAINING_RECORD': 1,
    'REPORT_EXPOSED_PII': 2,
    'REPORT_ACTIVE_DATA_FLOW': 3,
    'REPORT_RESTORE_RISK': 4,
    'DISABLE_DATA_FLOW': 5,
    'BLOCK_RESTORE': 6,
    'DELETE_RECORD': 7,
    'REDACT_RECORD': 8,
    'ANONYMIZE_RECORD': 9,
    'VERIFY_RECORD_ABSENT': 10,
    'VERIFY_RECORD_PRESENT': 11,
    'VERIFY_RECORD_REDACTED': 12,
    'VERIFY_RECORD_ANONYMIZED': 13,
    'VERIFY_DATA_FLOW_DISABLED': 14,
    'VERIFY_RESTORE_BLOCKED': 15
}

def sort_steps(steps):
    def sort_key(s):
        return (
            PHASE_ORDER[s['phase']],
            OPERATION_ORDER[s['operation']],
            s['system_id'],
            s['resource_id']
        )
    sorted_s = sorted(steps, key=sort_key)
    for idx, s in enumerate(sorted_s):
        s['step_no'] = idx + 1
    return sorted_s

print("Auditor setup completed.")
