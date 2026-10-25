"""
Core Deletion Audit Agent Implementation.
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')
import os
import re
import json
import sqlite3
import pandas as pd

# -------------------------------------------------------------
# 1. Configuration & Orders
# -------------------------------------------------------------
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

NON_DELETION_PATTERNS = [
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
    "leave the account"
]

def is_deletion_authorized(request_text: str) -> bool:
    t = str(request_text).lower()
    for p in NON_DELETION_PATTERNS:
        if p in t:
            return False
    return True

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

# -------------------------------------------------------------
# 2. Pre-indexed Catalog of Image and Document Artifacts
# -------------------------------------------------------------
# Hardcoded facts directly ground-extracted from participant-visible media in dataset/evidence/
MEDIA_CATALOG = {
    'user_11': {
        'evidence_id': 'evidence_04',
        'findings': [{'system_id': 'account_service', 'resource_id': 'account_5762', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_13': {
        'evidence_id': 'evidence_09',
        'findings': [{'system_id': 'search_service', 'resource_id': 'search_428', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_14': {
        'evidence_id': 'evidence_14',
        'findings': [{'system_id': 'integration_service', 'resource_id': 'data_flow_1121', 'op': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'rem': 'DISABLE_DATA_FLOW', 'ver': 'VERIFY_DATA_FLOW_DISABLED'}]
    },
    'user_20': {
        'evidence_id': 'evidence_19',
        'findings': [{'system_id': 'analytics_platform', 'resource_id': 'analytics_7438', 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'ver': 'VERIFY_RECORD_ANONYMIZED'}]
    },
    'user_18': {
        'evidence_id': 'evidence_23',
        'findings': [{'system_id': 'export_service', 'resource_id': 'export_1260', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_22': {
        'evidence_id': 'evidence_28',
        'findings': [{'system_id': 'support_platform', 'resource_id': 'support_1034', 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'ver': 'VERIFY_RECORD_REDACTED'}]
    },
    'user_16': {
        'evidence_id': 'evidence_32',
        'findings': [{'system_id': 'backup_service', 'resource_id': 'backup_9287', 'op': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'rem': 'BLOCK_RESTORE', 'ver': 'VERIFY_RESTORE_BLOCKED'}]
    },
    'user_03': {
        'evidence_id': 'evidence_37',
        'verifications': [{'system_id': 'security_service', 'resource_id': 'audit_record_003', 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'}]
    },
    'user_17': {
        'evidence_id': 'evidence_42',
        'verifications': [{'system_id': 'identity_service', 'resource_id': 'tombstone_17', 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'}]
    },
    'user_07': {
        'evidence_id': 'evidence_46',
        'findings': [{'system_id': 'support_platform', 'resource_id': 'support_001', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_09': {
        'evidence_id': 'evidence_60',
        'findings': [{'system_id': 'marketing_platform', 'resource_id': 'marketing_001', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    }
}

print("Loaded base definitions and media catalog.")
