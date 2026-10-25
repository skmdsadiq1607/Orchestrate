"""
Comprehensive validation script for output.csv.
Validates all structural, schema, semantic, and temporal invariants conforming to AGENTS.md §6.
"""
import pandas as pd
import json
import csv
from datetime import datetime

df = pd.read_csv("output.csv")
dr = {r['case_id']: r for r in csv.DictReader(open('dataset/deletion_requests.csv', encoding='utf-8'))}
ef = {r['file_id']: r for r in csv.DictReader(open('dataset/evidence_files.csv', encoding='utf-8'))}

print(f"Total rows: {len(df)}")
assert len(df) == 518, f"Expected 518 rows, got {len(df)}"

# 1. Columns check
assert list(df.columns) == ['case_id', 'deletion_status', 'steps_json'], f"Columns mismatch: {df.columns}"

# 2. Case ID check
assert list(df['case_id']) == sorted(list(dr.keys())), "Case IDs do not match sorted deletion_requests.csv"

# 3. Status values
valid_statuses = {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'}
assert set(df['deletion_status']).issubset(valid_statuses), f"Invalid status: {set(df['deletion_status']) - valid_statuses}"
print(f"Status distribution:\n{df['deletion_status'].value_counts()}")

# Allowed operations and required states per AGENTS.md §6.4
ALLOWED_OPS = {
    'FINDING': {
        'REPORT_REMAINING_RECORD': 'PRESENT',
        'REPORT_EXPOSED_PII': 'PRESENT',
        'REPORT_ACTIVE_DATA_FLOW': 'ACTIVE',
        'REPORT_RESTORE_RISK': 'ACTIVE'
    },
    'REMEDIATION': {
        'DISABLE_DATA_FLOW': 'DISABLED',
        'BLOCK_RESTORE': 'BLOCKED',
        'DELETE_RECORD': 'ABSENT',
        'REDACT_RECORD': 'REDACTED',
        'ANONYMIZE_RECORD': 'ANONYMIZED'
    },
    'VERIFICATION': {
        'VERIFY_RECORD_ABSENT': 'ABSENT',
        'VERIFY_RECORD_PRESENT': 'PRESENT',
        'VERIFY_RECORD_REDACTED': 'REDACTED',
        'VERIFY_RECORD_ANONYMIZED': 'ANONYMIZED',
        'VERIFY_DATA_FLOW_DISABLED': 'DISABLED',
        'VERIFY_RESTORE_BLOCKED': 'BLOCKED'
    }
}

# 4. Step JSON validation
for idx, r in df.iterrows():
    cid = r['case_id']
    st = r['deletion_status']
    sj = r['steps_json']
    req = dr[cid]
    audit_at = req['audit_at']
    
    try:
        steps = json.loads(sj)
    except Exception as e:
        assert False, f"{cid}: JSON decode error: {e}"
    assert isinstance(steps, list), f"{cid}: steps_json is not a list"
    
    if st == 'NOT_APPLICABLE':
        assert len(steps) == 0, f"{cid}: NOT_APPLICABLE must have empty steps_json"
    elif st == 'COMPLETE':
        assert all(s['phase'] == 'VERIFICATION' for s in steps), f"{cid}: COMPLETE case has non-verification step"
        assert all(s['evidence_id'] != "" for s in steps), f"{cid}: COMPLETE step must cite non-empty evidence_id"
    elif st == 'INCOMPLETE':
        findings = [s for s in steps if s['phase'] == 'FINDING']
        rems = [s for s in steps if s['phase'] == 'REMEDIATION']
        vers = [s for s in steps if s['phase'] == 'VERIFICATION']
        assert len(findings) > 0, f"{cid}: INCOMPLETE case has no findings"
        assert len(rems) > 0, f"{cid}: INCOMPLETE case has no remediation"
        assert all(s['evidence_id'] != "" for s in findings), f"{cid}: Finding has empty evidence_id"
        assert all(s['evidence_id'] == "" for s in rems), f"{cid}: Remediation has non-empty evidence_id"
        assert all(s['evidence_id'] == "" for s in vers), f"{cid}: Future verification has non-empty evidence_id"

    # Step numbering check
    for i, s in enumerate(steps):
        assert s['step_no'] == i + 1, f"{cid}: step_no {s['step_no']} != {i+1}"
        assert set(s.keys()) == {'step_no', 'phase', 'system_id', 'resource_id', 'operation', 'state', 'evidence_id'}, f"{cid}: Invalid keys: {s.keys()}"

    # Phase order check: strictly FINDING -> REMEDIATION -> VERIFICATION
    phases = [s['phase'] for s in steps]
    phase_ranks = [{'FINDING': 1, 'REMEDIATION': 2, 'VERIFICATION': 3}[p] for p in phases]
    assert phase_ranks == sorted(phase_ranks), f"{cid}: Phases not in FINDING -> REMEDIATION -> VERIFICATION order"

    # Operation, State, and Temporal Cutoff checks
    for s in steps:
        ph = s['phase']
        op = s['operation']
        state = s['state']
        eid = s['evidence_id']
        assert op in ALLOWED_OPS[ph], f"{cid}: Invalid operation {op} for phase {ph}"
        assert state == ALLOWED_OPS[ph][op], f"{cid}: Invalid state {state} for op {op}"
        
        # Temporal cutoff check: evidence must be captured at or before audit_at
        if eid:
            assert eid in ef, f"{cid}: Unknown evidence_id {eid}"
            cap_at = ef[eid]['captured_at']
            assert cap_at <= audit_at, f"{cid}: Temporal violation! {eid} captured at {cap_at} > audit_at {audit_at}"

print("\nALL INVARIANTS, SCHEMAS, TEMPORAL CUTOFFS, AND VALIDATIONS PASSED 100% PERFECTLY!")
