import pandas as pd
import json

df = pd.read_csv("output.csv")
dr = pd.read_csv("dataset/deletion_requests.csv")

print(f"Total rows: {len(df)}")
assert len(df) == 518, f"Expected 518 rows, got {len(df)}"

# Columns check
assert list(df.columns) == ['case_id', 'deletion_status', 'steps_json'], f"Columns mismatch: {df.columns}"

# Case ID check
assert list(df['case_id']) == sorted(list(dr['case_id'])), "Case IDs do not match sorted deletion_requests.csv"

# Status values
valid_statuses = {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'}
assert set(df['deletion_status']).issubset(valid_statuses), f"Invalid status: {set(df['deletion_status']) - valid_statuses}"
print(f"Status distribution:\n{df['deletion_status'].value_counts()}")

# Step JSON validation
for idx, r in df.iterrows():
    cid = r['case_id']
    st = r['deletion_status']
    sj = r['steps_json']
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

print("\nALL INVARIANTS AND VALIDATIONS PASSED 100% PERFECTLY!")
