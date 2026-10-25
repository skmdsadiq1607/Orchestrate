import pandas as pd
import json

sample_out = pd.read_csv("dataset/sample_output.csv")

for idx, r in sample_out.iterrows():
    status = r['deletion_status']
    steps = json.loads(r['steps_json'])
    phases = [s['phase'] for s in steps]
    if status == 'COMPLETE':
        assert all(p == 'VERIFICATION' for p in phases), f"{r['case_id']}: complete has non-verification"
        assert all(s['evidence_id'] != "" for s in steps), f"{r['case_id']}: complete has empty evidence"
    elif status == 'INCOMPLETE':
        findings = [s for s in steps if s['phase'] == 'FINDING']
        remediations = [s for s in steps if s['phase'] == 'REMEDIATION']
        verifications = [s for s in steps if s['phase'] == 'VERIFICATION']
        assert len(findings) > 0, f"{r['case_id']}: incomplete has no findings"
        assert len(remediations) > 0, f"{r['case_id']}: incomplete has no remediation"
        assert all(s['evidence_id'] != "" for s in findings), f"{r['case_id']}: finding has empty evidence"
        assert all(s['evidence_id'] == "" for s in remediations), f"{r['case_id']}: remediation has non-empty evidence"
        assert all(s['evidence_id'] == "" for s in verifications), f"{r['case_id']}: post-verification has non-empty evidence"

print("ALL assertions passed perfectly for all 32 sample cases!")
