import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd
import json

sample_req = pd.read_csv("dataset/sample_deletion_requests.csv")
sample_out = pd.read_csv("dataset/sample_output.csv")
merged = pd.merge(sample_req, sample_out, on="case_id")

for idx, r in merged.iterrows():
    steps = json.loads(r['steps_json'])
    print(f"==================================================")
    print(f"CASE: {r['case_id']} | Email: {r['email']} | Reported: {r['reported_status']} -> Actual: {r['deletion_status']}")
    print(f"Requested: {r['requested_at']} | Reported: {r['reported_at']} | Audit: {r['audit_at']}")
    print(f"Text: {r['request_text']}")
    print(f"Steps count: {len(steps)}")
    for s in steps:
        print(f"  Step {s['step_no']}: [{s['phase']}] {s['system_id']} / {s['resource_id']} -> {s['operation']} ({s['state']}) ev={s['evidence_id']}")
