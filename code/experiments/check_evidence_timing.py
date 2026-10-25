import pandas as pd
import json

requests = pd.read_csv("dataset/sample_deletion_requests.csv")
output = pd.read_csv("dataset/sample_output.csv")
manifest = pd.read_csv("dataset/evidence_files.csv")

for idx, r in requests.iterrows():
    case_id = r['case_id']
    audit_at = r['audit_at']
    out_row = output[output['case_id'] == case_id].iloc[0]
    steps = json.loads(out_row['steps_json'])
    ev_ids = sorted(list(set(s['evidence_id'] for s in steps if s['evidence_id'])))
    
    for ev_id in ev_ids:
        m_row = manifest[manifest['file_id'] == ev_id].iloc[0]
        captured_at = m_row['captured_at']
        origin = m_row['origin']
        path = m_row['file_path']
        is_before = captured_at <= audit_at
        print(f"{case_id} [audit: {audit_at}] -> {ev_id} [captured: {captured_at}] before={is_before} origin={origin}")
