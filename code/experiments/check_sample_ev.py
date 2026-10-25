import pandas as pd
import json

output = pd.read_csv("dataset/sample_output.csv")
requests = pd.read_csv("dataset/sample_deletion_requests.csv")
manifest = pd.read_csv("dataset/evidence_files.csv")

for idx, row in output.iterrows():
    case_id = row['case_id']
    status = row['deletion_status']
    steps = json.loads(row['steps_json'])
    ev_ids = [s.get('evidence_id') for s in steps if s.get('evidence_id')]
    unique_ev = sorted(list(set(ev_ids)))
    
    # Get origin and file_path for unique_ev
    ev_details = []
    for eid in unique_ev:
        m_row = manifest[manifest['file_id'] == eid]
        if len(m_row) > 0:
            ev_details.append(f"{eid} ({m_row.iloc[0]['origin']} -> {m_row.iloc[0]['file_path']})")
        else:
            ev_details.append(f"{eid} (UNKNOWN)")
    
    print(f"{case_id} [{status}]: {', '.join(ev_details)}")
