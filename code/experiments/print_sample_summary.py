import pandas as pd
import json

sr = pd.read_csv('dataset/sample_deletion_requests.csv')
so = pd.read_csv('dataset/sample_output.csv')
m = pd.merge(sr, so, on='case_id')

for idx, r in m.iterrows():
    steps = json.loads(r['steps_json'])
    findings = [s['system_id'] + '/' + s['resource_id'] + ' (' + s['operation'] + ') ev=' + s['evidence_id'] for s in steps if s['phase'] == 'FINDING']
    verifs = [s['system_id'] + '/' + s['resource_id'] + ' (' + s['operation'] + ') ev=' + s['evidence_id'] for s in steps if s['phase'] == 'VERIFICATION']
    print(f"{r['case_id']} [{r['deletion_status']}] reported={r['reported_status']}:")
    if findings:
        print("  Findings:", ", ".join(findings))
    print("  Verifs:", ", ".join(verifs))
