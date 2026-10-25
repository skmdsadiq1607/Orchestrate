import pandas as pd
import json

sample_out = pd.read_csv("dataset/sample_output.csv")

for idx, r in sample_out.iterrows():
    if r['deletion_status'] != 'INCOMPLETE':
        continue
    cid = r['case_id']
    steps = json.loads(r['steps_json'])
    findings = [s for s in steps if s['phase'] == 'FINDING']
    rem = [s for s in steps if s['phase'] == 'REMEDIATION']
    ver = [s for s in steps if s['phase'] == 'VERIFICATION']
    
    # Check that remediation mirrors findings
    f_res = set(s['resource_id'] for s in findings)
    r_res = set(s['resource_id'] for s in rem)
    assert f_res == r_res, f"{cid}: findings resources {f_res} != rem resources {r_res}"
    
    # Check verification covers all rem + extra (like account_service / security_service)
    v_res = set(s['resource_id'] for s in ver)
    diff = v_res - r_res
    print(f"{cid}: Findings/Rem res count={len(f_res)}, Ver res count={len(v_res)} | Extra in ver: {diff}")
