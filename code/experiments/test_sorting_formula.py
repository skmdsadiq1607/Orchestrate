import pandas as pd
import json

sample_out = pd.read_csv("dataset/sample_output.csv")

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

def sort_key(step):
    return (
        PHASE_ORDER[step['phase']],
        OPERATION_ORDER[step['operation']],
        step['system_id'],
        step['resource_id']
    )

all_match = True
for idx, r in sample_out.iterrows():
    steps = json.loads(r['steps_json'])
    sorted_steps = sorted(steps, key=sort_key)
    # Check if order matches
    for i in range(len(steps)):
        s_orig = steps[i]
        s_sort = sorted_steps[i]
        if (s_orig['phase'], s_orig['operation'], s_orig['system_id'], s_orig['resource_id']) != \
           (s_sort['phase'], s_sort['operation'], s_sort['system_id'], s_sort['resource_id']):
            print(f"Mismatch in {r['case_id']} step {i+1}: original={s_orig} sorted={s_sort}")
            all_match = False
            break

if all_match:
    print("SUCCESS! Every single step across all 32 sample cases matches the exact sorting formula!")
