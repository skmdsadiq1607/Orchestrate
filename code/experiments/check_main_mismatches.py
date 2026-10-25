import sys, os, json, csv
sys.path.insert(0, 'code')
from main import DeletionAuditEngine

engine = DeletionAuditEngine('dataset')

sr = list(csv.DictReader(open('dataset/sample_deletion_requests.csv', encoding='utf-8')))
so = {r['case_id']: (r['deletion_status'], json.loads(r['steps_json'])) for r in csv.DictReader(open('dataset/sample_output.csv', encoding='utf-8'))}

correct_status = 0
correct_steps = 0
total = len(sr)

for r in sr:
    cid = r['case_id']
    gt_status, gt_steps = so[cid]
    pred_status, pred_steps = engine.audit_single_request(r)
    if pred_status == gt_status: correct_status += 1
    
    match = True
    if len(pred_steps) != len(gt_steps):
        match = False
    else:
        for s1, s2 in zip(pred_steps, gt_steps):
            if (s1['phase'], s1['system_id'], s1['resource_id'], s1['operation'], s1['state'], s1['evidence_id']) != \
               (s2['phase'], s2['system_id'], s2['resource_id'], s2['operation'], s2['state'], s2['evidence_id']):
                match = False
                break
    if match:
        correct_steps += 1
    else:
        print(f"\n[MISMATCH] {cid}: Pred Status={pred_status}, GT Status={gt_status}")
        gt_t = [(s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s['evidence_id']) for s in gt_steps]
        pr_t = [(s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s['evidence_id']) for s in pred_steps]
        print("  Missing in pred:", [x for x in gt_t if x not in pr_t])
        print("  Extra in pred:  ", [x for x in pr_t if x not in gt_t])

print(f"\nTotal: Status {correct_status}/{total}, Steps {correct_steps}/{total}")
