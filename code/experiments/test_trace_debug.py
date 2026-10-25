import re, glob, os, json, csv

identities = list(csv.DictReader(open('dataset/user_identities.csv', encoding='utf-8')))
email_to_user = {r['email'].strip().lower(): r['user_id'] for r in identities if r['email']}

p = 'dataset/evidence/logs/service_events_ap_south_20260915.log'
traces = {}
with open(p, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        l = line.strip()
        m = re.search(r'trace_id["\s:=]+([a-zA-Z0-9_\-]+)', l)
        if m:
            tr = m.group(1)
            traces.setdefault(tr, []).append(l)

print('Trace tr-4708586 in traces:', 'tr-4708586' in traces)
if 'tr-4708586' in traces:
    text = ' '.join(traces['tr-4708586'])
    print('text:', text)
    uids = set(re.findall(r'user_\d+', text))
    for em in re.findall(r'[\w\.-]+@[\w\.-]+', text):
        if em.lower() in email_to_user:
            uids.add(email_to_user[em.lower()])
    print('uids:', uids)
    res_matches = re.findall(r'(account_\d+|audit_record_\d+|tombstone_\d+)', text)
    print('res_matches:', res_matches)
