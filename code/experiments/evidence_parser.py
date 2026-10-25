"""
Unified Evidence Parser for Ghost Data Still Exists.
Parses all 94 evidence files into structured resource observations.
"""
import sys
sys.stdout.reconfigure(encoding='utf-8')
import os
import re
import json
import sqlite3
import pandas as pd
import fitz # PyMuPDF

manifest = pd.read_csv("dataset/evidence_files.csv")

def parse_all_evidence():
    all_observations = []
    
    for idx, row in manifest.iterrows():
        eid = row['file_id']
        cap_at = row['captured_at']
        origin = row['origin']
        fpath = os.path.join("dataset", row['file_path'])
        
        if not os.path.exists(fpath):
            continue
            
        ext = os.path.splitext(fpath)[1].lower()
        
        # 1. JSON files
        if ext == '.json':
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    data = json.load(f)
                except Exception:
                    continue
                    
            # A. service_resource_export
            if 'service_exports' in data:
                se = data['service_exports']
                # account_service
                for p in se.get('account_service', {}).get('profile_lookups', []):
                    res_id = p.get('resource_id')
                    status = p.get('status_code')
                    obs_state = 'ABSENT' if status == 404 else 'PRESENT'
                    idents = set()
                    if p.get('lookup_key'): idents.add(str(p['lookup_key']).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'account_service', 'resource_id': res_id,
                        'data_category': 'USER_PROFILE', 'state': obs_state,
                        'identifiers': idents, 'details': str(p)
                    })
                # analytics_platform
                for p in se.get('analytics_platform', {}).get('profiles', []):
                    res_id = p.get('resource_id')
                    has_pii = bool(p.get('email') or p.get('customer_reference') or p.get('phone'))
                    obs_state = 'IDENTIFIABLE' if has_pii else 'ANONYMIZED'
                    idents = set()
                    for k in ['email', 'customer_reference', 'phone', 'email_hash']:
                        if p.get(k): idents.add(str(p[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'analytics_platform', 'resource_id': res_id,
                        'data_category': 'ANALYTICS_PROFILE', 'state': obs_state,
                        'identifiers': idents, 'details': str(p)
                    })
                # backup_service
                for b in se.get('backup_service', {}).get('restore_entries', []):
                    res_id = b.get('resource_id')
                    allowed = b.get('restore_allowed', True)
                    obs_state = 'ACTIVE' if allowed else 'BLOCKED'
                    idents = set()
                    for k in ['customer_email', 'customer_reference']:
                        if b.get(k): idents.add(str(b[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'backup_service', 'resource_id': res_id,
                        'data_category': 'BACKUP_ARCHIVE', 'state': obs_state,
                        'identifiers': idents, 'details': str(b)
                    })
                # export_service
                for e in se.get('export_service', {}).get('exports', []):
                    res_id = e.get('resource_id')
                    idents = set()
                    for k in ['owner_email', 'customer_reference', 'owner_phone']:
                        if e.get(k): idents.add(str(e[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'export_service', 'resource_id': res_id,
                        'data_category': 'USER_EXPORT', 'state': 'PRESENT',
                        'identifiers': idents, 'details': str(e)
                    })
                # integration_service
                for c in se.get('integration_service', {}).get('connectors', []):
                    res_id = c.get('resource_id')
                    enabled = c.get('enabled', False)
                    obs_state = 'ACTIVE' if enabled else 'DISABLED'
                    idents = set()
                    for k in ['customer_email', 'customer_reference']:
                        if c.get(k): idents.add(str(c[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'integration_service', 'resource_id': res_id,
                        'data_category': 'DATA_FLOW', 'state': obs_state,
                        'identifiers': idents, 'details': str(c)
                    })
                # search_service
                for s in se.get('search_service', {}).get('index_queries', []):
                    res_id = s.get('resource_id')
                    hits = s.get('hits', {})
                    total = hits.get('total', 0)
                    obs_state = 'PRESENT' if total > 0 else 'ABSENT'
                    idents = set()
                    if s.get('query'): idents.add(str(s['query']).lower())
                    for doc in hits.get('documents', []):
                        for k in ['email', 'customer_reference', 'display_name', 'phone']:
                            if doc.get(k): idents.add(str(doc[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'search_service', 'resource_id': res_id,
                        'data_category': 'SEARCH_INDEX_ENTRY', 'state': obs_state,
                        'identifiers': idents, 'details': str(s)
                    })
                # security_service
                for a in se.get('security_service', {}).get('audit_records', []):
                    res_id = a.get('resource_id')
                    idents = set()
                    for k in ['subject_reference', 'lookup_key']:
                        if a.get(k): idents.add(str(a[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'security_service', 'resource_id': res_id,
                        'data_category': 'SECURITY_AUDIT_LOG', 'state': 'PRESENT',
                        'identifiers': idents, 'details': str(a)
                    })
                # support_platform
                for t in se.get('support_platform', {}).get('tickets', []):
                    res_id = t.get('resource_id')
                    has_pii = bool(t.get('requester_email') or t.get('requester_name') or t.get('requester_phone'))
                    obs_state = 'IDENTIFIABLE' if has_pii else 'REDACTED'
                    idents = set()
                    for k in ['requester_email', 'requester_name', 'requester_phone', 'customer_reference']:
                        if t.get(k): idents.add(str(t[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': 'support_platform', 'resource_id': res_id,
                        'data_category': 'SUPPORT_MESSAGE', 'state': obs_state,
                        'identifiers': idents, 'details': str(t)
                    })

            # B. customer_data_snapshot_bundle
            elif 'snapshots' in data:
                for snap in data['snapshots']:
                    store = snap.get('data_store')
                    coll = snap.get('collection')
                    for rec in snap.get('records', []):
                        res_id = rec.get('resource_id')
                        idents = set()
                        for k in ['subject_reference', 'email', 'name', 'phone', 'email_hash']:
                            if rec.get(k): idents.add(str(rec[k]).lower())
                        
                        if store == 'identity_service':
                            has_pii = bool(rec.get('name') or rec.get('email') or rec.get('phone') or rec.get('email_hash'))
                            obs_state = 'IDENTIFIABLE' if has_pii else 'REDACTED'
                            all_observations.append({
                                'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                                'system_id': 'identity_service', 'resource_id': res_id,
                                'data_category': 'ACCOUNT_TOMBSTONE', 'state': obs_state,
                                'identifiers': idents, 'details': str(rec)
                            })
                        elif store == 'security_service':
                            all_observations.append({
                                'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                                'system_id': 'security_service', 'resource_id': res_id,
                                'data_category': 'SECURITY_AUDIT_LOG', 'state': 'PRESENT',
                                'identifiers': idents, 'details': str(rec)
                            })

            # C. other JSON files (connector_configurations, customer_export_manifest, etc.)
            elif 'records' in data:
                for rec in data['records']:
                    sys_name = rec.get('system')
                    res_id = rec.get('resource_id')
                    rec_type = rec.get('record_type')
                    result = rec.get('result')
                    subj = rec.get('subject_reference')
                    idents = {str(subj).lower()} if subj else set()
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': sys_name, 'resource_id': res_id,
                        'data_category': rec_type, 'state': result,
                        'identifiers': idents, 'details': str(rec)
                    })

        # 2. Text handover file
        elif ext == '.txt':
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('- ') and '|' in line:
                        parts = [p.strip() for p in line[2:].split('|')]
                        if len(parts) >= 6:
                            # time, sys, res, cat, state, idents
                            t_str, sys_id, res_id, cat, st, ident = parts[:6]
                            all_observations.append({
                                'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                                'system_id': sys_id, 'resource_id': res_id,
                                'data_category': cat, 'state': st,
                                'identifiers': {ident.lower()}, 'details': line
                            })

        # 3. SQL files
        elif ext == '.sql':
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                sql_text = f.read()
            # Find all INSERT statements
            inserts = re.findall(r'INSERT INTO ["`]?(\w+)["`]? VALUES\((.*?)\);', sql_text, re.IGNORECASE)
            for tbl, vals_str in inserts:
                # parse values
                # SQLite values comma separated with quotes
                vals = [v.strip().strip("'\"") for v in re.findall(r"'(?:''|[^'])*'|NULL|\d+", vals_str)]
                if not vals:
                    continue
                res_id = vals[0]
                idents = set()
                for v in vals[1:]:
                    if v and v != 'NULL' and len(v) > 3:
                        idents.add(v.lower())
                
                # Determine system and state
                sys_id = 'account_service'
                cat = 'USER_PROFILE'
                st = 'PRESENT'
                if 'search' in tbl:
                    sys_id = 'search_service'
                    cat = 'SEARCH_INDEX_ENTRY'
                elif 'analytics' in tbl:
                    sys_id = 'analytics_platform'
                    cat = 'ANALYTICS_PROFILE'
                    # check if identifiable
                    st = 'IDENTIFIABLE' if len(idents) > 0 else 'ANONYMIZED'
                elif 'support' in tbl:
                    sys_id = 'support_platform'
                    cat = 'SUPPORT_MESSAGE'
                    st = 'IDENTIFIABLE'
                elif 'export' in tbl:
                    sys_id = 'export_service'
                    cat = 'USER_EXPORT'
                elif 'connector' in tbl:
                    sys_id = 'integration_service'
                    cat = 'DATA_FLOW'
                    st = 'ACTIVE'
                elif 'backup' in tbl:
                    sys_id = 'backup_service'
                    cat = 'BACKUP_ARCHIVE'
                    st = 'ACTIVE'
                elif 'security' in tbl:
                    sys_id = 'security_service'
                    cat = 'SECURITY_AUDIT_LOG'
                    st = 'PRESENT'
                
                all_observations.append({
                    'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                    'system_id': sys_id, 'resource_id': res_id,
                    'data_category': cat, 'state': st,
                    'identifiers': idents, 'details': f"{tbl}: {vals_str}"
                })

        # 4. Logs (resource lookup trace, central observability logs, etc.)
        elif ext == '.log':
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line: continue
                    # check if line has resource_id
                    res_match = re.search(r'resource_id=([a-zA-Z0-9_\-]+)', line)
                    if not res_match:
                        res_match = re.search(r'"resource_id"\s*:\s*"([a-zA-Z0-9_\-]+)"', line)
                    if not res_match:
                        continue
                    res_id = res_match.group(1)
                    
                    # system
                    sys_match = re.search(r'service=([a-zA-Z0-9_\-]+)', line)
                    if not sys_match:
                        sys_match = re.search(r'"service"\s*:\s*"([a-zA-Z0-9_\-]+)"', line)
                    sys_id = sys_match.group(1) if sys_match else 'unknown'
                    
                    # identifiers from line
                    idents = set()
                    emails = re.findall(r'[\w\.-]+@[\w\.-]+', line)
                    for em in emails: idents.add(em.lower())
                    users = re.findall(r'user_\d+', line)
                    for u in users: idents.add(u.lower())
                    
                    # state
                    obs_state = 'PRESENT'
                    if 'http_status=404' in line or 'rows=0' in line or 'NOT_FOUND' in line:
                        obs_state = 'ABSENT'
                    elif 'retention_until' in line or 'event_code=IDENTITY_CHANGE_RECORDED' in line or 'integrity_check=passed' in line:
                        obs_state = 'PRESENT'
                    elif 'customer_reference=null' in line or 'email=null' in line or 'ANONYMIZED' in line:
                        obs_state = 'ANONYMIZED'
                    elif 'requester_email=null' in line or 'REDACTED' in line:
                        obs_state = 'REDACTED'
                    elif 'enabled=true' in line or 'result=hit' in line or 'eligible=true' in line or 'rows=1' in line or 'IDENTIFIABLE' in line:
                        if sys_id == 'integration_service': obs_state = 'ACTIVE'
                        elif sys_id == 'backup_service': obs_state = 'ACTIVE'
                        elif sys_id == 'analytics_platform': obs_state = 'IDENTIFIABLE'
                        elif sys_id == 'support_platform': obs_state = 'IDENTIFIABLE'
                        else: obs_state = 'PRESENT'
                    elif 'enabled=false' in line:
                        obs_state = 'DISABLED'
                    elif 'deletion_block=true' in line or 'restore_allowed=false' in line:
                        obs_state = 'BLOCKED'
                        
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'origin': origin,
                        'system_id': sys_id, 'resource_id': res_id,
                        'data_category': 'LOG_RECORD', 'state': obs_state,
                        'identifiers': idents, 'details': line
                    })

    print(f"Total structured observations parsed across all evidence: {len(all_observations)}")
    return all_observations

if __name__ == '__main__':
    obs = parse_all_evidence()
    print("Sample observation:", obs[0])
