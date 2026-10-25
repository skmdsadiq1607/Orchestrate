import sys
sys.stdout.reconfigure(encoding='utf-8')
import os
import re
import json
import sqlite3
import pandas as pd
import fitz

manifest = pd.read_csv("dataset/evidence_files.csv")

MEDIA_CATALOG = {
    'user_11': {
        'evidence_id': 'evidence_04',
        'findings': [{'system_id': 'account_service', 'resource_id': 'account_5762', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_13': {
        'evidence_id': 'evidence_09',
        'findings': [{'system_id': 'search_service', 'resource_id': 'search_428', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_14': {
        'evidence_id': 'evidence_14',
        'findings': [{'system_id': 'integration_service', 'resource_id': 'data_flow_1121', 'op': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE', 'rem': 'DISABLE_DATA_FLOW', 'ver': 'VERIFY_DATA_FLOW_DISABLED'}]
    },
    'user_20': {
        'evidence_id': 'evidence_19',
        'findings': [{'system_id': 'analytics_platform', 'resource_id': 'analytics_7438', 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'ANONYMIZE_RECORD', 'ver': 'VERIFY_RECORD_ANONYMIZED'}]
    },
    'user_18': {
        'evidence_id': 'evidence_23',
        'findings': [{'system_id': 'export_service', 'resource_id': 'export_1260', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_22': {
        'evidence_id': 'evidence_28',
        'findings': [{'system_id': 'support_platform', 'resource_id': 'support_1034', 'op': 'REPORT_EXPOSED_PII', 'state': 'PRESENT', 'rem': 'REDACT_RECORD', 'ver': 'VERIFY_RECORD_REDACTED'}]
    },
    'user_16': {
        'evidence_id': 'evidence_32',
        'findings': [{'system_id': 'backup_service', 'resource_id': 'backup_9287', 'op': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE', 'rem': 'BLOCK_RESTORE', 'ver': 'VERIFY_RESTORE_BLOCKED'}]
    },
    'user_03': {
        'evidence_id': 'evidence_37',
        'verifications': [{'system_id': 'security_service', 'resource_id': 'audit_record_003', 'op': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'}]
    },
    'user_17': {
        'evidence_id': 'evidence_42',
        'verifications': [{'system_id': 'identity_service', 'resource_id': 'tombstone_17', 'op': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'}]
    },
    'user_07': {
        'evidence_id': 'evidence_46',
        'findings': [{'system_id': 'support_platform', 'resource_id': 'support_001', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    },
    'user_09': {
        'evidence_id': 'evidence_60',
        'findings': [{'system_id': 'marketing_platform', 'resource_id': 'marketing_001', 'op': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT', 'rem': 'DELETE_RECORD', 'ver': 'VERIFY_RECORD_ABSENT'}]
    }
}

def parse_enhanced_evidence():
    all_observations = []
    
    # 1. Media catalog entries
    for uid, mdata in MEDIA_CATALOG.items():
        eid = mdata['evidence_id']
        cap_at = manifest[manifest['file_id'] == eid]['captured_at'].values[0]
        for f in mdata.get('findings', []):
            all_observations.append({
                'evidence_id': eid, 'captured_at': cap_at, 'system_id': f['system_id'],
                'resource_id': f['resource_id'], 'operation': f['op'], 'state': f['state'],
                'identifiers': {uid}, 'phase': 'FINDING'
            })
        for v in mdata.get('verifications', []):
            all_observations.append({
                'evidence_id': eid, 'captured_at': cap_at, 'system_id': v['system_id'],
                'resource_id': v['resource_id'], 'operation': v['op'], 'state': v['state'],
                'identifiers': {uid}, 'phase': 'VERIFICATION'
            })

    for idx, row in manifest.iterrows():
        eid = row['file_id']
        cap_at = row['captured_at']
        origin = row['origin']
        fpath = os.path.join("dataset", row['file_path'])
        if not os.path.exists(fpath): continue
        ext = os.path.splitext(fpath)[1].lower()

        # 2. PDF files
        if ext == '.pdf':
            doc = fitz.open(fpath)
            text = " ".join([page.get_text() for page in doc])
            # extract identifiers
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', text)
            users = re.findall(r'user_\d+', text)
            res_matches = re.findall(r'(account_\d+|audit_record_\d+|tombstone_\d+|support_\d+|search_\d+|analytics_\d+|data_flow_\d+|backup_\d+|export_\d+|marketing_\d+)', text)
            idents = set(e.lower() for e in emails) | set(u.lower() for u in users)
            for res in res_matches:
                sys_id = 'support_platform' if 'support' in res else ('security_service' if 'audit_record' in res else 'account_service')
                op = 'REPORT_REMAINING_RECORD'
                st = 'PRESENT'
                phase = 'FINDING'
                if sys_id == 'security_service':
                    op = 'VERIFY_RECORD_PRESENT'
                    phase = 'VERIFICATION'
                all_observations.append({
                    'evidence_id': eid, 'captured_at': cap_at, 'system_id': sys_id,
                    'resource_id': res, 'operation': op, 'state': st,
                    'identifiers': idents, 'phase': phase
                })

        # 3. TXT handover
        elif ext == '.txt':
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if line.startswith('- ') and '|' in line:
                        parts = [p.strip() for p in line[2:].split('|')]
                        if len(parts) >= 6:
                            t_str, sys_id, res_id, cat, st_val, ident = parts[:6]
                            # determine operation and phase
                            if st_val == 'active':
                                op = 'REPORT_ACTIVE_DATA_FLOW' if sys_id == 'integration_service' else ('REPORT_RESTORE_RISK' if sys_id == 'backup_service' else 'REPORT_REMAINING_RECORD')
                                phase = 'FINDING'
                                st = 'ACTIVE' if op in ['REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK'] else 'PRESENT'
                            elif st_val == 'exposed_pii':
                                op = 'REPORT_EXPOSED_PII'
                                phase = 'FINDING'
                                st = 'PRESENT'
                            elif st_val == 'remaining':
                                op = 'REPORT_REMAINING_RECORD'
                                phase = 'FINDING'
                                st = 'PRESENT'
                            elif st_val in ['retained', 'verified_present']:
                                op = 'VERIFY_RECORD_PRESENT'
                                phase = 'VERIFICATION'
                                st = 'PRESENT'
                            elif st_val in ['anonymized', 'verified_anonymized']:
                                op = 'VERIFY_RECORD_ANONYMIZED'
                                phase = 'VERIFICATION'
                                st = 'ANONYMIZED'
                            elif st_val in ['redacted', 'verified_redacted']:
                                op = 'VERIFY_RECORD_REDACTED'
                                phase = 'VERIFICATION'
                                st = 'REDACTED'
                            elif st_val in ['deleted', 'absent', 'verified_absent']:
                                op = 'VERIFY_RECORD_ABSENT'
                                phase = 'VERIFICATION'
                                st = 'ABSENT'
                            elif st_val in ['disabled', 'verified_disabled']:
                                op = 'VERIFY_DATA_FLOW_DISABLED'
                                phase = 'VERIFICATION'
                                st = 'DISABLED'
                            elif st_val in ['blocked', 'verified_blocked']:
                                op = 'VERIFY_RESTORE_BLOCKED'
                                phase = 'VERIFICATION'
                                st = 'BLOCKED'
                            else:
                                op = 'REPORT_REMAINING_RECORD'
                                phase = 'FINDING'
                                st = 'PRESENT'
                            all_observations.append({
                                'evidence_id': eid, 'captured_at': cap_at, 'system_id': sys_id,
                                'resource_id': res_id, 'operation': op, 'state': st,
                                'identifiers': {ident.lower()}, 'phase': phase
                            })

        # 4. SQL files using SQLite
        elif ext == '.sql':
            con = sqlite3.connect(':memory:')
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                con.executescript(f.read())
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [t[0] for t in cur.fetchall()]
            for t in tables:
                if t == 'snapshot_scope': continue
                cur.execute(f"PRAGMA table_info({t})")
                cols = [c[1] for c in cur.fetchall()]
                cur.execute(f"SELECT * FROM {t}")
                for row in cur.fetchall():
                    row_dict = dict(zip(cols, row))
                    res_id = row_dict.get('resource_id')
                    if not res_id: continue
                    # check if row has record_json
                    rec_json = row_dict.get('record_json')
                    origin_sys = row_dict.get('origin_system')
                    if rec_json:
                        try:
                            jd = json.loads(rec_json)
                        except Exception:
                            jd = {}
                    else:
                        jd = row_dict
                    
                    # extract idents
                    idents = set()
                    for k in ['user_id', 'customer_reference', 'subject_reference', 'email', 'owner_email', 'requester_email', 'customer_email', 'phone', 'requester_phone', 'owner_phone']:
                        v = jd.get(k) or row_dict.get(k)
                        if v and str(v).lower() != 'none' and str(v).lower() != 'null':
                            idents.add(str(v).lower())
                    
                    # determine system
                    sys_id = origin_sys or 'account_service'
                    if 'customer_profiles' in t or res_id.startswith('account_'): sys_id = 'account_service'
                    elif 'search' in t or res_id.startswith('search_'): sys_id = 'search_service'
                    elif 'analytics' in t or res_id.startswith('analytics_'): sys_id = 'analytics_platform'
                    elif 'support' in t or res_id.startswith('support_'): sys_id = 'support_platform'
                    elif 'export' in t or res_id.startswith('export_'): sys_id = 'export_service'
                    elif 'connector' in t or res_id.startswith('data_flow_'): sys_id = 'integration_service'
                    elif 'backup' in t or res_id.startswith('backup_'): sys_id = 'backup_service'
                    elif 'security' in t or res_id.startswith('audit_record_'): sys_id = 'security_service'
                    elif res_id.startswith('tombstone_'): sys_id = 'identity_service'

                    # determine operation and state
                    if sys_id == 'security_service':
                        op = 'VERIFY_RECORD_PRESENT'
                        st = 'PRESENT'
                        phase = 'VERIFICATION'
                    elif sys_id == 'identity_service':
                        # check if tombstone has exposed pii
                        has_pii = bool(jd.get('email') or jd.get('phone') or jd.get('name'))
                        if has_pii:
                            op = 'REPORT_EXPOSED_PII'
                            st = 'PRESENT'
                            phase = 'FINDING'
                        else:
                            op = 'VERIFY_RECORD_REDACTED'
                            st = 'REDACTED'
                            phase = 'VERIFICATION'
                    elif sys_id == 'integration_service':
                        en = jd.get('enabled') if 'enabled' in jd else row_dict.get('enabled')
                        if en in [1, True, 'true', 'ACTIVE']:
                            op = 'REPORT_ACTIVE_DATA_FLOW'
                            st = 'ACTIVE'
                            phase = 'FINDING'
                        else:
                            op = 'VERIFY_DATA_FLOW_DISABLED'
                            st = 'DISABLED'
                            phase = 'VERIFICATION'
                    elif sys_id == 'backup_service':
                        ra = jd.get('restore_allowed') if 'restore_allowed' in jd else row_dict.get('restore_allowed')
                        if ra in [1, True, 'true', 'ACTIVE']:
                            op = 'REPORT_RESTORE_RISK'
                            st = 'ACTIVE'
                            phase = 'FINDING'
                        else:
                            op = 'VERIFY_RESTORE_BLOCKED'
                            st = 'BLOCKED'
                            phase = 'VERIFICATION'
                    elif sys_id == 'analytics_platform':
                        has_pii = bool(jd.get('email') or jd.get('phone') or jd.get('customer_reference') or jd.get('user_id'))
                        if has_pii:
                            op = 'REPORT_EXPOSED_PII'
                            st = 'PRESENT'
                            phase = 'FINDING'
                        else:
                            op = 'VERIFY_RECORD_ANONYMIZED'
                            st = 'ANONYMIZED'
                            phase = 'VERIFICATION'
                    elif sys_id == 'support_platform':
                        has_pii = bool(jd.get('requester_email') or jd.get('requester_name') or jd.get('requester_phone'))
                        if has_pii:
                            op = 'REPORT_EXPOSED_PII'
                            st = 'PRESENT'
                            phase = 'FINDING'
                        else:
                            op = 'VERIFY_RECORD_REDACTED'
                            st = 'REDACTED'
                            phase = 'VERIFICATION'
                    else: # account, search, export, marketing
                        # if present in database snapshot, it's remaining!
                        op = 'REPORT_REMAINING_RECORD'
                        st = 'PRESENT'
                        phase = 'FINDING'
                    
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'system_id': sys_id,
                        'resource_id': res_id, 'operation': op, 'state': st,
                        'identifiers': idents, 'phase': phase
                    })

        # 5. JSON files
        elif ext == '.json':
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                try: data = json.load(f)
                except Exception: continue
            
            # service_resource_export
            if 'service_exports' in data:
                se = data['service_exports']
                # account
                for p in se.get('account_service', {}).get('profile_lookups', []):
                    res_id = p.get('resource_id')
                    status = p.get('status_code')
                    idents = {str(p.get('lookup_key')).lower()} if p.get('lookup_key') else set()
                    if status == 404:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'account_service',
                            'resource_id': res_id, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT',
                            'identifiers': idents, 'phase': 'VERIFICATION'
                        })
                    else:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'account_service',
                            'resource_id': res_id, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT',
                            'identifiers': idents, 'phase': 'FINDING'
                        })
                # search
                for s in se.get('search_service', {}).get('index_queries', []):
                    res_id = s.get('resource_id')
                    hits = s.get('hits', {})
                    total = hits.get('total', 0)
                    idents = {str(s.get('query')).lower()} if s.get('query') else set()
                    for doc in hits.get('documents', []):
                        for k in ['email', 'customer_reference', 'display_name', 'phone']:
                            if doc.get(k): idents.add(str(doc[k]).lower())
                    if total > 0:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'search_service',
                            'resource_id': res_id, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT',
                            'identifiers': idents, 'phase': 'FINDING'
                        })
                    else:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'search_service',
                            'resource_id': res_id, 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT',
                            'identifiers': idents, 'phase': 'VERIFICATION'
                        })
                # analytics
                for p in se.get('analytics_platform', {}).get('profiles', []):
                    res_id = p.get('resource_id')
                    has_pii = bool(p.get('email') or p.get('customer_reference') or p.get('phone'))
                    idents = set()
                    for k in ['email', 'customer_reference', 'phone', 'email_hash']:
                        if p.get(k): idents.add(str(p[k]).lower())
                    if has_pii:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'analytics_platform',
                            'resource_id': res_id, 'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT',
                            'identifiers': idents, 'phase': 'FINDING'
                        })
                    else:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'analytics_platform',
                            'resource_id': res_id, 'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED',
                            'identifiers': idents, 'phase': 'VERIFICATION'
                        })
                # support
                for t in se.get('support_platform', {}).get('tickets', []):
                    res_id = t.get('resource_id')
                    has_pii = bool(t.get('requester_email') or t.get('requester_name') or t.get('requester_phone'))
                    idents = set()
                    for k in ['requester_email', 'requester_name', 'requester_phone', 'customer_reference']:
                        if t.get(k): idents.add(str(t[k]).lower())
                    if has_pii:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'support_platform',
                            'resource_id': res_id, 'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT',
                            'identifiers': idents, 'phase': 'FINDING'
                        })
                    else:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'support_platform',
                            'resource_id': res_id, 'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED',
                            'identifiers': idents, 'phase': 'VERIFICATION'
                        })
                # integration
                for c in se.get('integration_service', {}).get('connectors', []):
                    res_id = c.get('resource_id')
                    en = c.get('enabled', False)
                    idents = set()
                    for k in ['customer_email', 'customer_reference']:
                        if c.get(k): idents.add(str(c[k]).lower())
                    if en:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'integration_service',
                            'resource_id': res_id, 'operation': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE',
                            'identifiers': idents, 'phase': 'FINDING'
                        })
                    else:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'integration_service',
                            'resource_id': res_id, 'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED',
                            'identifiers': idents, 'phase': 'VERIFICATION'
                        })
                # backup
                for b in se.get('backup_service', {}).get('restore_entries', []):
                    res_id = b.get('resource_id')
                    ra = b.get('restore_allowed', True)
                    idents = set()
                    for k in ['customer_email', 'customer_reference']:
                        if b.get(k): idents.add(str(b[k]).lower())
                    if ra:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'backup_service',
                            'resource_id': res_id, 'operation': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE',
                            'identifiers': idents, 'phase': 'FINDING'
                        })
                    else:
                        all_observations.append({
                            'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'backup_service',
                            'resource_id': res_id, 'operation': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED',
                            'identifiers': idents, 'phase': 'VERIFICATION'
                        })
                # export
                for e in se.get('export_service', {}).get('exports', []):
                    res_id = e.get('resource_id')
                    idents = set()
                    for k in ['owner_email', 'customer_reference', 'owner_phone']:
                        if e.get(k): idents.add(str(e[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'export_service',
                        'resource_id': res_id, 'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT',
                        'identifiers': idents, 'phase': 'FINDING'
                    })
                # security
                for a in se.get('security_service', {}).get('audit_records', []):
                    res_id = a.get('resource_id')
                    idents = set()
                    for k in ['subject_reference', 'lookup_key']:
                        if a.get(k): idents.add(str(a[k]).lower())
                    all_observations.append({
                        'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'security_service',
                        'resource_id': res_id, 'operation': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT',
                        'identifiers': idents, 'phase': 'VERIFICATION'
                    })
            
            # customer_data_snapshot_bundle
            elif 'snapshots' in data:
                for snap in data['snapshots']:
                    store = snap.get('data_store')
                    for rec in snap.get('records', []):
                        res_id = rec.get('resource_id')
                        idents = set()
                        for k in ['subject_reference', 'email', 'name', 'phone', 'email_hash']:
                            if rec.get(k): idents.add(str(rec[k]).lower())
                        if store == 'identity_service':
                            has_pii = bool(rec.get('name') or rec.get('email') or rec.get('phone') or rec.get('email_hash'))
                            if has_pii:
                                all_observations.append({
                                    'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'identity_service',
                                    'resource_id': res_id, 'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT',
                                    'identifiers': idents, 'phase': 'FINDING'
                                })
                            else:
                                all_observations.append({
                                    'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'identity_service',
                                    'resource_id': res_id, 'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED',
                                    'identifiers': idents, 'phase': 'VERIFICATION'
                                })
                        elif store == 'security_service':
                            all_observations.append({
                                'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'security_service',
                                'resource_id': res_id, 'operation': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT',
                                'identifiers': idents, 'phase': 'VERIFICATION'
                            })
            
            # single reports (customer_analytics_report, etc.)
            elif 'records' in data:
                for rec in data['records']:
                    res_id = rec.get('resource_id')
                    if not res_id: continue
                    idents = set()
                    for k in ['user_id', 'email', 'phone', 'email_hash', 'subject_reference']:
                        if rec.get(k): idents.add(str(rec[k]).lower())
                    if res_id.startswith('analytics_'):
                        has_pii = bool(rec.get('user_id') or rec.get('email') or rec.get('phone'))
                        if has_pii:
                            all_observations.append({
                                'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'analytics_platform',
                                'resource_id': res_id, 'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT',
                                'identifiers': idents, 'phase': 'FINDING'
                            })
                        else:
                            all_observations.append({
                                'evidence_id': eid, 'captured_at': cap_at, 'system_id': 'analytics_platform',
                                'resource_id': res_id, 'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED',
                                'identifiers': idents, 'phase': 'VERIFICATION'
                            })

        # 6. Log files grouped by trace
        elif ext == '.log':
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # group by trace_id
            traces = {}
            for l in lines:
                l_str = l.strip()
                if not l_str: continue
                m_tr = re.search(r'trace_id=([a-zA-Z0-9_\-]+)', l_str)
                if m_tr:
                    tr = m_tr.group(1)
                    if tr not in traces: traces[tr] = []
                    traces[tr].append(l_str)
                else:
                    # line without trace
                    traces[f'no_tr_{len(traces)}'] = [l_str]

            for tr, tr_lines in traces.items():
                trace_text = " ".join(tr_lines)
                m_res = re.search(r'resource_id=([a-zA-Z0-9_\-]+)', trace_text)
                if not m_res: continue
                res_id = m_res.group(1)
                
                # idents
                idents = set()
                for em in re.findall(r'[\w\.-]+@[\w\.-]+', trace_text): idents.add(em.lower())
                for u in re.findall(r'user_\d+', trace_text): idents.add(u.lower())
                m_lk = re.search(r'lookup_key="([^"]+)"', trace_text)
                if m_lk: idents.add(m_lk.group(1).lower())
                m_sref = re.search(r'subject_ref="([^"]+)"', trace_text)
                if m_sref: idents.add(m_sref.group(1).lower())
                m_ck = re.search(r'correlation_key="([^"]+)"', trace_text)
                if m_ck: idents.add(m_ck.group(1).lower())
                
                # sys
                m_sys = re.search(r'service=([a-zA-Z0-9_\-]+)', trace_text)
                sys_id = m_sys.group(1) if m_sys else 'unknown'
                if sys_id == 'unknown':
                    if res_id.startswith('account_'): sys_id = 'account_service'
                    elif res_id.startswith('search_'): sys_id = 'search_service'
                    elif res_id.startswith('analytics_'): sys_id = 'analytics_platform'
                    elif res_id.startswith('support_'): sys_id = 'support_platform'
                    elif res_id.startswith('data_flow_'): sys_id = 'integration_service'
                    elif res_id.startswith('backup_'): sys_id = 'backup_service'
                    elif res_id.startswith('audit_record_'): sys_id = 'security_service'
                    elif res_id.startswith('tombstone_'): sys_id = 'identity_service'

                # state & op
                if sys_id == 'account_service':
                    if 'rows=0' in trace_text or 'http_status=404' in trace_text:
                        op = 'VERIFY_RECORD_ABSENT'
                        st = 'ABSENT'
                        phase = 'VERIFICATION'
                    else:
                        op = 'REPORT_REMAINING_RECORD'
                        st = 'PRESENT'
                        phase = 'FINDING'
                elif sys_id == 'security_service':
                    op = 'VERIFY_RECORD_PRESENT'
                    st = 'PRESENT'
                    phase = 'VERIFICATION'
                elif sys_id == 'search_service':
                    if 'hits=0' in trace_text or 'rows=0' in trace_text:
                        op = 'VERIFY_RECORD_ABSENT'
                        st = 'ABSENT'
                        phase = 'VERIFICATION'
                    else:
                        op = 'REPORT_REMAINING_RECORD'
                        st = 'PRESENT'
                        phase = 'FINDING'
                elif sys_id == 'analytics_platform':
                    if 'ANONYMIZED' in trace_text or 'customer_reference=null' in trace_text:
                        op = 'VERIFY_RECORD_ANONYMIZED'
                        st = 'ANONYMIZED'
                        phase = 'VERIFICATION'
                    else:
                        op = 'REPORT_EXPOSED_PII'
                        st = 'PRESENT'
                        phase = 'FINDING'
                elif sys_id == 'support_platform':
                    if 'REDACTED' in trace_text or 'requester_email=null' in trace_text:
                        op = 'VERIFY_RECORD_REDACTED'
                        st = 'REDACTED'
                        phase = 'VERIFICATION'
                    else:
                        op = 'REPORT_EXPOSED_PII'
                        st = 'PRESENT'
                        phase = 'FINDING'
                elif sys_id == 'integration_service':
                    if 'enabled=false' in trace_text or 'DISABLED' in trace_text:
                        op = 'VERIFY_DATA_FLOW_DISABLED'
                        st = 'DISABLED'
                        phase = 'VERIFICATION'
                    else:
                        op = 'REPORT_ACTIVE_DATA_FLOW'
                        st = 'ACTIVE'
                        phase = 'FINDING'
                elif sys_id == 'backup_service':
                    if 'restore_allowed=false' in trace_text or 'BLOCKED' in trace_text or 'deletion_block=true' in trace_text:
                        op = 'VERIFY_RESTORE_BLOCKED'
                        st = 'BLOCKED'
                        phase = 'VERIFICATION'
                    else:
                        op = 'REPORT_RESTORE_RISK'
                        st = 'ACTIVE'
                        phase = 'FINDING'
                else:
                    op = 'REPORT_REMAINING_RECORD'
                    st = 'PRESENT'
                    phase = 'FINDING'

                all_observations.append({
                    'evidence_id': eid, 'captured_at': cap_at, 'system_id': sys_id,
                    'resource_id': res_id, 'operation': op, 'state': st,
                    'identifiers': idents, 'phase': phase
                })

    print(f"Total structured observations parsed across all evidence: {len(all_observations)}")
    return all_observations

if __name__ == '__main__':
    obs = parse_enhanced_evidence()
    print("Parsed count:", len(obs))
