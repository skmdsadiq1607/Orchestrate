import sys
sys.stdout.reconfigure(encoding='utf-8')
import pandas as pd

df = pd.read_csv("dataset/deletion_requests.csv")

# Look for patterns that are NOT deletion
non_deletion_keywords = [
    'export', 'download', 'copy', 'access', 'rectify', 'correct', 'update', 
    'newsletter', 'opt-out', 'opt out', 'unsubscribe', 'marketing'
]

deletion_keywords = [
    'delete', 'deletion', 'erase', 'erasure', 'remove', 'removal', 'close', 'closure',
    'suppress', 'suppression', 'suprimir', 'eliminar', 'eliminación', 'borrar',
    'löschen', 'löschung', 'schließen', 'effacer', 'supprimer', 'fermer',
    '削除', '消去', '해지', '삭제', '탈퇴'
]

potential_not_applicable = []
for idx, row in df.iterrows():
    text_lower = str(row['request_text']).lower()
    has_del = any(dk in text_lower for dk in deletion_keywords)
    # Check if it doesn't have deletion keyword or if it's explicitly asking for only export/access/correction
    if not has_del:
        potential_not_applicable.append((row['case_id'], row['email'], row['reported_status'], row['request_text']))

print(f"Total potential NOT_APPLICABLE (without explicit delete keyword): {len(potential_not_applicable)}")
for c, em, st, txt in potential_not_applicable[:20]:
    print(f"[{c}] status={st}: {txt}\n")
