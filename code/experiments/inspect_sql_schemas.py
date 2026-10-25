import sqlite3
import glob
import os
import json

sql_files = glob.glob('dataset/evidence/databases/*.sql')
schemas = {}

for sf in sql_files:
    con = sqlite3.connect(':memory:')
    with open(sf, 'r', encoding='utf-8') as f:
        con.executescript(f.read())
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [t[0] for t in cur.fetchall()]
    for t in tables:
        cur.execute(f"PRAGMA table_info({t})")
        cols = [c[1] for c in cur.fetchall()]
        col_sig = (t, tuple(cols))
        if col_sig not in schemas:
            schemas[col_sig] = []
        schemas[col_sig].append(os.path.basename(sf))

print("Unique table schemas across all SQL files:")
for (tname, cols), files in schemas.items():
    print(f"Table: {tname} | Cols: {cols} | Count files: {len(files)}")
