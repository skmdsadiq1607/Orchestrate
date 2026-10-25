import sqlite3
import glob
import os

sql_files = glob.glob('dataset/evidence/databases/*.sql')
print(f"Testing {len(sql_files)} SQL files...")

success = 0
for sf in sql_files:
    con = sqlite3.connect(':memory:')
    with open(sf, 'r', encoding='utf-8') as f:
        sql = f.read()
    try:
        con.executescript(sql)
        success += 1
    except Exception as e:
        print(f"Failed {sf}: {e}")

print(f"Successfully executed {success}/{len(sql_files)} SQL files in SQLite!")
