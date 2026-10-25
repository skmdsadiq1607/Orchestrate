import sqlite3
import json

con = sqlite3.connect(':memory:')
with open('dataset/evidence/databases/customer_data_read_replica_20260921.sql', 'r', encoding='utf-8') as f:
    sql_script = f.read()

# Filter out CHECK (json_valid(...)) if sqlite doesn't have json extension or test directly
try:
    con.executescript(sql_script)
    print("Executed raw script successfully!")
except Exception as e:
    print("Raw script execution error:", e)
    # If json_valid is not defined in built-in sqlite, replace json_valid
    clean_sql = sql_script.replace('CHECK (json_valid(record_json))', '')
    con.executescript(clean_sql)
    print("Executed clean script successfully!")

cur = con.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cur.fetchall()
print("Tables:", tables)

for t in tables:
    tname = t[0]
    cur.execute(f"SELECT COUNT(*) FROM {tname}")
    print(f"{tname}: {cur.fetchone()[0]} rows")
