import glob
import os
import re

sql_files = glob.glob("dataset/evidence/databases/*.sql")
print(f"Total SQL files: {len(sql_files)}")

tables_found = set()
for sql_path in sql_files:
    fname = os.path.basename(sql_path)
    with open(sql_path, "r", encoding="utf-8") as f:
        content = f.read()
    creates = re.findall(r'CREATE TABLE (?:IF NOT EXISTS )?["`]?(\w+)["`]?', content, re.IGNORECASE)
    tables_found.update(creates)
    print(f"{fname}: {creates}")

print("\nAll unique tables across SQL files:", sorted(list(tables_found)))
