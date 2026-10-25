import glob

for sql in glob.glob("dataset/evidence/databases/*.sql"):
    with open(sql, "r", encoding="utf-8") as f:
        text = f.read()
        if "account_4857" in text or "account_8858" in text:
            print(f"Found in {sql}")
            for l in text.splitlines():
                if "account_4857" in l or "account_8858" in l:
                    print("  ", l)
