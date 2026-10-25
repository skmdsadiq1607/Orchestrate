import glob

for sql in glob.glob("dataset/evidence/databases/customer_data_inventory_*.sql"):
    with open(sql, "r", encoding="utf-8") as f:
        text = f.read()
        if "account_3136" in text or "analytics_1895" in text:
            print(f"Found in {sql}")
            for l in text.splitlines():
                if "account_3136" in l or "analytics_1895" in l:
                    print("  ", l)
