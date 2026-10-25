with open("dataset/evidence/databases/customer_accounts_failover_replica_20260902.sql", "r", encoding="utf-8") as f:
    text = f.read()

print("File size:", len(text))
print("Lines in evidence_54:")
for line in text.splitlines()[:30]:
    print(line)
