with open("dataset/evidence/databases/customer_data_read_replica_20260921.sql", "r", encoding="utf-8") as f:
    text = f.read()

print("File size:", len(text))
for line in text.splitlines()[:30]:
    print(line)
