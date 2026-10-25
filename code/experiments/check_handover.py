with open("dataset/evidence/records/customer_account_handover_20261001.txt", "r", encoding="utf-8") as f:
    text = f.read()

print("File length:", len(text))
print("Sample lines:")
for line in text.splitlines()[:30]:
    print(line)
