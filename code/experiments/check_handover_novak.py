with open("dataset/evidence/records/customer_account_handover_20261001.txt", "r", encoding="utf-8") as f:
    text = f.read()

for line in text.splitlines():
    if "support_864" in line or "audit_record_9394" in line or "novak" in line:
        print(line)
