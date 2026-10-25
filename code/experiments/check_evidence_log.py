with open("dataset/evidence/logs/resource_lookup_trace_20260926_103856.log", "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines: {len(lines)}")
for i, line in enumerate(lines):
    if "user_43" in line or "account_7566" in line or "analytics_9406" in line or "audit_record_2016" in line:
        print(f"Line {i}: {line.strip()}")
