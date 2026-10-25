with open("dataset/evidence/databases/customer_data_reporting_replica_20260918.sql", "r", encoding="utf-8") as f:
    text = f.read()
for line in text.splitlines():
    if "support_002" in line or "analytics_9914" in line:
        print(line)

with open("dataset/evidence/logs/service_events_ap_south_20260915.log", "r", encoding="utf-8") as f:
    for line in f:
        if "analytics_9914" in line:
            print(line.strip())
