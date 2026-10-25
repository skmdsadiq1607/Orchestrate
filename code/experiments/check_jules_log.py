with open("dataset/evidence/logs/structured_service_events_eu_west_20260918.log", "r", encoding="utf-8") as f:
    for line in f:
        if "user_69" in line or "jules" in line.lower():
            print(line.strip())
