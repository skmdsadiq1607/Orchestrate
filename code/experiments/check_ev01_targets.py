with open("dataset/evidence/logs/service_events_ap_south_20260915.log", "r", encoding="utf-8") as f:
    lines = f.readlines()

print(f"Total lines in evidence_01: {len(lines)}")
for target in ["minjun.kim", "analytics_9914", "account_9797", "audit_record_2945", "lucia-torres", "data_flow_9846", "leonie.g9352", "backup_3245", "e.varga90", "search_6083", "support_9553"]:
    matches = [l.strip() for l in lines if target in l]
    print(f"\n--- Target: {target} (count: {len(matches)}) ---")
    for m in matches[:5]:
        print(" ", m)
