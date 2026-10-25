import os

for target in ["audit_record_3954", "audit_record_1707", "audit_record_7095", "audit_record_4128"]:
    for root, dirs, files in os.walk("dataset"):
        for f in files:
            if "sample_output" in f: continue
            p = os.path.join(root, f)
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                    if target in fp.read():
                        print(f"Found {target} in {p}")
            except Exception:
                pass
