import os

target = "user_69"
for root, dirs, files in os.walk("dataset"):
    for f in files:
        p = os.path.join(root, f)
        if any(p.endswith(ext) for ext in ['.txt', '.sql', '.log', '.json', '.csv']):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                    if target in fp.read():
                        print(f"  Found in {p}")
            except Exception:
                pass
