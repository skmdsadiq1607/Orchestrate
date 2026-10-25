import os

for target in ["account_4857", "account_8858"]:
    print(f"\nSearching for {target}...")
    for root, dirs, files in os.walk("dataset"):
        for f in files:
            p = os.path.join(root, f)
            if any(p.endswith(ext) for ext in ['.csv', '.txt', '.sql', '.log', '.json']):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                        if target in fp.read():
                            print(f"  Found in {p}")
                except Exception:
                    pass
