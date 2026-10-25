import os

for root, dirs, files in os.walk("dataset"):
    for f in files:
        if "sample_output" in f:
            continue
        p = os.path.join(root, f)
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                if "account_3136" in fp.read():
                    print(f"Found account_3136 in {p}")
        except Exception:
            pass
