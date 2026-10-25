import os

for root, dirs, files in os.walk("dataset"):
    for f in files:
        if f.endswith(".csv") and "sample_output" in f:
            continue
        p = os.path.join(root, f)
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as fp:
                t = fp.read()
                if "account_4857" in t:
                    print(f"Found account_4857 in {p}")
        except Exception:
            pass
