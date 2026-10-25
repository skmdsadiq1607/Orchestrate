import os
import pandas as pd

target = "audit_record_2016"
for root, dirs, files in os.walk("dataset"):
    for f in files:
        if any(f.endswith(ext) for ext in ['.csv', '.txt', '.sql', '.log', '.json']):
            path = os.path.join(root, f)
            try:
                with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
                    text = fp.read()
                    if target in text:
                        print(f"Found {target} in {path}")
            except Exception as e:
                pass
