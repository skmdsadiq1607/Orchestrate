import os
import pandas as pd

manifest = pd.read_csv("dataset/evidence_files.csv")
obs = manifest[manifest['origin'] == 'central_observability_export']

for idx, r in obs.iterrows():
    p = os.path.join("dataset", r['file_path'])
    with open(p, "r", encoding="utf-8") as f:
        first_line = f.readline().strip()
    print(f"{r['file_id']} ({r['file_path']}):\n  {first_line[:120]}\n")
