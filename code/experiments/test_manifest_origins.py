import os
import glob
import json
import sqlite3
import pandas as pd

manifest = pd.read_csv("dataset/evidence_files.csv")
print(f"Loaded manifest with {len(manifest)} files.")

# Let's inspect the origins and file paths
origins = manifest['origin'].unique()
print(f"Unique origins: {len(origins)}")
for orig in sorted(origins):
    sub = manifest[manifest['origin'] == orig]
    sample_path = sub.iloc[0]['file_path']
    print(f"- {orig} ({len(sub)} files): {sample_path}")
