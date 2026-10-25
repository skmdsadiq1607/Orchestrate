import pandas as pd

manifest = pd.read_csv("dataset/evidence_files.csv")
print(manifest[manifest['captured_at'].str.contains("2026-09-16") | manifest['captured_at'].str.contains("2026-09-15")][['file_id', 'captured_at', 'origin', 'file_path']].to_string())
