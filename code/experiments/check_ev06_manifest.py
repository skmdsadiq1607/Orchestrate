import pandas as pd

manifest = pd.read_csv("dataset/evidence_files.csv")
print(manifest[manifest['file_path'].str.contains("structured_service_events_eu_west_20260918.log")].to_dict('records'))
