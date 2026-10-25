import os
import pandas as pd

manifest = pd.read_csv("dataset/evidence_files.csv")
print(f"Total manifest entries: {len(manifest)}")

# Group by origin and path pattern
print(manifest['origin'].value_counts())
print("\nUnique file path patterns:")
print(manifest['file_path'].apply(lambda x: x.split('/')[1] + '/' + x.split('/')[2].split('_')[0]).value_counts())
