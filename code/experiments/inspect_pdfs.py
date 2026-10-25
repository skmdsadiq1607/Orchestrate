import pandas as pd
import fitz
import os

df = pd.read_csv('dataset/evidence_files.csv')
pdfs = df[df['file_path'].str.endswith('.pdf')]

for idx, r in pdfs.iterrows():
    p = os.path.join('dataset', r['file_path'])
    doc = fitz.open(p)
    text = "".join([page.get_text() for page in doc])
    print(f"=== {r['file_id']} ({r['captured_at']}) {r['file_path']} ===")
    print(text.strip())
    print()
