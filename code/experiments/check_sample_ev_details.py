import os

# Check evidence_57 (customer_search_primary_20260910.sql)
print("=== evidence_57 ===")
with open("dataset/evidence/databases/customer_search_primary_20260910.sql", "r", encoding="utf-8") as f:
    lines = [l for l in f if "user_06" in l or "search_001" in l or "jonas.berg" in l]
    print("Matches in evidence_57:", lines)

# Check evidence_58 (delivery_correction_attachment.pdf)
print("=== evidence_58 ===")
import fitz # PyMuPDF
doc = fitz.open("dataset/evidence/documents/delivery_correction_attachment.pdf")
print("PDF pages:", len(doc))
for i, page in enumerate(doc):
    text = page.get_text()
    for kw in ['Priya', 'Raman', 'priya', 'support_001', 'user_07']:
        if kw in text:
            print(f"Page {i} mentions {kw}")
            print(text[:300])

# Check evidence_59 (customer_export_jobs_20260914.json)
print("=== evidence_59 ===")
with open("dataset/evidence/records/customer_export_jobs_20260914.json", "r", encoding="utf-8") as f:
    text = f.read()
    for kw in ['Gabriel', 'Costa', 'export_001', 'user_08', 'gabriel.costa']:
        if kw in text:
            print(f"evidence_59 mentions {kw}")
