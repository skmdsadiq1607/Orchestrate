import fitz
import glob
import os

pdf_files = glob.glob("dataset/evidence/documents/*.pdf")
for pdf in sorted(pdf_files):
    print(f"\n=================== {os.path.basename(pdf)} ===================")
    doc = fitz.open(pdf)
    print(f"Pages: {len(doc)}")
    for i, page in enumerate(doc):
        text = page.get_text()
        print(f"--- Page {i+1} (chars: {len(text)}) ---")
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        for line in lines[:20]:
            print("  ", line)
        if len(lines) > 20:
            print(f"   ... ({len(lines)-20} more lines)")
