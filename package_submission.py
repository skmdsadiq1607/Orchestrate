"""
Package code.zip for HackerRank Orchestrate submission.
"""
import os
import zipfile

zip_filename = "code.zip"
print(f"Packaging {zip_filename}...")

files_to_add = [
    ("code/main.py", "main.py"),
    ("code/main.py", "code/main.py"),
    ("code/README.md", "README.md"),
    ("code/README.md", "code/README.md"),
    ("code/verify_root_output.py", "verify_root_output.py"),
    ("code/verify_root_output.py", "code/verify_root_output.py"),
    ("code/evaluation/evaluation_report.md", "evaluation/evaluation_report.md"),
    ("code/evaluation/evaluation_report.md", "code/evaluation/evaluation_report.md"),
    ("code/evaluation/usage_report.md", "evaluation/usage_report.md"),
    ("code/evaluation/usage_report.md", "code/evaluation/usage_report.md"),
    ("code/evaluation/main.py", "evaluation/main.py"),
    ("code/evaluation/main.py", "code/evaluation/main.py"),
]

with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
    for src, arcname in files_to_add:
        if os.path.exists(src):
            zipf.write(src, arcname)
            print(f"  Added: {arcname}")

# Verify archive contents
print(f"\nVerifying {zip_filename} contents:")
with zipfile.ZipFile(zip_filename, "r") as zipf:
    namelist = zipf.namelist()
    for name in namelist:
        print(f"  - {name} ({zipf.getinfo(name).file_size} bytes)")

    assert "evaluation/evaluation_report.md" in namelist or "code/evaluation/evaluation_report.md" in namelist
    assert "evaluation/usage_report.md" in namelist or "code/evaluation/usage_report.md" in namelist
    assert not any("dataset" in n for n in namelist)
    assert not any(".venv" in n for n in namelist)
    assert not any("__pycache__" in n for n in namelist)

print("\nSUCCESS: code.zip successfully verified and ready for submission!")
