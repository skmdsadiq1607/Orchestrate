import re

with open("dataset/evidence/databases/customer_data_inventory_20260916.sql", "r", encoding="utf-8") as f:
    text = f.read()

# Find CREATE TABLE customer_profiles
print("=== CREATE TABLE customer_profiles ===")
m = re.search(r'CREATE TABLE customer_profiles \((.*?)\);', text, re.DOTALL)
if m:
    print(m.group(0))

# Sample 3 INSERTs into customer_profiles
inserts = [l for l in text.splitlines() if 'INSERT INTO customer_profiles ' in l]
print(f"Total customer_profiles inserts: {len(inserts)}")
for l in inserts[:3]:
    print(" ", l)
