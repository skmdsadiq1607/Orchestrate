with open("dataset/evidence/databases/customer_data_inventory_20260916.sql", "r", encoding="utf-8") as f:
    text = f.read()

for term in ["user_69", "jules", "JULES"]:
    if term in text:
        print(f"Found {term} in evidence_93!")
        for line in text.splitlines():
            if term in line:
                print(" ", line)
