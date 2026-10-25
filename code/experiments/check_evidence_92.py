import json

with open("dataset/evidence/records/service_resource_export_20260915_114455.json", "r", encoding="utf-8") as f:
    data = json.load(f)

print("Type of data:", type(data))
if isinstance(data, dict):
    print("Keys:", data.keys())
    for k in list(data.keys())[:5]:
        print(f"Sample of {k}:", str(data[k])[:200])
elif isinstance(data, list):
    print(f"List length: {len(data)}")
    print("Sample item 0:", json.dumps(data[0], indent=2))
