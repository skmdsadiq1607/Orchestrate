with open("dataset/evidence/logs/support_replica.log", "r", encoding="utf-8") as f:
    text = f.read()

for id in ['support_002', 'user_10', 'nadia.ionescu@yahoo.com', 'nadia.petrescu@yahoo.com', 'n.petrescu@yahoo.com']:
    if id in text:
        print(f"Found {id} in support_replica.log")

# Print matching lines
for line in text.splitlines():
    if any(id in line for id in ['support_002', 'user_10', 'petrescu', 'ionescu']):
        print(line)
