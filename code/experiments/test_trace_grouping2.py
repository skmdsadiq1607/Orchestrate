import re

with open("dataset/evidence/logs/resource_lookup_trace_20260926_103856.log", "r", encoding="utf-8") as f:
    lines = f.readlines()

traces = {}
for line in lines:
    tr_match = re.search(r'trace_id=([a-zA-Z0-9_\-]+)', line)
    if tr_match:
        tr = tr_match.group(1)
        if tr not in traces:
            traces[tr] = []
        traces[tr].append(line.strip())

print(f"Total traces in resource_lookup_trace: {len(traces)}")
for tr, tr_lines in list(traces.items())[:3]:
    print(f"\nTrace {tr} ({len(tr_lines)} lines):")
    for l in tr_lines:
        print(" ", l)
