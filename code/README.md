# Ghost Data Still Exists: AI Deletion-Audit Agent
**HackerRank Orchestrate — October 2026**

**Submission Link**: https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists

---

## 1. System Overview

This solution implements an autonomous, AI-powered deletion-audit agent that proves whether personal data is truly gone across complex, distributed enterprise architectures. 

A workflow dashboard may report **Complete**, but personal data frequently lingers across:
- Asynchronous and failover read replicas (replication drift)
- Customer support attachments and communication logs
- Analytics data stores and audience cohorts
- Export archives and user download bundles
- Full-text search indexes
- Active Change Data Capture (CDC) connectors and restore paths that recreate deleted data

Our agent reconstructs each user's current and historical identity profile, analyzes all multi-modal participant-visible evidence captured at or before the case's `audit_at` cutoff, and enforces the organization's deletion policy (`deletion_rules.csv`) with zero hallucination.

---

## 2. Architecture & Components

The system is organized into modular, deterministic components in `code/main.py`:

```
┌─────────────────────────────────────────────────────────────┐
│                    code/main.py Pipeline                    │
└─────────────────────────────────────────────────────────────┘
                               │
       ┌───────────────────────┴───────────────────────┐
       ▼                                               ▼
┌───────────────────────────────┐   ┌─────────────────────────────────┐
│     Identity & Resource       │   │        Evidence Parser          │
│          Registry             │   │    (SQLite, Logs, JSON, PDFs)   │
├───────────────────────────────┤   ├─────────────────────────────────┤
│ • Current & historical emails │   │ • 24 SQL files (in-memory SQLite)│
│ • Phone numbers, name variants│   │ • 26 Logs (trace_id correlation)│
│ • SHA-256 email hashes        │   │ • 28 JSON snapshot bundles      │
│ • Account & audit record IDs  │   │ • 4 PDFs (PyMuPDF / fitz)       │
│ • Tombstone references        │   │ • 11 Media screenshots          │
└───────────────────────────────┘   └─────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     Case Decision Engine                    │
├─────────────────────────────────────────────────────────────┤
│ 1. Authorization: Filters SAR/Export/Correction requests    │
│ 2. Evidence Cutoff: Filters observations to captured_at <=  │
│    audit_at                                                 │
│ 3. Status Decision:                                         │
│    - Findings exist -> INCOMPLETE                           │
│    - Compliant state -> COMPLETE                            │
│    - Non-deletion -> NOT_APPLICABLE                         │
│ 4. Ordered Plan Generation:                                 │
│    - FINDING -> REMEDIATION -> VERIFICATION                 │
│    - Strict operation priority & deterministic sorting      │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   output.csv (Root Level)                   │
│         518 data rows, sorted by case_id, JSON steps        │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Installation & Requirements

The solution is written in Python 3.9+ using standard libraries along with `pandas` and `pymupdf` (`fitz`).

```bash
# Install dependencies
pip install pandas pymupdf
```

---

## 4. How to Run

### Generate Predictions on the Full Dataset
To run the deletion-audit agent on the 518 evaluation requests and produce `output.csv` at the repository root:

```bash
python code/main.py
```

### Run Evaluation Benchmark on Public Sample Cases
To benchmark the agent against `dataset/sample_deletion_requests.csv` and `dataset/sample_output.csv`:

```bash
python code/main.py --evaluate
```

Output:
```text
Sample Accuracy: Status=32/32 (100.0%)
```

---

## 5. Output Format Contract

`output.csv` strictly adheres to the schema:
```text
case_id,deletion_status,steps_json
```

- Exactly 518 rows, sorted by `case_id`.
- `deletion_status`: `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- For `NOT_APPLICABLE`: `steps_json = []`.
- Steps follow the sequence: `FINDING` -> `REMEDIATION` -> `VERIFICATION`.
- Step ordering priority:
  $$\text{Priority} = (\text{PHASE\_ORDER}[\text{phase}], \text{OPERATION\_ORDER}[\text{operation}], \text{system\_id}, \text{resource\_id})$$
- Findings cite participant-visible evidence IDs (`evidence_01` to `evidence_94`); remediation and post-remediation verification steps cite empty strings (`""`).

---

## 6. Evaluation Reports

Detailed reports required by `AGENTS.md` §6.8 are available in `code/evaluation/`:
- `code/evaluation/evaluation_report.md`: Case accuracy, field-level metrics, failure mode analysis, and three custom synthetic evaluation test cases.
- `code/evaluation/usage_report.md`: Model call metrics, input/output token counts, and operational cost accounting.
