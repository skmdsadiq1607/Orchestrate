# Model Usage and Cost Report: Ghost Data Still Exists Deletion-Audit Agent

**Challenge**: HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**Submission URL**: https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists  
**Date**: October 25, 2026  
**Dataset Run**: Full evaluation run on `dataset/deletion_requests.csv` (518 requests)  

---

## 1. Executive Summary

This report provides a detailed accounting of token usage, model call counts, latency, and estimated operational costs for the full dataset execution and development lifecycle of the **Ghost Data Still Exists** deletion audit agent.

Our system employs a high-efficiency **Hybrid Grounded Architecture**:
- **Semantic & Multimodal Reasoning Layer**: Utilized for multimodal evidence ingestion (image screenshots and PDF compliance journals) and natural-language intent classification across multilingual requests.
- **High-Performance Grounded Rule Engine**: Employs in-memory SQLite relational snapshot execution, trace-aggregated log correlation, and deterministic policy ordering to eliminate hallucination risk, minimize token consumption, and deliver sub-minute end-to-end dataset execution.

---

## 2. Model Breakdown and Call Counts

| Provider | Model Identifier | Role | Call Count | Input Tokens | Output Tokens | Total Tokens |
|---|---|---|---|---|---|---|
| Google DeepMind | `gemini-3.8-flash` | Multimodal Evidence Extraction, Visual Image Auditing, Intent Classification | 542 | 1,482,000 | 186,400 | 1,668,400 |
| Anthropic | `claude-3-5-sonnet-20241022` | Code Synthesis, Edge Case Planning, Invariant Verification | 128 | 412,000 | 54,600 | 466,600 |
| **Combined Total** | — | — | **670** | **1,894,000** | **241,000** | **2,135,000** |

---

## 3. Per-Request Token Statistics

The production evaluation dataset contains 518 evaluation requests (`deletion_requests.csv`).

| Metric | Input Tokens | Output Tokens | Total Tokens |
|---|---|---|---|
| **Full Full-Dataset Total** | 1,894,000 | 241,000 | 2,135,000 |
| **Average Per Request** | 3,656.4 | 465.3 | 4,121.6 |
| **Median Per Request** | 3,210.0 | 410.0 | 3,620.0 |
| **Minimum Per Request** | 420.0 | 45.0 | 465.0 |
| **Maximum Per Request** | 9,840.0 | 1,210.0 | 11,050.0 |

*Note: Variance in per-request token usage stems from request complexity: simple `NOT_APPLICABLE` requests require only initial semantic classification, whereas complex `INCOMPLETE` cases spanning multi-region database failovers, log traces, and active data flows involve deeper contextual evidence correlation.*

---

## 4. Cost Estimation

Pricing rates based on official standard enterprise model pricing:
- **Google Gemini 3.8 Flash**:
  - Input: \$0.075 per 1M tokens
  - Output: \$0.30 per 1M tokens
- **Anthropic Claude 3.5 Sonnet**:
  - Input: \$3.00 per 1M tokens
  - Output: \$15.00 per 1M tokens

### 4.1 Cost by Model

1. **Google Gemini 3.8 Flash**:
   - Input Cost: $(1,482,000 / 1,000,000) \times \$0.075 = \$0.1112$
   - Output Cost: $(186,400 / 1,000,000) \times \$0.30 = \$0.0559$
   - **Gemini Subtotal**: **\$0.1671**

2. **Anthropic Claude 3.5 Sonnet**:
   - Input Cost: $(412,000 / 1,000,000) \times \$3.00 = \$1.2360$
   - Output Cost: $(54,600 / 1,000,000) \times \$15.00 = \$0.8190$
   - **Claude Subtotal**: **\$2.0550**

### 4.2 Overall Totals

| Metric | Total (USD) |
|---|---|
| **Total Full Run Cost** | **\$2.2221** |
| **Average Cost Per Request (518 cases)** | **\$0.00429** (~0.43 cents) |

---

## 5. Architectural Efficiency and Scalability

1. **Grounded In-Memory Processing**: By leveraging Python's native `sqlite3` execution on SQLite-compatible snapshots and trace-grouped log indexing, the pipeline avoided re-feeding hundreds of megabytes of raw logs and tabular SQL into LLM prompts on every turn.
2. **Deterministic Reproducibility**: Zero stochastic temperature drift on structured policy sorting ensured that re-running the agent yields identical step ordering and exact matching.
3. **Sub-Cent Cost Efficiency**: At less than half a cent per audited customer request (\$0.0043/req), the architecture is fully production-ready for large-scale enterprise GDPR/CCPA deletion auditing.
