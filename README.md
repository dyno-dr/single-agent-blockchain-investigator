<div align="center">

<img src="docs/workflow.png" alt="System Workflow" width="100%"/>

# Single-Agent Blockchain Investigator

**Autonomous forensic analysis of Ethereum wallets using LangGraph + Gemini AI**

[![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2-6B48FF?style=flat)](https://langchain-ai.github.io/langgraph/)
[![Gemini](https://img.shields.io/badge/Gemini-2.0_Flash-4285F4?style=flat&logo=google&logoColor=white)](https://deepmind.google/technologies/gemini/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active_Research-orange?style=flat)]()

*A research prototype for the Multi-Agent Blockchain Forensics Framework*

[Overview](#overview) · [Architecture](#architecture) · [Quick Start](#quick-start) · [API](#api-reference) · [Analytical Tools](#analytical-tools) · [Roadmap](#roadmap)

</div>

---

## Overview

The **Single-Agent Blockchain Investigator** is an autonomous AI system that, given any Ethereum wallet address, automatically:

1. **Fetches** on-chain data (balance, transactions, token transfers) from Etherscan
2. **Profiles** the wallet and computes behavioral statistics
3. **Scores** outgoing transactions using a deterministic 4-factor ranking model
4. **Plans** a trace strategy via Gemini LLM (constrained to 5 valid strategies)
5. **Detects** suspicious patterns using 7 general forensic rules
6. **Triages** potential rugpull operators *pre-deployment* via a specialized behavioral engine
7. **Maps Funding Provenance** using graph analysis to detect scripted CEX-funding behaviors
8. **Generates** a structured investigation report with evidence-backed reasoning
9. **Persists** the full investigation history in SQLite for audit and replay

Every decision the agent makes is logged, structured, and explainable — this is not a black-box score. Each finding carries an **Observation**, **Evidence**, and **Reasoning** field, following the XAI (Explainable AI) principle.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  USER  →  FastAPI REST  →  LangGraph Agent  →  Investigation Report │
│          (Frontend UI)                                              │
└─────────────────────────────────────────────────────────────────────┘

LangGraph Pipeline (6 nodes):

  [1] PLANNER      — Gemini selects trace strategy from fixed enum
  [2] PROFILER     — Etherscan fetch + normalize → WalletProfile
  [3] TRACE SCORER — Deterministic 4-factor ranking (no LLM)
  [4] DETECTOR     — 7 forensic rules + RiskScorer (0–100)
  [5] REPORTER     — Gemini generates report (ReportContext boundary)
  [6] MEMORY       — Single bulk INSERT, WAL mode, status → COMPLETE
```

**Key design principles from the architecture spec:**

| Principle | Implementation |
|---|---|
| Deterministic forensics | Rule engine has zero LLM dependency — independently testable |
| Context window safety | `StateCondenser` compresses state → `ReportContext` before LLM sees it |
| O(N^d) explosion prevention | `PruningEngine` applies EXPAND/SKIP/HALT/SAMPLE per hop |
| Full auditability | Every node appends to `reasoning_log`; persisted at MEMORY node |
| Forward compatibility | Every interface maps directly to the future multi-agent framework |

---

## Project Structure

```
single-agent-blockchain-investigator/
│
├── backend/                           # Core FastAPI & LangGraph backend
│   ├── api/                           # REST API routes and middleware
│   ├── agent/                         # LangGraph state graph and nodes
│   ├── tools/                         # Standalone logic tools (Profiler, Tracer, etc.)
│   ├── forensics/                     # Deterministic rule engines
│   │   ├── rules/                     # 7 general anomaly rules
│   │   └── rugpull/                   # Rugpull Creator Triage Engine & Funding Graph
│   ├── blockchain/                    # Etherscan client and normalizers
│   └── persistence/                   # SQLite database and migrations
│
├── frontend/                          # Web UI Investigation Console
│   ├── index.html                     # Main dashboard layout
│   ├── styles.css                     # Custom styling (Glassmorphism, Dark mode)
│   └── app.js                         # API integration and real-time polling
│
├── scripts/                           # Utility scripts for data processing
│   ├── separate_addresses.py          # Separates EOAs from Contracts
│   └── derive_rugpull_thresholds.py   # Statistical derivation scripts
│
├── docs/                              # Diagrams and documentation
│
├── test_langgraph.py                  # CLI test runner for full LangGraph pipeline
├── test_rugpull.py                    # CLI test harness for rugpull engine
├── test_full_dataset.py               # Benchmarking dataset tester
├── advanced_batch_analyzer.py         # Pandas/Seaborn visualization generator
│
├── .env.example
├── requirements.txt
├── pyproject.toml
└── Dockerfile
```

---

### General Anomaly Rules

Seven deterministic rules — no LLM, fully reproducible:

| Rule | Name | Detection Logic | Severity |
|---|---|---|---|
| RULE-001 | Large Transfer | Single tx value > 10 ETH | HIGH |
| RULE-002 | Rapid Succession | 5+ transactions within 300 seconds | HIGH |
| RULE-003 | High Fan-Out | Sends to 20+ unique addresses per block window | CRITICAL |
| RULE-004 | Dormant Activation | Inactive > 180 days, then outflow within 48h | HIGH |
| RULE-005 | Activity Burst | Frequency > 3× wallet's own 30-day average | MEDIUM |
| RULE-006 | Round Numbers | 3+ transactions with exact power-of-10 values | MEDIUM |
| RULE-007 | New Wallet Interaction | Sends to / receives from wallets < 24h old | HIGH |

### Pre-Deployment Rugpull Rules

A specialized standalone engine (`RugpullEngine`) profiles contract deployers *before* the malicious act occurs based on preparation behaviour, and tracks funding provenance via `FunderGraph`.

| Rule | Name | Detection Logic | Severity |
|---|---|---|---|
| RUG-001 | No Dry-Runs | Zero testnet/reverted mainnet attempts before deployment | MEDIUM |
| RUG-002 | Scripted Funding | Extremely low CV in funding gap timing | HIGH |
| RUG-004 | Fast Burst | Consecutive deployments in under 60 minutes | LOW |
| RUG-NEW-A | Immediate Clone | Secondary contract deployment within 60 minutes | MEDIUM |
| RUG-NEW-B | Ownership Transfer| Contract ownership transferred away within 48h | HIGH |

---

## Quick Start

### Prerequisites

- Python 3.12+
- [Etherscan API key](https://etherscan.io/apis) (free tier)
- [Google AI API key](https://aistudio.google.com/) (Gemini 2.0 Flash, free tier)

### 1 — Clone & Environment

```bash
git clone https://github.com/<your-username>/single-agent-blockchain-investigator.git
cd single-agent-blockchain-investigator

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2 — Configure

```bash
cp .env.example .env
```

Edit `.env` and set these three values:

```env
ETHERSCAN_API_KEY=your_etherscan_key_here
GOOGLE_API_KEY=your_google_ai_key_here
SECRET_KEY=any_random_32_character_string
```

### 3 — Run the Backend

```bash
mkdir -p data
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
Server starts at `http://localhost:8000`

### 4 — Open the Frontend UI
Simply open `frontend/index.html` in any web browser to access the beautiful web dashboard. No separate frontend build step is required! Enter a wallet address and watch the investigation unfold.

---

## Analytical Tools

The framework ships with several powerful CLI tools to benchmark datasets and generate visualizations.

**Evaluate the entire dataset with funding provenance:**
```bash
python test_full_dataset.py --fetch
```

**Generate Pandas/Seaborn visualization plots from batch results:**
```bash
python advanced_batch_analyzer.py
```
This will automatically generate `analysis_verdicts.png`, `analysis_rules.png`, and `analysis_scores.png`.

**Test the full LangGraph pipeline locally from the terminal:**
```bash
python test_langgraph.py 0xYourWalletAddressHere
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/investigate` | Start a new investigation |
| `GET` | `/api/v1/investigate/{id}` | Get investigation status + summary |
| `GET` | `/api/v1/investigate/{id}/full` | Full state (for research inspection) |
| `GET` | `/api/v1/report/{id}` | Structured investigation report |
| `GET` | `/api/v1/graph/{id}` | Transaction graph (node-link JSON + node_count) |
| `GET` | `/api/v1/history` | Past investigations (filterable) |

**Interactive docs:** `http://localhost:8000/docs` (when `DEBUG=true`)

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend framework | FastAPI (async) |
| Agent framework | LangGraph (StateGraph) |
| LLM | Gemini 2.0 Flash (Google AI) |
| Frontend | Vanilla JS, HTML5, CSS3 (Glassmorphism design) |
| Data Analytics | Pandas, Seaborn, Matplotlib |
| Database | SQLite (WAL mode) + aiosqlite |

---

## Roadmap

The current system is **Agent Zero** of a planned multi-agent forensics platform.

```
Phase 1  ✅  Infrastructure (FastAPI, DB, logging, middleware, exceptions)
Phase 2  ✅  Blockchain Data Layer (Etherscan client, normalizer, rate limiter)
Phase 3  ✅  Agent Layer (LangGraph pipeline, 7 forensic rules, LLM integration)
Phase 4  🔲  WebSocket live streaming (real-time agent reasoning in frontend)
Phase 5  🔲  Visualization backend (NetworkX graph → D3/Canvas/WebGL renderer)
Phase 6  ✅  Frontend Investigation Console (HTML/JS/CSS Implementation)
Phase 7  🔲  Multi-agent expansion
              ├── Pre-Deployment Rugpull Profiler (✅ Completed as standalone engine)
              ├── Wallet Attribution Agent (ML entity clustering)
              ├── AML Compliance Agent (50+ FATF typology rules)
              ├── Transaction Tracing Agent (cross-chain, MEV, L2)
              └── Knowledge Graph Agent (Neo4j entity relationships)
```

---

## Research Context

This project is developed as part of a **Multi-Agent Blockchain Forensics Research Programme** exploring agentic AI architectures for financial crime detection, XAI in forensics, and defense-in-depth against adversarial structures.

**If you use this in your research, please cite:**
```bibtex
@software{blockchain_investigator_2025,
  title  = {Single-Agent Blockchain Investigator},
  author = {Santhosh},
  year   = {2025},
  url    = {https://github.com/<your-username>/single-agent-blockchain-investigator}
}
```

---

## License
MIT License — see [LICENSE](LICENSE) for details.

<div align="center">
<sub>Built for research · Designed for extensibility · Agent Zero of a multi-agent forensics platform</sub>
</div>