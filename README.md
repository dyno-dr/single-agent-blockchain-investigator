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

[Overview](#overview) · [Architecture](#architecture) · [Quick Start](#quick-start) · [API](#api-reference) · [Roadmap](#roadmap) · [Research](#research-context)

</div>

---

## Overview

The **Single-Agent Blockchain Investigator** is an autonomous AI system that, given any Ethereum wallet address, automatically:

1. **Fetches** on-chain data (balance, transactions, token transfers) from Etherscan
2. **Profiles** the wallet and computes behavioral statistics
3. **Scores** outgoing transactions using a deterministic 4-factor ranking model
4. **Plans** a trace strategy via Gemini LLM (constrained to 5 valid strategies)
5. **Detects** suspicious patterns using 7 forensic rules with explainable findings
6. **Generates** a structured investigation report with evidence-backed reasoning
7. **Persists** the full investigation history in SQLite for audit and replay

Every decision the agent makes is logged, structured, and explainable — this is not a black-box score. Each finding carries an **Observation**, **Evidence**, and **Reasoning** field, following the XAI (Explainable AI) principle.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  USER  →  FastAPI REST  →  LangGraph Agent  →  Investigation Report │
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
├── backend/
│   ├── main.py                        # FastAPI app entry + lifespan
│   ├── constants.py                   # All enums, type aliases, rule IDs
│   ├── exceptions.py                  # Centralized exception hierarchy
│   ├── dependencies.py                # DI: DB, rate limiter, LLM client
│   ├── utils.py                       # Pure utilities (address, ETH, time)
│   │
│   ├── settings/base.py               # Pydantic-settings config
│   ├── logging_config.py              # Structlog JSON pipeline
│   │
│   ├── api/
│   │   ├── middleware.py              # Auth, CORS, RequestID, logging
│   │   └── routers/                   # investigation, report, history, graph, health
│   │
│   ├── agent/
│   │   ├── graph.py                   # LangGraph StateGraph compilation
│   │   ├── state.py                   # AgentState TypedDict (shared state)
│   │   ├── state_condensor.py         # Map-Reduce: AgentState → ReportContext
│   │   ├── session_manager.py         # UUID session registry
│   │   └── nodes/                     # planner, profiler, trace_scorer, detector,
│   │                                  # tracer, reporter, memory, transaction
│   │
│   ├── tools/                         # 8 standalone tools (each independently testable)
│   │   ├── wallet_profiler.py
│   │   ├── transaction_fetcher.py
│   │   ├── transaction_stats.py
│   │   ├── trace_scorer.py
│   │   ├── tracing_engine.py
│   │   ├── suspicion_detector.py
│   │   ├── graph_builder.py
│   │   └── report_generator.py
│   │
│   ├── forensics/
│   │   ├── engine.py                  # Rule executor (no LLM dependency)
│   │   ├── base_rule.py               # Abstract ForensicRule interface
│   │   ├── risk_scorer.py             # Weighted severity aggregation (0–100)
│   │   ├── pruning_engine.py          # EXPAND/SKIP/HALT/SAMPLE per hop
│   │   ├── trace_scorer.py            # Layer-1 deterministic scoring math
│   │   ├── models.py                  # TraceDirective, ReportContext, ScoredCandidate
│   │   └── rules/                     # 7 rule implementations (RULE-001 → RULE-007)
│   │
│   ├── blockchain/
│   │   ├── etherscan_client.py        # Async HTTP client
│   │   ├── rate_limiter.py            # AsyncTokenBucket (aiolimiter)
│   │   ├── normalizer.py              # Raw JSON → canonical models
│   │   ├── models.py                  # CleanTransaction, WalletProfile
│   │   └── known_entities.json        # 42 labelled addresses (CEX/DEX/mixer/bridge)
│   │
│   ├── persistence/
│   │   ├── database.py                # aiosqlite + WAL PRAGMA + lifespan
│   │   ├── orm_models.py              # SQLAlchemy table definitions
│   │   ├── migrations/001_initial_schema.sql
│   │   └── repositories/              # investigation, evidence, report repos
│   │
│   └── tests/
│       ├── unit/                      # test_foundation, test_blockchain, test_persistence
│       ├── integration/               # test_routes (full API tests)
│       └── fixtures/mock_etherscan_responses/
│
├── docs/
│   └── workflow.png                   # System architecture diagram
│
├── .env.example
├── requirements.txt
├── pyproject.toml
├── Dockerfile
└── docker-compose.yml
```

---

## Forensic Rules

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

**Risk scoring** (weighted sum, capped at 100):

```
CRITICAL finding → +40 pts   HIGH → +20 pts   MEDIUM → +10 pts   LOW → +5 pts
Mixer contact bonus → +30 pts flat
```

---

## Quick Start

### Prerequisites

- Python 3.12+
- [Etherscan API key](https://etherscan.io/apis) (free tier)
- [Google AI API key](https://aistudio.google.com/) (Gemini 2.0 Flash, free tier)

### 1 — Clone

```bash
git clone https://github.com/<your-username>/single-agent-blockchain-investigator.git
cd single-agent-blockchain-investigator
```

### 2 — Environment

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 3 — Configure

```bash
cp .env.example .env
```

Edit `.env` and set these three values:

```env
ETHERSCAN_API_KEY=your_etherscan_key_here
GOOGLE_API_KEY=your_google_ai_key_here
SECRET_KEY=any_random_32_character_string
```

### 4 — Run

```bash
mkdir -p data
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Server starts at `http://localhost:8000`

### 5 — Investigate a wallet

```bash
# Start an investigation (replace with any Ethereum wallet)
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your_secret_key" \
  -d '{"wallet_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "depth": 1}'

# Response (immediate):
# { "investigation_id": "3f4a...", "status": "PENDING" }

# Check result (poll until status = COMPLETE)
curl http://localhost:8000/api/v1/investigate/{investigation_id} \
  -H "X-API-Key: your_secret_key"

# Get the full report
curl http://localhost:8000/api/v1/report/{investigation_id} \
  -H "X-API-Key: your_secret_key"
```

### Docker

```bash
docker-compose up --build
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/investigate` | Start a new investigation |
| `GET` | `/api/v1/investigate/{id}` | Get investigation status + summary |
| `GET` | `/api/v1/investigate/{id}/full` | Full state (for research inspection) |
| `GET` | `/api/v1/report/{id}` | Structured investigation report |
| `GET` | `/api/v1/report/{id}/export?format=pdf\|json` | Download report |
| `GET` | `/api/v1/graph/{id}` | Transaction graph (node-link JSON + node_count) |
| `GET` | `/api/v1/history` | Past investigations (filterable) |
| `GET` | `/api/v1/history/{wallet}` | All investigations for a wallet |
| `GET` | `/api/v1/rules` | List all forensic rules (transparency endpoint) |
| `GET` | `/api/v1/health` | Health check (DB + Etherscan connectivity) |

**Interactive docs:** `http://localhost:8000/docs` (when `DEBUG=true`)

### Example investigation request

```json
{
  "wallet_address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "depth": 2,
  "options": {
    "include_token_transfers": true,
    "flag_threshold_eth": 10.0,
    "lookback_days": 90,
    "max_transactions": 500,
    "min_trace_value_eth": 0.05
  }
}
```

### Example report response

```json
{
  "investigation_id": "3f4a8c...",
  "wallet_address": "0xd8dA...",
  "risk_score": 65.0,
  "risk_level": "HIGH",
  "executive_summary": "Wallet shows patterns consistent with layering behaviour...",
  "findings": [
    {
      "rule_id": "RULE-003",
      "severity": "CRITICAL",
      "observation": "Wallet sent to 47 unique addresses within a single block window",
      "evidence": { "tx_hashes": ["0xabc..."], "values": [0.1, 0.1, 0.1] },
      "reasoning": "High fan-out patterns are a common indicator of fund distribution..."
    }
  ],
  "recommendation": "Escalate for manual AML review. Mixer contact detected.",
  "trace_summary": {
    "total_wallets_traced": 12,
    "mixer_contacts": 1,
    "cex_contacts": 3
  }
}
```

---

## Running Tests

```bash
# All tests
pytest backend/tests/ -v

# With coverage
pytest backend/tests/ --cov=backend --cov-report=term-missing

# Unit tests only
pytest backend/tests/unit/ -v

# Integration tests only
pytest backend/tests/integration/ -v
```

---

## Known Entities

The system ships with `backend/blockchain/known_entities.json` containing 42 labelled Ethereum addresses:

- **20 CEX hot wallets** — Binance (×6), Coinbase (×4), Kraken (×4), OKX (×2), Bybit, Bittrex, cold storage
- **9 DEX routers** — Uniswap V2/V3/Universal, SushiSwap, 1inch v3/v5, 0x, USDC/USDT contracts
- **7 Tornado Cash contracts** — Router, 0.1/1/10/100 ETH pools, Governance, TORN token (all OFAC-sanctioned)
- **6 Cross-chain bridges** — Polygon, Avalanche, Arbitrum, Optimism, Base

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend framework | FastAPI (async) |
| Agent framework | LangGraph (StateGraph) |
| LLM | Gemini 2.0 Flash (Google AI) |
| Blockchain data | Etherscan API |
| Rate limiting | aiolimiter (AsyncTokenBucket) |
| Retry logic | tenacity (exponential backoff) |
| Database | SQLite (WAL mode) + aiosqlite |
| Graph analytics | NetworkX |
| Logging | structlog (JSON structured) |
| Validation | Pydantic v2 |
| Testing | pytest + pytest-asyncio |

---

## Roadmap

The current system is **Agent Zero** of a planned multi-agent forensics platform.

```
Phase 1  ✅  Infrastructure (FastAPI, DB, logging, middleware, exceptions)
Phase 2  ✅  Blockchain Data Layer (Etherscan client, normalizer, rate limiter)
Phase 3  ✅  Agent Layer (LangGraph pipeline, 7 forensic rules, LLM integration)
Phase 4  🔲  WebSocket live streaming (real-time agent reasoning in frontend)
Phase 5  🔲  Visualization backend (NetworkX graph → D3/Canvas/WebGL renderer)
Phase 6  🔲  React frontend (investigation console, suspicion panel, report viewer)
Phase 7  🔲  Multi-agent expansion
              ├── Wallet Attribution Agent (ML entity clustering)
              ├── AML Compliance Agent (50+ FATF typology rules)
              ├── Transaction Tracing Agent (cross-chain, MEV, L2)
              ├── Cross-Chain Analysis Agent (Bitcoin, Solana, Arbitrum)
              └── Knowledge Graph Agent (Neo4j entity relationships)
```

---

## Research Context

This project is developed as part of a **Multi-Agent Blockchain Forensics Research Programme** exploring:

- Agentic AI architectures for financial crime detection
- Explainable AI (XAI) in blockchain forensics
- Deterministic vs. LLM-assisted forensic rule design
- Context window management in long-horizon agent tasks
- Defense-in-depth against adversarial blockchain data structures

The architecture is intentionally designed to be **publishable** — every component is independently testable, every decision is auditable, and the system produces structured evidence-backed findings rather than opaque risk scores.

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

## Contributing

Contributions are welcome, especially:

- Additional forensic rules (`backend/forensics/rules/`)
- Expanded `known_entities.json` entries
- Frontend implementation (React + Vite + TailwindCSS)
- Additional blockchain data sources (Alchemy, Moralis adapters)
- Test coverage improvements

Please open an issue before submitting a large PR so we can discuss the approach.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">
<sub>Built for research · Designed for extensibility · Agent Zero of a multi-agent forensics platform</sub>
</div>