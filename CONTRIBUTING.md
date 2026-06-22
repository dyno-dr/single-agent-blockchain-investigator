# Contributing to Single-Agent Blockchain Investigator

Thank you for your interest in contributing. This is an active research project —
contributions that improve forensic coverage, data quality, or test coverage are
especially welcome.

---

## What we need most

| Area | Where | Difficulty |
|---|---|---|
| New forensic rules | `backend/forensics/rules/` | Medium |
| Known entity entries | `backend/blockchain/known_entities.json` | Easy |
| React frontend | `frontend/` | Hard |
| Blockchain adapter (Alchemy / Moralis) | `backend/blockchain/` | Medium |
| Additional test coverage | `backend/tests/` | Easy–Medium |
| Documentation improvements | `docs/` | Easy |

---

## Ground rules

1. **Do not redesign the architecture.** The system architecture (`docs/architecture.md`)
   is the source of truth. New components must fit within the existing layer structure.

2. **Forensic rules must be deterministic.** Rules in `backend/forensics/rules/` must
   have zero LLM dependency and must produce identical output given identical input.
   This is what makes findings reproducible and publishable.

3. **All code must include tests.** New rules go in `backend/tests/unit/test_rules/`.
   New tools go in `backend/tests/unit/test_tools/`.

4. **No secrets in commits.** Never commit `.env`, API keys, or wallet private keys.
   The `.gitignore` already excludes `.env`, but double-check before pushing.

---

## Adding a new forensic rule

**For General Anomaly Rules:**
1. Create `backend/forensics/rules/your_rule.py` inheriting from `BaseForensicRule`
2. Assign the next `RULE-00N` ID from `backend/constants.py`
3. Register it in `backend/forensics/engine.py`
4. Add tests to `backend/tests/unit/test_rules/test_your_rule.py`
5. Document it in `README.md` under the Forensic Rules table

**For Pre-Deployment Rugpull Rules:**
1. Add the rule logic inside `backend/forensics/rugpull/rules.py`
2. Assign the next `RUG-00N` or `RUG-NEW-X` ID
3. Test your rule empirically against the dataset using the CLI test harness:
   ```bash
   # Make sure it works against offline cached data without hitting API rate limits
   python test_rugpull.py --known --cache
   ```
4. If your rule requires new data to be extracted (e.g. internal transactions), update `extractor.py` and the `FeatureVector` model.

---

## Development setup

```bash
git clone https://github.com/<username>/single-agent-blockchain-investigator.git
cd single-agent-blockchain-investigator
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in your keys
mkdir -p data
pytest backend/tests/ -v
```

---

## Pull request checklist

- [ ] Tests pass: `pytest backend/tests/ -v`
- [ ] No new linting errors: `ruff check backend/`
- [ ] No secrets in the diff
- [ ] PR description explains what changed and why
- [ ] If adding a general forensic rule: determinism is documented in the docstring
- [ ] If adding a rugpull rule: tested locally using `python test_rugpull.py --known --cache`

---

## Opening issues

For bugs: include the full error message and the wallet address (if safe to share).
For features: describe the use case and which research domain it serves.