# Security Policy

## Supported versions

This is an active research prototype. Only the latest commit on `main` is supported.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, email the maintainer directly (add your contact in `.env.example` or README).
Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact

You will receive a response within 72 hours.

## Important notes for operators

- **Never expose this API publicly without authentication.** The `X-API-Key` middleware
  is lightweight — add a proper auth layer (OAuth2, JWT) before production use.
- **The Etherscan API key has rate limits.** Do not expose the `/investigate` endpoint
  without per-user rate limiting in production.
- **SQLite is not suitable for multi-process production deployments.** Migrate to
  PostgreSQL for concurrent write workloads (connection string change only).
- **The `known_entities.json` is not a compliance database.** It is a research
  convenience file. Do not use it as the sole basis for regulatory decisions.