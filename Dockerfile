# ─────────────────────────────────────────────────────────────────────────────
# Single-Agent Blockchain Investigator — Dockerfile
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

WORKDIR /app

# System dependencies (for weasyprint and other native libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpango-1.0-0 \
    libharfbuzz0b \
    libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY . .

# Ensure data directory exists
RUN mkdir -p data

# Non-root user for security
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Entrypoint: uvicorn via the module entry point
CMD ["python", "-m", "backend.main"]