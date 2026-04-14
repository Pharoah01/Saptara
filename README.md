# SAPTARA

**Automated Web Application Vulnerability Assessment Framework**

> Seven relics. Seven roles. One system.

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](https://docker.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-336791?logo=postgresql&logoColor=white)](https://postgresql.org)
[![License](https://img.shields.io/badge/License-SAPTARA%20Academic-orange)](./LICENSE)
[![Tests](https://img.shields.io/badge/Tests-14%20passing-brightgreen)](#testing)

---

SAPTARA is a production-ready, microservices-based web application security testing framework that runs a fixed three-stage pipeline — **Scanner → Simulator → Validator** — against any HTTP/HTTPS target. Every test result is persisted to PostgreSQL, exposed through authenticated REST APIs, and accessible via a professional command-line interface.

---

## Table of Contents

- [Architecture](#architecture)
- [Pipeline](#pipeline)
- [Features](#features)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Configuration](#configuration)
- [Testing](#testing)
- [Monitoring](#monitoring)
- [Project Structure](#project-structure)
- [Ethical Use](#ethical-use)
- [License](#license)

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLIENT LAYER                        │
│         CLI (saptara)  ·  REST  ·  CI/CD Pipeline      │
└──────────────────────┬──────────────────────────────────┘
                       │  POST /orchestrate
┌──────────────────────▼──────────────────────────────────┐
│                  ORCHESTRATOR :8000                     │
│         Coordinates pipeline · Checkpoints to DB       │
└──────┬───────────────┬───────────────────┬──────────────┘
       │               │                   │
  POST /scan     POST /simulate      POST /validate
       │               │                   │
┌──────▼──────┐  ┌─────▼──────┐  ┌────────▼──────┐
│ Scanner     │  │ Simulator  │  │  Validator    │
│ :8001       │→→│ :8003      │→→│  :8002        │
│ 17 OWASP    │  │ Multi-step │  │  8 defence    │
│ categories  │  │ exploits   │  │  checks       │
└──────┬──────┘  └─────┬──────┘  └────────┬──────┘
       │               │                   │
       └───────────────┴───────────────────┘
                       │  persist results
┌──────────────────────▼──────────────────────────────────┐
│              INFRASTRUCTURE LAYER                       │
│   PostgreSQL :5432  ·  Redis :6379  ·  Prometheus :9090 │
│   Grafana :3000     ·  Loki :3100                       │
└─────────────────────────────────────────────────────────┘
```

---

## Pipeline

| Stage | Service | What it does |
|---|---|---|
| 1 | **Scanner** | Probes target across 17 OWASP-mapped categories with real HTTP payload injection |
| 2 | **Simulator** | Receives scanner findings, executes multi-step exploit confirmation |
| 3 | **Validator** | Independently confirms presence of security defences |

The Simulator receives the Scanner's confirmed vulnerability categories and selects only the relevant attack scenarios — it never runs blind.

---

## Features

**Scanner — 17 OWASP Top 10 (2021) categories**
- SQL Injection (error-based, time-based blind, union-based)
- XSS, Path Traversal, Command Injection, XXE Injection
- Authentication Bypass, IDOR, API Enumeration
- SSL/TLS Security, Information Disclosure
- Security Headers, CORS Misconfiguration
- Rate Limiting, CSRF Protection, File Upload Security
- SSRF, Bot Detection

**Simulator — multi-step attacks single-pass scanners cannot perform**
- Second-order SQL injection
- Stored XSS (post then retrieve)
- Session fixation
- Mass assignment / privilege escalation
- CSRF token bypass (3 variants)
- Race conditions on one-time actions
- IDOR enumeration across 5 resource types
- HTTP verb tampering
- JWT RS256 → HS256 algorithm confusion
- GraphQL introspection and batch query abuse
- Insecure direct file download

**Validator — 8 defence confirmation checks**
- Bot protection, Rate limiting, CSRF enforcement
- Session cookie security, Input validation
- Security headers, Robots.txt, Security middleware

**Infrastructure**
- All results persisted to PostgreSQL with IST timestamps
- Prometheus metrics on all services
- Grafana dashboards + Loki log aggregation
- DB-backed cache restore on service restart
- Null-byte sanitisation before DB insertion

---

## Quick Start

### Prerequisites

- Docker Engine 24.0+
- Docker Compose v2.0+
- Python 3.11+ (for the CLI)

### 1. Clone and configure

```bash
git clone <repository-url>
cd saptara
cp .env.example .env
```

Edit `.env` and set your API key:

```env
API_KEYS=your-secret-key-here
```

Generate a strong key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Build and start

```bash
# Build the shared base image first
sudo docker compose build base

# Build all services
sudo docker compose build

# Start everything
sudo docker compose up -d
```

### 3. Verify

```bash
curl http://localhost:8000/health
```

All services should show `healthy`.

### 4. Install the CLI

```bash
pip install -e .
```

### 5. Run your first scan

```bash
saptara scan --target https://example.com --intensity light --wait
```

---

## CLI Reference

```
Usage: saptara [OPTIONS] COMMAND [ARGS]

Options:
  --orchestrator-url URL    Orchestrator URL [default: http://localhost:8000]
  -k, --api-key KEY         API key [env: API_KEYS]
  -v, --verbose             Verbose output
  -h, --help                Show help

Commands:
  health      Check health of all services
  scan        Launch full pipeline scan
  status      Show scan status (--watch for live polling)
  results     Fetch and display results
  cancel      Cancel a running scan
  list-scans  List all scan jobs
```

### Examples

```bash
# Full scan, all categories, medium intensity
saptara scan -t https://target.com --wait

# Light scan, specific categories
saptara scan -t https://target.com -i light \
  -c sql_injection -c xss -c security_headers --wait

# Watch live progress
saptara status <id> --watch

# Get results as JSON
saptara results <id> --format json

# Save results to specific path
saptara results <id> --save /tmp/report.json
```

### Available categories

```
sql_injection       xss                 path_traversal
command_injection   xxe_injection       authentication_bypass
api_enumeration     idor                ssl_tls_security
information_disclosure  security_headers  cors_misconfiguration
rate_limiting       csrf_protection     file_upload_security
ssrf                bot_detection
```

---

## Configuration

All configuration is through environment variables. Copy `.env.example` to `.env`.

| Variable | Default | Description |
|---|---|---|
| `API_KEYS` | `saptara-dev-key-change-me` | Comma-separated valid API keys |
| `DATABASE_URL` | postgres on `database:5432` | SQLAlchemy async connection URL |
| `SCANNER_URL` | `http://scanner:8001` | Scanner service URL |
| `VALIDATOR_URL` | `http://validator:8002` | Validator service URL |
| `SIMULATOR_URL` | `http://simulator:8003` | Simulator service URL |
| `ORCHESTRATOR_URL` | `http://localhost:8000` | Used by the CLI |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

> **Never commit `.env` to version control.** The `.gitignore` already excludes it.

---

## Testing

```bash
# Activate the virtual environment first
source env/bin/activate

# Install the CLI
pip install -e .

# Run all tests
python -m pytest tests/ -v
```

All 14 tests should pass. No running services or database required.

---

## Monitoring

| Service | URL | Credentials |
|---|---|---|
| Grafana | http://localhost:3000 | admin / saptara_vision |
| Prometheus | http://localhost:9090 | — |
| API Docs (Orchestrator) | http://localhost:8000/docs | — |
| API Docs (Scanner) | http://localhost:8001/docs | — |
| API Docs (Validator) | http://localhost:8002/docs | — |
| API Docs (Simulator) | http://localhost:8003/docs | — |

### Query results from PostgreSQL

```bash
sudo docker compose exec database psql -U saptara_keeper -d saptara_knowledge
```

```sql
-- Recent scan jobs
SELECT scan_id, service_name, status, results_count, vulnerabilities_found, started_at
FROM scan_jobs ORDER BY started_at DESC LIMIT 10;

-- Vulnerabilities from a specific scan
SELECT category, test_name, status, vulnerability_level, details
FROM scan_results
WHERE scan_id = '<your-scan-id>'
  AND status IN ('vulnerable', 'failed')
ORDER BY vulnerability_level;
```

---

## Project Structure

```
saptara/
├── cli.py                          # Command-line interface
├── docker-compose.yml              # All seven services
├── Dockerfile.base                 # Shared base image
├── requirements.txt
├── .env.example
│
├── services/
│   ├── orchestrator/               # Pipeline coordinator :8000
│   ├── scanner/                    # Vulnerability scanner :8001
│   │   ├── scanner_engine.py       # 23 test methods, 17 categories
│   │   └── payloads.py             # Payload database
│   ├── validator/                  # Defence validator :8002
│   └── simulator/                  # Attack simulator :8003
│       └── simulator_engine.py     # Multi-step attack scenarios
│
├── shared/
│   ├── models/                     # ScanConfig, TestResult, enums
│   ├── utils/
│   │   ├── http_client.py          # SecurityHTTPClient (6 injection modes)
│   │   ├── logger.py
│   │   └── timezone.py             # IST timestamps
│   ├── auth.py                     # API key validation
│   ├── db.py                       # SQLAlchemy ORM + sanitize()
│   └── metrics.py                  # Prometheus metrics
│
├── monitoring/
│   ├── prometheus.yml
│   ├── promtail.yml
│   └── grafana_dashboard.json
│
├── tests/
│   ├── test_scanner_engine.py
│   ├── test_simulator_engine.py
│   └── test_validator_engine.py
│
└── results/                        # Auto-saved scan JSON files
```

---

## Ethical Use

SAPTARA is designed for **authorised security testing only**.

- Only test systems you own or have **explicit written permission** to test
- Unauthorised security testing is illegal in most jurisdictions
- Follow responsible disclosure practices for any vulnerabilities found
- The authors accept no liability for misuse of this tool

---

## License

This project is licensed under the SAPTARA Academic and Research License.
See [LICENSE](./LICENSE) for full terms.

---

*"In unity, the seven relics find their strength."*
