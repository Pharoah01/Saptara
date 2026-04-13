# 🛡️ Project SAPTARA
*Seven relics. Seven roles. One system.*

SAPTARA is a microservices-based security testing framework. Give it a target URL and it runs a full three-stage pipeline — **Scanner → Simulator → Validator** — persisting every result to PostgreSQL.

---

## Architecture

| Relic | Role | Port |
|---|---|---|
| Orchestrator | Runs the pipeline, aggregates results | 8000 |
| Scanner | 17-category vulnerability scanner | 8001 |
| Simulator | Multi-step exploit & blind-spot coverage | 8002 |
| Validator | Confirms defences are in place | 8003 |
| PostgreSQL | Persistent result storage | 5432 |
| Redis | Available for caching / queuing | 6379 |
| Prometheus | Metrics scraping | 9090 |
| Grafana | Dashboards | 3000 |

### Pipeline flow

```
POST /orchestrate
      │
      ▼
  [Scanner]  ── finds vulnerabilities (17 categories)
      │
      ▼
  [Simulator] ── exploits findings + covers blind spots
      │           (race conditions, stored XSS, IDOR,
      │            second-order SQLi, JWT confusion, etc.)
      ▼
  [Validator] ── confirms which defences are active
      │
      ▼
  Results saved to PostgreSQL + returned to client
```

---

## Prerequisites

- Docker and Docker Compose v2
- Python 3.11+ (local dev only)
- 4 GB RAM minimum

---

## Running with Docker (recommended)

### 1. Copy and configure environment

```bash
cp .env.example .env
```

The only value you must change before running:

```env
# .env
API_KEYS=your-secret-key-here   # used by all services and the CLI
```

Everything else has working defaults for local use.

### 2. Build the base image first

The four services share a common base image. Build it once:

```bash
docker compose build base
```

Or use the Makefile shortcut:

```bash
make build
```

### 3. Start all services

```bash
docker compose up -d
```

Or:

```bash
make up
```

Services start in dependency order. The orchestrator waits for PostgreSQL to be healthy before accepting requests.

### 4. Verify everything is up

```bash
curl http://localhost:8000/health
```

Expected response shows all three downstream services as `healthy`.

Or use the Makefile:

```bash
make health
```

---

## Running locally (without Docker)

Requires PostgreSQL running and accessible.

### 1. Create and activate a virtual environment

```bash
python3 -m venv env
source env/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set environment variables

```bash
export DATABASE_URL=postgresql+asyncpg://saptara_keeper:seven_relics_unite@localhost:5432/saptara_knowledge
export API_KEYS=saptara-dev-key-change-me
```

Or put them in a `.env` file — the CLI and services load it automatically via `python-dotenv`.

### 4. Start each service in a separate terminal

```bash
# Terminal 1 — Scanner
python -m uvicorn services.scanner.main:app --port 8001

# Terminal 2 — Simulator
python -m uvicorn services.simulator.main:app --port 8003

# Terminal 3 — Validator
python -m uvicorn services.validator.main:app --port 8002

# Terminal 4 — Orchestrator
python -m uvicorn services.orchestrator.main:app --port 8000
```

---

## Running a scan

### Using the CLI

```bash
# Basic scan — medium intensity, common categories
python cli.py --api-key your-secret-key-here scan --target https://example.com

# Light scan, specific categories
python cli.py -k your-secret-key-here scan \
  --target https://example.com \
  --intensity light \
  --categories sql_injection xss security_headers

# Heavy scan, wait for results and print them
python cli.py -k your-secret-key-here scan \
  --target https://example.com \
  --intensity heavy \
  --wait

# Save results to a file
python cli.py -k your-secret-key-here results <orchestration-id> --save results.json
```

Available intensity levels: `light`, `medium`, `heavy`

Available categories:
```
sql_injection       xss                 path_traversal
command_injection   xxe_injection       authentication_bypass
api_enumeration     idor                ssl_tls_security
information_disclosure  security_headers  cors_misconfiguration
rate_limiting       csrf_protection     file_upload_security
ssrf                bot_detection
```

### Using curl directly

```bash
# Start a scan
curl -X POST http://localhost:8000/orchestrate \
  -H "Content-Type: application/json" \
  -H "X-API-Key: saptara-dev-key-change-me" \
  -d '{
    "config": {
      "target_url": "https://example.com",
      "test_categories": ["sql_injection", "xss", "security_headers"],
      "intensity": "medium"
    }
  }'

# Returns: { "orchestration_id": "...", "status": "running", ... }

# Poll status
curl http://localhost:8000/orchestration/<id>/status \
  -H "X-API-Key: saptara-dev-key-change-me"

# Get results
curl http://localhost:8000/orchestration/<id>/results \
  -H "X-API-Key: saptara-dev-key-change-me"
```

### CLI reference

```bash
python cli.py --help

Commands:
  health      Check health of all services
  scan        Start a scan (Scanner → Simulator → Validator)
  status      Check status of a running scan
  results     Fetch results of a completed scan
  cancel      Cancel a running scan
  list-scans  List all scans
```

---

## Running tests

```bash
python -m pytest tests/ -v
```

All 14 tests should pass. No database or running services required — the engine tests run against `https://example.com` with real HTTP calls.

---

## Viewing results

### Interactive API docs

| Service | URL |
|---|---|
| Orchestrator | http://localhost:8000/docs |
| Scanner | http://localhost:8001/docs |
| Validator | http://localhost:8002/docs |
| Simulator | http://localhost:8003/docs |

### Grafana dashboards

Open http://localhost:3000 — login with `admin` / `saptara_vision`

### PostgreSQL directly

```bash
docker compose exec database psql -U saptara_keeper -d saptara_knowledge

# All scan jobs
SELECT scan_id, service_name, status, results_count, vulnerabilities_found, started_at
FROM scan_jobs ORDER BY started_at DESC LIMIT 20;

# Vulnerabilities from a specific scan
SELECT category, test_name, status, vulnerability_level, details
FROM scan_results
WHERE scan_id = '<your-scan-id>'
  AND status IN ('vulnerable', 'failed')
ORDER BY vulnerability_level;
```

---

## Stopping services

```bash
docker compose down          # stop containers, keep volumes
docker compose down -v       # stop containers and delete DB data
```

---

## Useful Makefile targets

```bash
make build    # build base image + all service images
make up       # docker compose up -d
make down     # docker compose down
make logs     # follow all logs
make health   # curl all four health endpoints
make test     # run pytest
make clean    # remove __pycache__, .pyc, coverage files
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `API_KEYS` | `saptara-dev-key-change-me` | Comma-separated valid API keys |
| `DATABASE_URL` | postgres on `database:5432` | SQLAlchemy async URL |
| `SCANNER_URL` | `http://scanner:8001` | Scanner service URL (orchestrator) |
| `VALIDATOR_URL` | `http://validator:8002` | Validator service URL (orchestrator) |
| `SIMULATOR_URL` | `http://simulator:8003` | Simulator service URL (orchestrator) |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `ORCHESTRATOR_URL` | `http://localhost:8000` | Used by the CLI |

---

## Ethical use

Only test systems you own or have explicit written permission to test. Unauthorised security testing is illegal in most jurisdictions.
