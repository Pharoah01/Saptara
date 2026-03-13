# Security Testing Suite Makefile

.PHONY: help install dev-install test lint format clean build up down logs health

# Default target
help:
	@echo "🛡️  Security Testing Suite - Available Commands"
	@echo "================================================"
	@echo "Development:"
	@echo "  install      Install production dependencies"
	@echo "  dev-install  Install development dependencies"
	@echo "  test         Run all tests"
	@echo "  lint         Run linting checks"
	@echo "  format       Format code with black"
	@echo ""
	@echo "Docker Operations:"
	@echo "  build        Build all Docker images"
	@echo "  up           Start all services"
	@echo "  down         Stop all services"
	@echo "  logs         View service logs"
	@echo "  health       Check service health"
	@echo ""
	@echo "Utilities:"
	@echo "  clean        Clean up temporary files"
	@echo "  reset        Reset all data and restart services"

# Installation
install:
	pip install -r requirements.txt

dev-install:
	pip install -r requirements.txt
	pip install pytest pytest-cov black flake8 mypy

# Testing
test:
	pytest tests/ -v --cov=services --cov-report=html --cov-report=term

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

# Code Quality
lint:
	flake8 services/ shared/ tests/
	mypy services/ shared/

format:
	black services/ shared/ tests/
	isort services/ shared/ tests/

# Docker Operations
build:
	docker-compose build

up:
	docker-compose up -d
	@echo "🚀 Services starting up..."
	@echo "Orchestrator: http://localhost:8000"
	@echo "Scanner: http://localhost:8001"
	@echo "Validator: http://localhost:8002"
	@echo "Simulator: http://localhost:8003"
	@echo "Grafana: http://localhost:3000"

down:
	docker-compose down

logs:
	docker-compose logs -f

logs-orchestrator:
	docker-compose logs -f orchestrator

logs-scanner:
	docker-compose logs -f scanner

# Health Checks
health:
	@echo "🔍 Checking service health..."
	@curl -s http://localhost:8000/health | jq '.' || echo "Orchestrator: ❌ Unhealthy"
	@curl -s http://localhost:8001/health | jq '.' || echo "Scanner: ❌ Unhealthy"
	@curl -s http://localhost:8002/health | jq '.' || echo "Validator: ❌ Unhealthy"
	@curl -s http://localhost:8003/health | jq '.' || echo "Simulator: ❌ Unhealthy"

# Development
dev-up:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

dev-logs:
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml logs -f

# Database Operations
db-migrate:
	docker-compose exec orchestrator alembic upgrade head

db-reset:
	docker-compose exec database psql -U security_user -d security_test -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	$(MAKE) db-migrate

# Utilities
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .coverage htmlcov/ .pytest_cache/

reset: down clean
	docker-compose down -v
	docker system prune -f
	$(MAKE) build up

# Load Testing
load-test:
	locust -f tests/load/test_orchestrator.py --host=http://localhost:8000 --users=10 --spawn-rate=2 --run-time=60s --headless

# Security Scan (self-test)
self-test:
	@echo "🔍 Running self-test security scan..."
	curl -X POST "http://localhost:8000/orchestrate" \
		-H "Content-Type: application/json" \
		-d '{"config": {"target_url": "http://localhost:8000", "test_categories": ["api_enumeration", "security_headers"], "intensity": "light"}, "services": ["scanner"], "parallel": false}'

# Monitoring
monitor:
	@echo "📊 Opening monitoring dashboards..."
	@echo "Prometheus: http://localhost:9090"
	@echo "Grafana: http://localhost:3000 (admin/admin)"
	open http://localhost:3000 || xdg-open http://localhost:3000 || echo "Open http://localhost:3000 manually"

# Documentation
docs:
	mkdocs serve

docs-build:
	mkdocs build

# Release
release-patch:
	bump2version patch

release-minor:
	bump2version minor

release-major:
	bump2version major