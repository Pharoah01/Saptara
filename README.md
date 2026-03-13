# 🛡️ Project SAPTARA
## *Seven relics. Seven roles. One system.*

**SAPTARA** — *a system where protection emerges from unity.*

A comprehensive, production-ready security testing framework built with microservices architecture. Inspired by the concept of seven protective layers working together as a unified system, each service represents a distinct role within the security architecture, emphasizing collaboration, resilience, and layered protection.

## 🏗️ The Seven Relics - Architecture Overview

SAPTARA is composed of seven core protective layers, each serving a distinct role in the unified security system:

### The Seven Relics (Core Services)
- **🎯 The Orchestrator** (Port 8000) - *The Conductor* - Coordinates and harmonizes all security testing services
- **🔍 The Scanner** (Port 8001) - *The Seeker* - Universal vulnerability scanner with 12+ test categories  
- **✅ The Validator** (Port 8002) - *The Guardian* - Security feature validation and verification service
- **🚀 The Simulator** (Port 8003) - *The Challenger* - Attack simulation and penetration testing
- **🗄️ The Keeper** (PostgreSQL, Port 5432) - *The Memory* - Persistent storage for all test results and knowledge
- **🔄 The Messenger** (Redis, Port 6379) - *The Swift* - Real-time communication and task coordination
- **📊 The Observer** (Prometheus + Grafana, Ports 9090/3000) - *The Watcher* - Monitoring, metrics, and insights

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Python 3.11+ (for local development)
- 4GB+ RAM recommended

### 1. Clone and Setup
```bash
git clone <repository-url>
cd security-test
```

### 2. Start All Services
```bash
# Start all services with Docker Compose
docker-compose up -d

# Check service health
curl http://localhost:8000/health
```

### 3. Invoke Your First Security Test
```bash
# Using the Orchestrator (The Conductor)
curl -X POST "http://localhost:8000/orchestrate" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "target_url": "https://example.com",
      "test_categories": ["sql_injection", "xss", "path_traversal"],
      "intensity": "medium"
    },
    "services": ["scanner", "validator"],
    "parallel": true
  }'
```

## 🔧 Development Setup

### Local Development
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start individual services for development
python -m uvicorn services.orchestrator.main:app --reload --port 8000
python -m uvicorn services.scanner.main:app --reload --port 8001
```

### Environment Variables
Create a `.env` file in the project root:
```env
# Service Configuration
LOG_LEVEL=INFO
DATABASE_URL=postgresql://security_user:security_pass@localhost:5432/security_test
REDIS_URL=redis://localhost:6379

# Security Configuration
MAX_CONCURRENT_SCANS=10
DEFAULT_TIMEOUT=30
RATE_LIMIT_PER_SECOND=10

# Monitoring
PROMETHEUS_ENABLED=true
GRAFANA_ADMIN_PASSWORD=admin
```

## 📊 API Documentation

### Orchestrator Service (Port 8000)
- `GET /` - Health check
- `GET /health` - Detailed health check with service status
- `POST /orchestrate` - Start orchestrated security testing
- `GET /orchestration/{id}/status` - Get orchestration status
- `GET /orchestration/{id}/results` - Get complete results
- `GET /services` - List all available services

### Scanner Service (Port 8001)
- `GET /` - Health check
- `POST /scan` - Start vulnerability scan
- `GET /scan/{id}/status` - Get scan status
- `GET /scan/{id}/results` - Get scan results
- `DELETE /scan/{id}` - Cancel running scan

### Interactive API Documentation
- Orchestrator: http://localhost:8000/docs
- Scanner: http://localhost:8001/docs
- Validator: http://localhost:8002/docs
- Simulator: http://localhost:8003/docs

## 🔍 Test Categories

### The Scanner (The Seeker)
1. **SQL Injection** - Database manipulation attacks
2. **Path Traversal** - File system access attempts
3. **XSS** - Cross-site scripting vulnerabilities
4. **Authentication Bypass** - Access control circumvention
5. **Rate Limiting** - Request flooding protection
6. **Bot Detection** - Automated tool identification
7. **API Enumeration** - Endpoint discovery
8. **File Upload Security** - Malicious file upload tests
9. **Information Disclosure** - Sensitive data exposure
10. **CSRF Protection** - Cross-site request forgery
11. **Security Headers** - HTTP security headers validation
12. **SSL/TLS Security** - Transport layer security

### The Validator (The Guardian)
- Bot Protection Middleware validation
- Security Middleware effectiveness
- Rate limiting configuration
- Session security implementation
- Input validation mechanisms

### The Simulator (The Challenger)
- Targeted attack simulations
- Penetration testing scenarios
- Security measure bypass attempts
- Real-world attack patterns

## 📈 Monitoring and Observability

### The Observer's Metrics (Prometheus)
- Request rates and response times across all relics
- Error rates and success rates for each protective layer
- Service health and availability monitoring
- Resource utilization and performance metrics

### The Watcher's Dashboards (Grafana)
- SAPTARA System Overview
- Individual Relic Performance Metrics
- Vulnerability Detection Trends
- Unified System Resource Monitoring

Access Grafana at http://localhost:3000 (admin/admin)

## 🔒 Security Considerations

### Ethical Use
- **Only test systems you own** or have explicit written permission to test
- **Unauthorized testing may be illegal** in your jurisdiction
- **Follow responsible disclosure** practices for any vulnerabilities found

### Production Deployment
- Use strong authentication for all services
- Enable TLS/SSL for all communications
- Implement proper network segmentation
- Regular security updates and patches
- Monitor and log all activities

## 🧪 Testing

### Unit Tests
```bash
# Run unit tests
pytest tests/unit/

# Run with coverage
pytest tests/unit/ --cov=services --cov-report=html
```

### Integration Tests
```bash
# Run integration tests
pytest tests/integration/

# Test specific service
pytest tests/integration/test_scanner.py
```

### Load Testing
```bash
# Install load testing tools
pip install locust

# Run load tests
locust -f tests/load/test_orchestrator.py --host=http://localhost:8000
```

## 📦 Deployment

### Docker Deployment
```bash
# Build and deploy
docker-compose up -d --build

# Scale services
docker-compose up -d --scale scanner=3 --scale validator=2

# View logs
docker-compose logs -f orchestrator
```

### Kubernetes Deployment
```bash
# Apply Kubernetes manifests
kubectl apply -f k8s/

# Check deployment status
kubectl get pods -n security-test
```

### Production Checklist
- [ ] Configure proper resource limits
- [ ] Set up persistent storage
- [ ] Configure backup strategies
- [ ] Implement monitoring and alerting
- [ ] Set up log aggregation
- [ ] Configure security policies
- [ ] Test disaster recovery procedures

## 🔧 Configuration

### Service Configuration
Each service can be configured via environment variables or configuration files:

```yaml
# config/scanner.yml
scanner:
  max_concurrent_scans: 10
  default_timeout: 30
  payload_database: "extended"
  rate_limiting:
    requests_per_second: 10
    burst_size: 20
```

### Database Configuration
```yaml
# config/database.yml
database:
  host: localhost
  port: 5432
  name: security_test
  user: security_user
  password: security_pass
  pool_size: 20
  max_overflow: 30
```

## 🐛 Debugging

### Service Logs
```bash
# View orchestrator logs
docker-compose logs -f orchestrator

# View all service logs
docker-compose logs -f

# Debug specific service
docker-compose exec scanner python -m pdb services/scanner/main.py
```

### Health Checks
```bash
# Check all service health
curl http://localhost:8000/health

# Check individual service
curl http://localhost:8001/health
```

### Database Debugging
```bash
# Connect to database
docker-compose exec database psql -U security_user -d security_test

# View test results
SELECT * FROM test_results ORDER BY timestamp DESC LIMIT 10;
```

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

### Code Style
- Follow PEP 8 for Python code
- Use type hints for all functions
- Add docstrings for all public methods
- Format code with Black
- Lint with flake8

### Adding New Test Categories
1. Add the test category to `shared/models/scan_config.py`
2. Implement the test logic in the appropriate service
3. Add payloads to the payload database
4. Write unit and integration tests
5. Update documentation

## 📚 Documentation

### Quick Start
- **[Getting Started Guide](docs/GETTING_STARTED.md)** - Setup and first security test in 5 minutes
- **[CLI Reference](docs/CLI_REFERENCE.md)** - Complete command-line interface documentation

### Architecture & APIs
- **[Architecture Guide](docs/ARCHITECTURE_GUIDE.md)** - System design and microservices architecture
- **[API Documentation](docs/API_DOCUMENTATION.md)** - REST API reference for all services

### Deployment & Configuration
- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** - Docker, Kubernetes, and cloud deployment
- **[Configuration Guide](docs/CONFIGURATION_GUIDE.md)** - Environment and service configuration

### Development & Testing
- **[Development Guide](docs/DEVELOPMENT_GUIDE.md)** - Local development setup and guidelines
- **[Testing Guide](docs/TESTING_GUIDE.md)** - Unit, integration, and end-to-end testing

### Additional Resources
- **[Security Best Practices](docs/SECURITY_BEST_PRACTICES.md)** - Security guidelines and best practices
- **[Troubleshooting Guide](docs/TROUBLESHOOTING_GUIDE.md)** - Common issues and solutions
- **[Documentation Index](docs/README.md)** - Complete documentation overview

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- Create an issue for bug reports
- Join our Discord for community support
- Check the documentation for common questions
- Contact the maintainers for security issues

---

**Remember**: SAPTARA is for authorized security testing only. The seven relics work in unity to protect - ensure you have proper permission before testing any system! 🛡️

*"In unity, the seven relics find their strength. In separation, they are but tools. Together, they are SAPTARA."*