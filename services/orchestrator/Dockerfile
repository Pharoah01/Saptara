FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY shared/ ./shared/

# Copy orchestrator service
COPY services/orchestrator/ ./services/orchestrator/

# Create non-root user
RUN useradd --create-home --shell /bin/bash orchestrator-user
USER orchestrator-user

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Start orchestrator service
CMD ["python", "-m", "uvicorn", "services.orchestrator.main:app", "--host", "0.0.0.0", "--port", "8000"]