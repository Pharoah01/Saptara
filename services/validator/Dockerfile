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

# Copy validator service
COPY services/validator/ ./services/validator/

# Create non-root user
RUN useradd --create-home --shell /bin/bash validator-user
USER validator-user

# Expose port
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Start validator service
CMD ["python", "-m", "uvicorn", "services.validator.main:app", "--host", "0.0.0.0", "--port", "8002"]