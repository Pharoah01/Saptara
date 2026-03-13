# Base Dockerfile for all services
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy shared modules
COPY shared/ ./shared/

# Copy service-specific code (will be overridden in service-specific Dockerfiles)
COPY services/ ./services/

# Create non-root user
RUN useradd --create-home --shell /bin/bash security-user
USER security-user

# Default command (will be overridden in service-specific Dockerfiles)
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]