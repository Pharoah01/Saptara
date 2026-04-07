FROM saptara-base

COPY services/orchestrator/ ./services/orchestrator/

RUN useradd --create-home --shell /bin/bash app-user && \
    chown -R app-user:app-user /app
USER app-user

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["python", "-m", "uvicorn", "services.orchestrator.main:app", \
     "--host", "0.0.0.0", "--port", "8000"]
