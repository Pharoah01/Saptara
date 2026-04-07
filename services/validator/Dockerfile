FROM saptara-base

COPY services/validator/ ./services/validator/

RUN useradd --create-home --shell /bin/bash app-user && \
    chown -R app-user:app-user /app
USER app-user

EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

CMD ["python", "-m", "uvicorn", "services.validator.main:app", \
     "--host", "0.0.0.0", "--port", "8002"]
