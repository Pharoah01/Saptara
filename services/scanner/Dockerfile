FROM saptara-base

COPY services/scanner/ ./services/scanner/

RUN useradd --create-home --shell /bin/bash app-user && \
    chown -R app-user:app-user /app
USER app-user

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

CMD ["python", "-m", "uvicorn", "services.scanner.main:app", \
     "--host", "0.0.0.0", "--port", "8001"]
