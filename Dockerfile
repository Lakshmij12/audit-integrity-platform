# Audit Integrity Platform: FastAPI service over SQLite.
#
# Build:  docker build -t audit-integrity-platform .
# Keys:   docker run --rm audit-integrity-platform python -m aip.cli new-api-key --role writer
#         docker run --rm -v aip-keys:/app/keys audit-integrity-platform \
#             python -m aip.cli new-signing-key --out keys/signing.pem
# Run:    docker run -d --name aip -p 127.0.0.1:8000:8000 \
#             -e AIP_API_KEYS="writer:<hex>,auditor:<hex>,admin:<hex>" \
#             -e AIP_SIGNING_KEY_PATH=keys/signing.pem \
#             -v aip-data:/app/data -v aip-archives:/app/archives -v aip-keys:/app/keys \
#             audit-integrity-platform
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # The project is not pip-installed; aip is imported from src (see docs/DEVELOPMENT.md).
    PYTHONPATH=/app/src

WORKDIR /app

# Runtime dependencies only, hash-checked against the lock file.
COPY requirements.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock

COPY src ./src
COPY tools ./tools

# Non-root user; data, archives and keys are owned by it so named volumes inherit the ownership.
RUN useradd --system --uid 10001 --no-create-home app \
 && install -d -o app -g app -m 0700 /app/data /app/archives /app/keys /app/exports
USER app

VOLUME ["/app/data", "/app/archives", "/app/keys"]
EXPOSE 8000

# The service has no health endpoint; the OpenAPI document needs no API key.
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import sys, urllib.request; sys.exit(urllib.request.urlopen('http://127.0.0.1:8000/openapi.json').status != 200)"

CMD ["uvicorn", "aip.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
