# Build from the BearBreach repository root so the shared corpus is accessible.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/app/.cache/huggingface \
    SEMANTIC_DETECTOR_CONFIG=services/semantic-detector/config/config.yaml

WORKDIR /app

# Install the CPU-only PyTorch build to avoid unnecessary CUDA packages.
COPY services/semantic-detector/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Paths match the relative paths specified in config.yaml.
COPY services/semantic-detector/ services/semantic-detector/
COPY libraries/semantic-corpus/curated/references.jsonl libraries/semantic-corpus/curated/references.jsonl

# The model is downloaded into the writable Hugging Face cache on first startup.
RUN useradd --create-home --uid 10001 detector \
    && mkdir -p /app/.cache/huggingface /app/services/semantic-detector/artifacts \
    && chown -R detector:detector /app/.cache /app/services/semantic-detector/artifacts
USER detector

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health/ready', timeout=3)" || exit 1

CMD ["python", "-m", "uvicorn", "main:app", "--app-dir", "services/semantic-detector/app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]
