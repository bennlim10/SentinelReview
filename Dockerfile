FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8000

WORKDIR /app

RUN addgroup --system sentinelreview \
    && adduser --system --ingroup sentinelreview --home /home/sentinelreview sentinelreview

COPY pyproject.toml README.md LICENSE ./
COPY app ./app

RUN python -m pip install --upgrade pip \
    && python -m pip install .

USER sentinelreview

EXPOSE 8000

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
