# Runs the HTTP API and dashboard as a non-root user with state kept in a volume.
#   docker build -t tip-platform .
#   docker run -p 8000:8000 -e TIP_API_KEY=change-me -v tip-data:/data tip-platform
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TIP_DB_PATH=/data/tip.db \
    TIP_FEEDS_FILE=/app/data/samples/feeds.json

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
RUN pip install --no-cache-dir . \
    && mkdir -p /data \
    && useradd --system --uid 10001 tip \
    && chown tip:tip /data

USER tip
VOLUME ["/data"]
EXPOSE 8000
CMD ["tip", "serve", "--host", "0.0.0.0", "--port", "8000"]
