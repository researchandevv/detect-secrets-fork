FROM python:3.11-slim AS builder

WORKDIR /app
COPY . .
RUN pip install --no-cache-dir ".[word_doc]" && \
    pip install --no-cache-dir gibberish-detector

FROM python:3.11-slim

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/detect-secrets /usr/local/bin/detect-secrets
COPY --from=builder /app /app

WORKDIR /scan
ENTRYPOINT ["detect-secrets"]
CMD ["scan", "."]
