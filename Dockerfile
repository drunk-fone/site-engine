# Site-Engine – Schlankes, gehärtetes Image (nur Python-Standardbibliothek)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DATA_DIR=/data \
    PUBLIC_DIR=/app/public \
    CONFIG_FILE=/app/config/site.json

WORKDIR /app
RUN groupadd --system --gid 10001 engine \
 && useradd --system --uid 10001 --gid engine --no-create-home --shell /usr/sbin/nologin engine \
 && mkdir -p /data && chown engine:engine /data

COPY --chown=root:root app/server.py /app/server.py
COPY --chown=root:root app/config /app/config
COPY --chown=root:root app/public /app/public

USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('PORT','8080'),timeout=2)"
CMD ["python", "/app/server.py"]
