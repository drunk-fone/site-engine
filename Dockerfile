# syntax=docker/dockerfile:1
# Site-Engine – minimales, gehärtetes Image (nur Python-Standardbibliothek)
#
# Stufe 1 entschlackt den offiziellen Python-Build (kein pip, keine Test-/GUI-Module).
# Stufe 2 ist "distroless": keine Shell, kein Paketmanager, keine Coreutils –
# nur glibc, OpenSSL, CA-Zertifikate, Zeitzonen und der Python-Interpreter.
# Base-Images sind per Digest gepinnt; Renovate hält die Digests aktuell.

ARG PYTHON_IMAGE=python:3.14-slim@sha256:9aaa474097d094040649f2162a627c0049b408f52138d980916788d80f04802f
ARG RUNTIME_IMAGE=gcr.io/distroless/base-debian13:nonroot@sha256:a08d9054afbaf1af9b90fd02cdc7b32236319b5376d374505a41548d42b0c5db

FROM ${PYTHON_IMAGE} AS python
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade libbz2-1.0 liblzma5 \
 && rm -rf /var/lib/apt/lists/*
RUN PY=/usr/local/lib/python3.14 \
 # Nicht benötigte Teile entfernen (pip & Co. sind die häufigsten Scanner-Funde)
 && rm -rf "$PY"/site-packages/* "$PY"/ensurepip "$PY"/idlelib "$PY"/tkinter "$PY"/turtledemo \
           "$PY"/test "$PY"/pydoc_data "$PY"/sqlite3 "$PY"/curses "$PY"/ctypes "$PY"/dbm "$PY"/__phello__ \
           "$PY"/config-3.14-* /usr/local/include /usr/local/share /usr/local/lib/pkgconfig \
 && (cd "$PY"/lib-dynload && rm -f _curses* _dbm* _gdbm* _sqlite3* _tkinter* readline* _test* xx* \
           _xxtestfuzz* _ctypes* _uuid* _remote_debugging*) \
 && rm -f /usr/local/bin/pip* /usr/local/bin/idle* /usr/local/bin/pydoc* /usr/local/bin/*-config \
 && find /usr/local -depth -name __pycache__ -exec rm -rf {} + \
 && python3 -m compileall -q -j0 "$PY" \
 # Zusätzliche Laufzeit-Bibliotheken (nicht in distroless/base) inkl. dpkg-Eintrag für Scanner
 && MA="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH"))')" \
 && mkdir -p "/out/usr/lib/$MA" /out/var/lib/dpkg/status.d /outdata \
 && for p in libbz2-1.0 liblzma5; do \
      dpkg-query -s "$p" > "/out/var/lib/dpkg/status.d/$p"; \
      dpkg -L "$p" | grep -E '\.so(\.|$)' | xargs -I{} cp -a {} "/out/usr/lib/$MA/"; \
    done \
 # Selbsttest: alle Module, die der Server braucht, müssen laden
 && python3 -c "import ssl, hashlib, hmac, zlib, bz2, lzma, zipfile, json, smtplib, email, http.server, fcntl, mimetypes, csv"

FROM ${RUNTIME_IMAGE}
ENV PATH=/usr/local/bin:/usr/bin:/bin \
    LANG=C.UTF-8 \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DATA_DIR=/data \
    PUBLIC_DIR=/app/public \
    ADMIN_DIR=/app/admin \
    CONFIG_FILE=/app/config/site.json

COPY --from=python /usr/local /usr/local
COPY --from=python /out/ /
COPY --from=python --chown=10001:10001 /outdata /data
COPY --chown=root:root app/server.py /app/server.py
COPY --chown=root:root app/config /app/config
COPY --chown=root:root app/public /app/public
COPY --chown=root:root app/admin /app/admin

WORKDIR /app
USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["python", "-c", "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:%s/healthz'%os.environ.get('PORT','8080'),timeout=2)"]
CMD ["python", "/app/server.py"]
