FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS build
ENV PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --prefix=/install -r requirements.txt

FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 PORT=8000
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl openssh-client tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 app \
 && useradd -u 10001 -g 10001 -m -s /usr/sbin/nologin app \
 && mkdir -p /data \
 && chown app:app /data
WORKDIR /app
COPY --from=build /install /usr/local
COPY main.py index.html ./
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fs "http://127.0.0.1:${PORT}/api/health" || exit 1
ENTRYPOINT ["tini", "--"]
CMD ["sh", "-c", "exec uvicorn main:app --host \"$HOST\" --port \"$PORT\""]
