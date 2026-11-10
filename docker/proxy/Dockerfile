# Build context is docker/ (see docker-compose.yml).
FROM python:3.12-slim
# ping, so the proxy can PROVE it does have internet.
# ca-certificates, so HTTPS fetches to real upstream hosts (dpaste.com,
# paste.rs, ...) can verify the server cert instead of failing with
# CERTIFICATE_VERIFY_FAILED (python:3.12-slim ships no trusted root CAs).
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY proxy/proxy_server.py /app/proxy_server.py
EXPOSE 8080
CMD ["python", "-u", "proxy_server.py"]
