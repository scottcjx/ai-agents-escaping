# Build context is docker/ (see docker-compose.yml).
FROM python:3.12-slim
# ping, so the proxy can PROVE it does have internet.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY proxy/proxy_server.py /app/proxy_server.py
EXPOSE 8080
CMD ["python", "-u", "proxy_server.py"]
