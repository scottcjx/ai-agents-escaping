# Build context is docker/ (see docker-compose.yml).
FROM python:3.12-slim
# ping + ip route, so the agent can PROVE it has no internet.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping iproute2 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Single source of truth: the same crypto_demo.py the host publisher uses.
COPY common/crypto_demo.py /app/crypto_demo.py
COPY agent/agent_main.py /app/agent_main.py
CMD ["python", "-u", "agent_main.py"]
