FROM python:3.12-slim

WORKDIR /app

# # Install only essential build dependencies and clean up in the same layer
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     wget \
#     libwebsockets-dev \
#     libjson-c-dev \
#     curl \
#     && wget https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 \
#     && chmod +x ttyd.x86_64 \
#     && mv ttyd.x86_64 /usr/local/bin/ttyd \
#     && apt-get purge -y wget \
#     && apt-get autoremove -y \
#     && apt-get clean \
#     && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN pip install --no-cache-dir poetry

# Copy only pyproject.toml first
COPY pyproject.toml ./

# Install dependencies AND the package itself
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --only main --no-root

# Copy application files
COPY app/ .

EXPOSE 80

CMD ["python", "server.py"]