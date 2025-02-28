FROM python:3.12-slim

ENV IS_CONTAINER=true \
    PYTHONUNBUFFERED=1 \
    PORT=80 \
    POETRY_VERSION=1.7.1 \
    POETRY_HOME=/opt/poetry \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

WORKDIR /app

# Install only essential build dependencies and clean up in the same layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    libwebsockets-dev \
    libjson-c-dev \
    curl \
    && wget https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 \
    && chmod +x ttyd.x86_64 \
    && mv ttyd.x86_64 /usr/local/bin/ttyd \
    && apt-get purge -y wget \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry

# Copy only pyproject.toml first
COPY pyproject.toml ./

# Install dependencies
RUN poetry install --no-root --only main

# Copy application files
COPY . .

EXPOSE 80

CMD ["python", "app/server.py"]