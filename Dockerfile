FROM python:3.12-slim

# Install ttyd and other required system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    cmake \
    git \
    pkg-config \
    libjson-c-dev \
    libwebsockets-dev \
    && wget https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 \
    && chmod +x ttyd.x86_64 \
    && mv ttyd.x86_64 /usr/local/bin/ttyd

# Install poetry
RUN pip install poetry

WORKDIR /app

# Copy project files
COPY pyproject.toml poetry.lock ./
COPY client.py server.py ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi --no-root

# Start ttyd with your Python app
CMD ["ttyd", "-p", "7681", "python", "client.py"]