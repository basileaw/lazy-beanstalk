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
    curl \
    && wget https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 \
    && chmod +x ttyd.x86_64 \
    && mv ttyd.x86_64 /usr/local/bin/ttyd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install pipenv
RUN pip install pipenv

# Copy Pipfile and Pipfile.lock first for better caching
COPY Pipfile* /app/

# Install dependencies
RUN pipenv install --deploy --system

# Copy the rest of the application
COPY . /app/

# Expose necessary ports
EXPOSE 7681
EXPOSE 5000

# Start the server
CMD ["python", "wrapper/server.py"]