FROM python:3.12-slim

# Install ttyd and system dependencies
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

# Install Python dependencies
RUN pip install pipenv

# Copy only Pipfile and Pipfile.lock first
COPY Pipfile Pipfile.lock ./

# Install dependencies without virtualenv (--system)
# Remove --deploy flag for now or ensure lock file is up to date
RUN pipenv install --system

# Copy application code
COPY . .

# Expose ports
EXPOSE 7681 5000

# Start the server
CMD ["python", "wrapper/server.py"]