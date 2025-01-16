# Dockerfile
FROM python:3.12-slim

# Install system dependencies
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
COPY Pipfile Pipfile.lock ./
RUN pipenv install --system --deploy

# Copy application files
COPY . .

# Expose port 80 for production
EXPOSE 80

# Set environment variables
ENV IS_CONTAINER=true
ENV PYTHONUNBUFFERED=1
ENV PORT=80

# Run the FastAPI server directly
CMD ["python", "backend/server.py"]