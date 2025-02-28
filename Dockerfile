FROM python:3.12-slim

ENV IS_CONTAINER=true \
    PYTHONUNBUFFERED=1 \
    PORT=80

WORKDIR /app

# Install only essential build dependencies and clean up in the same layer
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    libwebsockets-dev \
    libjson-c-dev \
    && wget https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 \
    && chmod +x ttyd.x86_64 \
    && mv ttyd.x86_64 /usr/local/bin/ttyd \
    && apt-get purge -y wget \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY Pipfile Pipfile.lock ./
RUN pip install --no-cache-dir pipenv && \
    pipenv install --system --deploy && \
    pip uninstall -y pipenv virtualenv-clone virtualenv

# Copy application files
COPY . .

EXPOSE 80
CMD ["python", "app/server.py"]