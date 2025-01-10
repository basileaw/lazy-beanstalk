FROM python:3.12-slim

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

RUN pip install pipenv

COPY Pipfile Pipfile.lock ./

RUN pipenv install --system

COPY . .

EXPOSE 7681 5000

ENV IS_CONTAINER=true

CMD ["python", "wrapper/server.py"]