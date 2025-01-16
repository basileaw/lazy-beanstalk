# Dockerfile
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
    nginx \
    supervisor \
    && wget https://github.com/tsl0922/ttyd/releases/download/1.7.3/ttyd.x86_64 \
    && chmod +x ttyd.x86_64 \
    && mv ttyd.x86_64 /usr/local/bin/ttyd \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install pipenv
COPY Pipfile Pipfile.lock ./
RUN pipenv install --system --deploy

COPY . .

# Remove default Nginx config
RUN rm -f /etc/nginx/sites-enabled/default

# Nginx configuration
RUN echo ' \
    map $http_upgrade $connection_upgrade { \
    default upgrade; \
    "" close; \
    } \n\
    server { \
    listen 80 default_server; \
    server_name _; \
    \
    location / { \
    proxy_pass http://127.0.0.1:5000; \
    proxy_set_header Host $host; \
    proxy_set_header X-Real-IP $remote_addr; \
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
    proxy_set_header X-Forwarded-Proto $scheme; \
    } \
    \
    location /ttyd/ { \
    proxy_pass http://127.0.0.1:7681/; \
    proxy_http_version 1.1; \
    proxy_set_header Upgrade $http_upgrade; \
    proxy_set_header Connection $connection_upgrade; \
    proxy_set_header Host $host; \
    proxy_set_header X-Real-IP $remote_addr; \
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
    proxy_read_timeout 1800; \
    proxy_send_timeout 1800; \
    proxy_buffering off; \
    } \
    }' > /etc/nginx/conf.d/app.conf

# Create nginx directory for pid file
RUN mkdir -p /run/nginx

# Supervisor configuration
RUN echo '[supervisord] \n\
    nodaemon=true \n\
    \n\
    [program:nginx] \n\
    command=nginx -g "daemon off;" \n\
    stdout_logfile=/dev/stdout \n\
    stdout_logfile_maxbytes=0 \n\
    stderr_logfile=/dev/stderr \n\
    stderr_logfile_maxbytes=0 \n\
    priority=2 \n\
    \n\
    [program:fastapi] \n\
    command=python backend/server.py \n\
    stdout_logfile=/dev/stdout \n\
    stdout_logfile_maxbytes=0 \n\
    stderr_logfile=/dev/stderr \n\
    stderr_logfile_maxbytes=0 \n\
    priority=1' > /etc/supervisor/conf.d/supervisord.conf

EXPOSE 80

# Set environment variables
ENV IS_CONTAINER=true
ENV PYTHONUNBUFFERED=1

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]