# Dockerfile

FROM python:3.12-slim

WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install Poetry and dependencies
RUN pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --only main --no-root

# Copy application code
COPY app/ ./

# Expose port
EXPOSE 8000

# Run the application
ENTRYPOINT ["python", "-u", "main.py"]
