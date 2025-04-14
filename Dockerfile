# Dockerfile
FROM python:3.14

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copy installation script first (for better layer caching)
COPY deployment/install_deps.py /install_deps.py

# Copy necessary files for detection and installation
COPY pyproject.toml poetry.lock* requirements.txt* Pipfile* Pipfile.lock* pdm.lock* .pdm.toml* environment.yml* conda-lock.yml* hatch.toml* ./
COPY app/ ./

# Run the dependency detection and installation
RUN python /install_deps.py

# Expose port
EXPOSE 8000

# Start the application with unbuffered output
ENTRYPOINT ["python", "-u", "main.py"]