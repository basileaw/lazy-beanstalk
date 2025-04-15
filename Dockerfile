FROM python:latest

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Copy necessary files for detection and installation
COPY pyproject.toml poetry.lock* requirements.txt* Pipfile* Pipfile.lock* pdm.lock* .pdm.toml* environment.yml* conda-lock.yml* hatch.toml* ./
COPY app/ ./

# Create flag files to track what we've detected
RUN touch /tmp/no_deps_found

# Poetry detection and installation (handles both [tool.poetry] and [project] formats)
RUN if [ -f "pyproject.toml" ] && (grep -q "tool.poetry" pyproject.toml || grep -q "\[project\]" pyproject.toml); then \
    echo "Detected Poetry project" && \
    pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --only main --no-root && \
    rm /tmp/no_deps_found; \
    fi

# PDM detection and installation
RUN if [ -f "pyproject.toml" ] && grep -q "tool.pdm" pyproject.toml; then \
    echo "Detected PDM project" && \
    pip install --no-cache-dir pdm && \
    pdm use -f python && \
    pdm install --production --no-self && \
    rm /tmp/no_deps_found; \
    fi

# Hatch detection and installation
RUN if [ -f "pyproject.toml" ] && grep -q "tool.hatch" pyproject.toml; then \
    echo "Detected Hatch project" && \
    pip install --no-cache-dir hatch && \
    hatch env create && \
    hatch install && \
    rm /tmp/no_deps_found; \
    fi

# Flit detection and installation
RUN if [ -f "pyproject.toml" ] && grep -q "tool.flit" pyproject.toml; then \
    echo "Detected Flit project" && \
    pip install --no-cache-dir flit && \
    flit install --deps production --python $(which python) && \
    rm /tmp/no_deps_found; \
    fi

# Pipenv detection and installation
RUN if [ -f "Pipfile" ]; then \
    echo "Detected Pipenv project" && \
    pip install --no-cache-dir pipenv && \
    pipenv install --system --deploy && \
    rm /tmp/no_deps_found; \
    fi

# Conda detection and installation - broken into smaller RUN commands
RUN if [ -f "environment.yml" ] || [ -f "conda-lock.yml" ]; then \
    echo "Detected Conda project" && \
    apt-get update && apt-get install -y wget && \
    wget -q https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh -O miniforge.sh && \
    rm /tmp/no_deps_found; \
    fi

# Conda installation continues if needed
RUN if [ -f "miniforge.sh" ]; then \
    bash miniforge.sh -b -p /opt/conda && \
    rm miniforge.sh && \
    export PATH="/opt/conda/bin:$PATH"; \
    fi

# Conda environment setup if needed
RUN if [ -f "environment.yml" ] && [ -d "/opt/conda" ]; then \
    export PATH="/opt/conda/bin:$PATH" && \
    conda env update -n base -f environment.yml && \
    conda clean -afy; \
    fi

RUN if [ -f "conda-lock.yml" ] && [ -d "/opt/conda" ]; then \
    export PATH="/opt/conda/bin:$PATH" && \
    conda-lock install -n base conda-lock.yml && \
    conda clean -afy; \
    fi

# Pip (default fallback)
RUN if [ -f "requirements.txt" ]; then \
    echo "Detected Pip project" && \
    pip install --no-cache-dir -r requirements.txt && \
    rm /tmp/no_deps_found; \
    fi

# Error if no package manager detected
RUN if [ -f "/tmp/no_deps_found" ]; then \
    echo "No recognized dependency manager files found." && \
    echo "Please include dependency files for one of the supported package managers." && \
    exit 1; \
    fi

# Expose port
EXPOSE 8000

# Start the application with unbuffered output
ENTRYPOINT ["python", "-u", "main.py"]