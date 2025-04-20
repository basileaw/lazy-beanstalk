FROM python:slim

# Set optimized environment variables for Python performance
ENV PYTHONUNBUFFERED=1 \
    # Allow bytecode generation for better runtime performance
    PYTHONDONTWRITEBYTECODE=0 \
    # Disable pip version check to speed up pip operations
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy dependency files first (for better layer caching)
COPY pyproject.toml poetry.lock* requirements.txt* Pipfile* Pipfile.lock* pdm.lock* .pdm.toml* environment.yml* conda-lock.yml* hatch.toml* ./

# Copy application code
COPY app/ ./

# Package manager detection and installation - preserved from original
RUN touch /tmp/no_deps_found && \
    # Poetry detection and installation
    if [ -f "pyproject.toml" ] && (grep -q "tool.poetry" pyproject.toml || grep -q "\[project\]" pyproject.toml); then \
    echo "Detected Poetry project" && \
    pip install --no-cache-dir poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --only main --no-root && \
    rm /tmp/no_deps_found; \
    # PDM detection and installation
    elif [ -f "pyproject.toml" ] && grep -q "tool.pdm" pyproject.toml; then \
    echo "Detected PDM project" && \
    pip install --no-cache-dir pdm && \
    pdm use -f python && \
    pdm install --production --no-self && \
    rm /tmp/no_deps_found; \
    # Hatch detection and installation
    elif [ -f "pyproject.toml" ] && grep -q "tool.hatch" pyproject.toml; then \
    echo "Detected Hatch project" && \
    pip install --no-cache-dir hatch && \
    hatch env create && \
    hatch install && \
    rm /tmp/no_deps_found; \
    # Flit detection and installation
    elif [ -f "pyproject.toml" ] && grep -q "tool.flit" pyproject.toml; then \
    echo "Detected Flit project" && \
    pip install --no-cache-dir flit && \
    flit install --deps production --python $(which python) && \
    rm /tmp/no_deps_found; \
    # Pipenv detection and installation
    elif [ -f "Pipfile" ]; then \
    echo "Detected Pipenv project" && \
    pip install --no-cache-dir pipenv && \
    pipenv install --system --deploy && \
    rm /tmp/no_deps_found; \
    # Conda detection and installation
    elif [ -f "environment.yml" ] || [ -f "conda-lock.yml" ]; then \
    echo "Detected Conda project" && \
    apt-get update && apt-get install -y --no-install-recommends wget && \
    wget -q https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-$(uname -m).sh -O miniforge.sh && \
    bash miniforge.sh -b -p /opt/conda && \
    rm miniforge.sh && \
    export PATH="/opt/conda/bin:$PATH" && \
    if [ -f "environment.yml" ]; then \
    conda env update -n base -f environment.yml; \
    fi && \
    if [ -f "conda-lock.yml" ]; then \
    conda-lock install -n base conda-lock.yml; \
    fi && \
    conda clean -afy && \
    rm /tmp/no_deps_found; \
    # Pip (default fallback)
    elif [ -f "requirements.txt" ]; then \
    echo "Detected Pip project" && \
    pip install --no-cache-dir -r requirements.txt && \
    rm /tmp/no_deps_found; \
    fi && \
    # Error if no package manager detected
    if [ -f "/tmp/no_deps_found" ]; then \
    echo "No recognized dependency manager files found." && \
    echo "Please include dependency files for one of the supported package managers." && \
    exit 1; \
    fi && \
    # Runtime optimization: pre-compile Python modules for faster startup
    python -m compileall .

# Make sure PATH includes conda if it's installed
ENV PATH="/opt/conda/bin:${PATH}"

# Expose port
EXPOSE 8000

# Start the application with unbuffered output (maintained from original)
ENTRYPOINT ["python", "-u", "main.py"]