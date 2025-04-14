# deployment/install_deps.py
import os
import subprocess
import sys

def run_command(command):
    """Run a shell command and print output."""
    print(f"Running: {command}")
    result = subprocess.run(command, shell=True, check=True)
    return result.returncode == 0

def check_file_contains(filename, text):
    """Check if a file exists and contains specific text."""
    if not os.path.isfile(filename):
        return False
    
    with open(filename, 'r') as f:
        content = f.read()
        return text in content

def main():
    """Detect and install dependencies based on available files."""
    print("Detecting dependency management system...")
    
    # Poetry detection
    if os.path.isfile("pyproject.toml") and check_file_contains("pyproject.toml", "tool.poetry"):
        print("Detected Poetry project")
        run_command("pip install --no-cache-dir poetry")
        run_command("poetry config virtualenvs.create false")
        run_command("poetry install --no-interaction --no-ansi --only main --no-root")
        return True
    
    # PDM detection
    if os.path.isfile("pyproject.toml") and check_file_contains("pyproject.toml", "tool.pdm"):
        print("Detected PDM project")
        run_command("pip install --no-cache-dir pdm")
        run_command("pdm use -f python")
        run_command("pdm install --production --no-self")
        return True
    
    # Hatch detection
    if os.path.isfile("pyproject.toml") and check_file_contains("pyproject.toml", "tool.hatch"):
        print("Detected Hatch project")
        run_command("pip install --no-cache-dir hatch")
        run_command("hatch env create")
        run_command("hatch install")
        return True
    
    # Flit detection
    if os.path.isfile("pyproject.toml") and check_file_contains("pyproject.toml", "tool.flit"):
        print("Detected Flit project")
        run_command("pip install --no-cache-dir flit")
        run_command(f"flit install --deps production --python {sys.executable}")
        return True
    
    # Pipenv detection
    if os.path.isfile("Pipfile"):
        print("Detected Pipenv project")
        run_command("pip install --no-cache-dir pipenv")
        run_command("pipenv install --system --deploy")
        return True
    
    # Conda detection
    if os.path.isfile("environment.yml") or os.path.isfile("conda-lock.yml"):
        print("Detected Conda project")
        run_command("apt-get update && apt-get install -y wget")
        run_command("wget -q https://github.com/conda-forge/miniforge/releases/latest/download/Miniforge3-Linux-x86_64.sh -O miniforge.sh")
        run_command("bash miniforge.sh -b -p /opt/conda")
        run_command("rm miniforge.sh")
        
        # Add conda to PATH
        os.environ["PATH"] = "/opt/conda/bin:" + os.environ["PATH"]
        
        if os.path.isfile("environment.yml"):
            run_command("conda env update -n base -f environment.yml")
        else:
            run_command("conda-lock install -n base conda-lock.yml")
        
        run_command("conda clean -afy")
        return True
    
    # Pip detection (simplest case, fallback)
    if os.path.isfile("requirements.txt"):
        print("Detected Pip project")
        run_command("pip install --no-cache-dir -r requirements.txt")
        return True
    
    print("No recognized dependency manager files found.")
    print("Please include dependency files for one of the supported package managers.")
    sys.exit(1)

if __name__ == "__main__":
    main()