#!/usr/bin/env bash
set -e

echo "Installing Lazy Beanstalk deployment tools..."

# Parse command line arguments
DEMO_MODE=false
for arg in "$@"; do
  if [ "$arg" == "--demo" ]; then
    DEMO_MODE=true
    echo "Running in demo mode - will install app code and dependencies"
  fi
done

# Function to detect package manager
detect_package_manager() {
  if [ -f "poetry.lock" ]; then
    echo "poetry"
  elif [ -f "Pipfile" ]; then
    echo "pipenv"
  elif [ -f "pdm.lock" ]; then
    echo "pdm"
  elif [ -f "pyproject.toml" ]; then
    # Check for tool sections
    if grep -q "tool.poetry" pyproject.toml; then
      echo "poetry"
    elif grep -q "tool.pdm" pyproject.toml; then
      echo "pdm"
    elif grep -q "tool.hatch" pyproject.toml; then
      echo "hatch"
    elif grep -q "tool.flit" pyproject.toml; then
      echo "flit"
    elif grep -q "\[project\]" pyproject.toml && grep -q "build-backend.*poetry" pyproject.toml; then
      # PEP 621 with Poetry backend
      echo "poetry"
    else
      echo "pip"  # Default for pyproject.toml without known tool
    fi
  elif [ -f "environment.yml" ] || [ -f "conda-lock.yml" ]; then
    echo "conda"
  else
    echo "pip"  # Default fallback
  fi
}

# Function to copy file with conflict handling
copy_file() {
  local src="$1"
  local dest="$2"
  
  if [ -f "$dest" ]; then
    local filename=$(basename "$dest")
    local extension="${filename##*.}"
    local base="${filename%.*}"
    local new_dest="${dest%/*}/${base}-lazybeanstalk.${extension}"
    cp "$src" "$new_dest"
    echo "File $dest already exists, created ${new_dest}"
  else
    mkdir -p "$(dirname "$dest")"
    cp "$src" "$dest"
    echo "Added $dest"
  fi
}

# Function to extract dev dependencies from pyproject.toml
extract_dev_dependencies() {
  local pyproject_path="$1"
  
  if [ ! -f "$pyproject_path" ]; then
    echo "Warning: pyproject.toml not found at $pyproject_path"
    return 1
  fi
  
  # Use Python to extract dependencies
  python3 -c "
import sys
import re

try:
    with open('$pyproject_path', 'r') as f:
        content = f.read()
    
    # Find the dev dependencies section
    dev_deps = []
    dev_pattern = r'\[project\.optional-dependencies\].*?dev\s*=\s*\[(.*?)\]'
    dev_match = re.search(dev_pattern, content, re.DOTALL)
    
    if dev_match:
        deps_text = dev_match.group(1)
        # Extract individual dependencies
        for line in deps_text.split(','):
            line = line.strip()
            if not line:
                continue
            
            # Get package name (everything before version specifier)
            package_match = re.match(r'[\"\']?([a-zA-Z0-9_-]+)', line.strip())
            if package_match:
                package = package_match.group(1)
                dev_deps.append(package)
        
        print(' '.join(dev_deps))
    else:
        sys.exit(1)
except Exception as e:
    sys.stderr.write(f'Error parsing pyproject.toml: {str(e)}\\n')
    sys.exit(1)
"
}

# Function to extract main dependencies from pyproject.toml
extract_main_dependencies() {
  local pyproject_path="$1"
  
  if [ ! -f "$pyproject_path" ]; then
    echo "Warning: pyproject.toml not found at $pyproject_path"
    return 1
  fi
  
  # Use Python to extract dependencies from the main project section
  python3 -c "
import sys
import re

try:
    with open('$pyproject_path', 'r') as f:
        content = f.read()
    
    # Find the main dependencies section
    main_deps = []
    main_pattern = r'\[project\].*?dependencies\s*=\s*\[(.*?)\]'
    main_match = re.search(main_pattern, content, re.DOTALL)
    
    if main_match:
        deps_text = main_match.group(1)
        # Extract individual dependencies
        for line in deps_text.split(','):
            line = line.strip()
            if not line:
                continue
            
            # Get package name (everything before version specifier)
            package_match = re.match(r'[\"\']?([a-zA-Z0-9_-]+)', line.strip())
            if package_match:
                package = package_match.group(1)
                main_deps.append(package)
        
        print(' '.join(main_deps))
    else:
        sys.exit(1)
except Exception as e:
    sys.stderr.write(f'Error parsing pyproject.toml: {str(e)}\\n')
    sys.exit(1)
"
}

# Function to install dependencies
install_dependencies() {
  local pkg_manager="$1"
  local group="$2"  # 'dev' or 'main'
  shift 2
  local dependencies=("$@")
  
  echo "Installing $group dependencies using $pkg_manager: ${dependencies[*]}"
  
  case $pkg_manager in
    poetry)
      if [ "$group" == "dev" ]; then
        for dep in "${dependencies[@]}"; do
          if [ -n "$dep" ]; then
            poetry add --group dev "$dep"
          fi
        done
      else
        for dep in "${dependencies[@]}"; do
          if [ -n "$dep" ]; then
            poetry add "$dep"
          fi
        done
      fi
      ;;
    pipenv)
      if [ "$group" == "dev" ]; then
        pipenv install --dev "${dependencies[@]}"
      else
        pipenv install "${dependencies[@]}"
      fi
      ;;
    pdm)
      if [ "$group" == "dev" ]; then
        pdm add -d "${dependencies[@]}"
      else
        pdm add "${dependencies[@]}"
      fi
      ;;
    hatch)
      if [ "$group" == "dev" ]; then
        # First check if hatch is installed
        if ! command -v hatch &> /dev/null; then
          pip install hatch
        fi
        # Add dependencies to hatch project
        for dep in "${dependencies[@]}"; do
          if [ -n "$dep" ]; then
            hatch add --dev "$dep"
          fi
        done
      else
        # First check if hatch is installed
        if ! command -v hatch &> /dev/null; then
          pip install hatch
        fi
        # Add dependencies to hatch project
        for dep in "${dependencies[@]}"; do
          if [ -n "$dep" ]; then
            hatch add "$dep"
          fi
        done
      fi
      ;;
    flit)
      # First check if flit is installed
      if ! command -v flit &> /dev/null; then
        pip install flit
      fi
      
      # Update pyproject.toml and install
      if [ "$group" == "dev" ]; then
        pip install "${dependencies[@]}"
        flit install --deps develop
      else
        pip install "${dependencies[@]}"
        flit install --deps production
      fi
      ;;
    conda)
      # Check if conda is installed
      if ! command -v conda &> /dev/null; then
        echo "Conda not installed. Please install conda first."
        exit 1
      fi
      
      # Install dependencies
      for dep in "${dependencies[@]}"; do
        if [ -n "$dep" ]; then
          conda install -y "$dep"
        fi
      done
      ;;
    pip)
      if [ "$group" == "dev" ]; then
        if [ -f "requirements-dev.txt" ]; then
          for dep in "${dependencies[@]}"; do
            if [ -n "$dep" ] && ! grep -q "^$dep" requirements-dev.txt; then
              echo "$dep" >> requirements-dev.txt
            fi
          done
          pip install -r requirements-dev.txt
        else
          pip install "${dependencies[@]}"
          # Create requirements-dev.txt
          for dep in "${dependencies[@]}"; do
            if [ -n "$dep" ]; then
              echo "$dep" >> requirements-dev.txt
            fi
          done
        fi
      else
        if [ -f "requirements.txt" ]; then
          for dep in "${dependencies[@]}"; do
            if [ -n "$dep" ] && ! grep -q "^$dep" requirements.txt; then
              echo "$dep" >> requirements.txt
            fi
          done
          pip install -r requirements.txt
        else
          pip install "${dependencies[@]}"
          # Create requirements.txt
          for dep in "${dependencies[@]}"; do
            if [ -n "$dep" ]; then
              echo "$dep" >> requirements.txt
            fi
          done
        fi
      fi
      ;;
  esac
}

# Create Python __init__.py files to solve import issues
create_init_files() {
  echo "Creating __init__.py files for proper module imports..."
  touch deployment/__init__.py
  touch deployment/modules/__init__.py
}

# Create a sample .env file with environment variable documentation
create_env_sample() {
  echo "Creating sample .env file with documentation..."
  if [ ! -f ".env" ]; then
    cat > ".env.sample" << EOF
# Lazy Beanstalk Environment Variables
#
# This file contains environment variable documentation for your application.
# Copy this file to .env and fill in your values.
# IMPORTANT: Make sure .env is in your .gitignore file!

# ==== LAZY BEANSTALK DEPLOYMENT VARIABLES ====
# Variables starting with LB_ are used by Lazy Beanstalk for deployment
# and won't be passed to your application environment

# HTTPS Certificate Selection (for 'make secure' command)
# LB_CERTIFICATE_ARN=arn:aws:acm:region:account:certificate/certificate-id

# OIDC Authentication (for 'make shield' command)
# LB_OIDC_CLIENT_ID=your-client-id
# LB_OIDC_CLIENT_SECRET=your-client-secret
# LB_OIDC_ISSUER=https://your-identity-provider
# LB_OIDC_AUTH_ENDPOINT=https://your-identity-provider/auth
# LB_OIDC_TOKEN_ENDPOINT=https://your-identity-provider/token
# LB_OIDC_USERINFO_ENDPOINT=https://your-identity-provider/userinfo

# ==== APPLICATION VARIABLES ====
# Variables without the LB_ prefix will be passed to your application

# Database configuration
# DATABASE_URL=postgres://user:password@host:port/dbname

# API credentials
# API_KEY=your-api-key
# API_SECRET=your-api-secret

# Service endpoints
# SERVICE_ENDPOINT=https://api.example.com
EOF
    echo "Created .env.sample with documentation"
  else
    echo ".env file already exists, skipping sample creation"
  fi
}

# Create an empty requirements.txt if no requirements file exists
create_empty_requirements() {
  echo "Checking for requirements files..."
  if [ ! -f "requirements.txt" ] && [ ! -f "pyproject.toml" ] && [ ! -f "Pipfile" ] && [ ! -f "environment.yml" ] && [ ! -f "pdm.lock" ]; then
    echo "No dependency files found, creating empty requirements.txt"
    cat > "requirements.txt" << EOF
# This file was created by Lazy Beanstalk installer
# The Dockerfile requires at least one dependency file to exist
# Add your Python dependencies here, one per line:
# 
# flask==2.0.1
# requests>=2.25.0
# python-dotenv==0.19.0
EOF
    echo "Created empty requirements.txt with instructions"
  else
    echo "Dependency files already exist, skipping requirements.txt creation"
  fi
}

# Main installation process
main() {
  # For production use GitHub, for local testing use LOCAL_SRC
  if [ -n "$LOCAL_SRC" ]; then
    SOURCE_DIR="$LOCAL_SRC"
    echo "Using local source: $SOURCE_DIR"
  else
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT
    echo "Downloading from GitHub..."
    git clone --depth 1 https://github.com/anotherbazeinthewall/lazy-beanstalk.git "$TEMP_DIR"
    SOURCE_DIR="$TEMP_DIR"
  fi
  
  # Detect package manager
  PKG_MANAGER=$(detect_package_manager)
  echo "Detected package manager: $PKG_MANAGER"
  
  # Copy deployment directory
  mkdir -p deployment
  echo "Copying deployment files..."
  if [ -d "$SOURCE_DIR/deployment" ]; then
    for file in $(find "$SOURCE_DIR/deployment" -type f); do
      rel_path="${file#$SOURCE_DIR/deployment/}"
      copy_file "$file" "deployment/$rel_path"
    done
  else
    echo "Warning: deployment directory not found in source"
  fi
  
  # Copy root files
  if [ -f "$SOURCE_DIR/.ebignore" ]; then
    copy_file "$SOURCE_DIR/.ebignore" ".ebignore"
  fi
  if [ -f "$SOURCE_DIR/lazy-beanstalk.yml" ]; then
    copy_file "$SOURCE_DIR/lazy-beanstalk.yml" "lazy-beanstalk.yml"
  fi
  if [ -f "$SOURCE_DIR/Dockerfile" ]; then
    copy_file "$SOURCE_DIR/Dockerfile" "Dockerfile"
  fi
  if [ -f "$SOURCE_DIR/docker-compose.yml" ]; then
    copy_file "$SOURCE_DIR/docker-compose.yml" "docker-compose.yml"
  fi
  if [ -f "$SOURCE_DIR/.dockerignore" ]; then
  copy_file "$SOURCE_DIR/.dockerignore" ".dockerignore"
  fi
  if [ -f "$SOURCE_DIR/Makefile" ]; then
    copy_file "$SOURCE_DIR/Makefile" "Makefile"
  fi
  
  # Create app/main.py if it doesn't exist
  mkdir -p app
  if [ ! -f "app/main.py" ]; then
      if [ "$DEMO_MODE" == true ] && [ -d "$SOURCE_DIR/app" ]; then
          # Copy entire app directory
          echo "Copying demo app directory..."
          for file in $(find "$SOURCE_DIR/app" -type f); do
              rel_path="${file#$SOURCE_DIR/app/}"
              copy_file "$file" "app/$rel_path"
          done
          echo "Copied complete demo app directory"
      else
          # Create empty main.py
          touch "app/main.py"
          echo "Created empty app/main.py"
      fi
  else
      echo "app/main.py already exists, leaving unchanged"
  fi
  
  # Extract and install dev dependencies directly from source pyproject.toml
  echo "Extracting dev dependencies from source pyproject.toml..."
  DEV_DEPENDENCIES=$(extract_dev_dependencies "$SOURCE_DIR/pyproject.toml" 2>/dev/null) || true
  
  if [ -n "$DEV_DEPENDENCIES" ]; then
    # Convert string to array
    IFS=' ' read -r -a DEV_DEP_ARRAY <<< "$DEV_DEPENDENCIES"
    
    # Install dev dependencies
    install_dependencies "$PKG_MANAGER" "dev" "${DEV_DEP_ARRAY[@]}"
  else
    echo "No dev dependencies specified in source pyproject.toml"
    echo "Only base files will be installed"
  fi
  
  # For demo mode, also install main dependencies
  if [ "$DEMO_MODE" == true ]; then
    echo "Demo mode: Extracting main dependencies from pyproject.toml..."
    MAIN_DEPENDENCIES=$(extract_main_dependencies "$SOURCE_DIR/pyproject.toml" 2>/dev/null) || true
    
    if [ -n "$MAIN_DEPENDENCIES" ]; then
      # Convert string to array
      IFS=' ' read -r -a MAIN_DEP_ARRAY <<< "$MAIN_DEPENDENCIES"
      
      # Install main dependencies
      install_dependencies "$PKG_MANAGER" "main" "${MAIN_DEP_ARRAY[@]}"
    else
      echo "No main dependencies found for demo mode"
    fi
  fi
  
  # Create __init__.py files to solve import issues
  create_init_files
  
  # Create sample .env file
  create_env_sample
  
  # Create empty requirements.txt if needed
  create_empty_requirements
  
  echo "Lazy Beanstalk deployment setup complete!"
  echo ""
  echo "IMPORTANT NOTES:"
  echo "1. Environment variables starting with LB_ are used for deployment."
  echo "2. All other environment variables will be passed to your application."
  echo "3. See .env.sample for documentation and examples."
  echo "4. IMPORTANT: Add .env to your .gitignore to prevent accidental exposure of secrets."
  echo ""
  echo "To deploy your application:"
  echo "  make serve    # Run locally"
  echo "  make spin     # Run in Docker"
  echo "  make ship     # Deploy to AWS Elastic Beanstalk"
}

main "$@"