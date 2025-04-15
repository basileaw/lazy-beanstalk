#!/usr/bin/env bash
set -e

echo "Installing Lazy Beanstalk deployment tools..."

# Function to detect package manager
detect_package_manager() {
  if [ -f "poetry.lock" ]; then
    echo "poetry"
  elif [ -f "Pipfile" ]; then
    echo "pipenv"
  elif [ -f "pdm.lock" ]; then
    echo "pdm"
  else
    echo "pip"  # Default to pip
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
  for file in $(find "$SOURCE_DIR/deployment" -type f); do
    rel_path="${file#$SOURCE_DIR/deployment/}"
    copy_file "$file" "deployment/$rel_path"
  done
  
  # Copy root files
  copy_file "$SOURCE_DIR/Dockerfile" "Dockerfile"
  copy_file "$SOURCE_DIR/docker-compose.yml" "docker-compose.yml"
  copy_file "$SOURCE_DIR/Makefile" "Makefile"
  
  # Create app/main.py if it doesn't exist
  mkdir -p app
  if [ ! -f "app/main.py" ]; then
    if [ -f "$SOURCE_DIR/app/main.py" ]; then
      cp "$SOURCE_DIR/app/main.py" "app/main.py"
    else
      cat > "app/main.py" << EOF
def main():
    print("Hello from Lazy Beanstalk!")

if __name__ == "__main__":
    main()
EOF
    fi
    echo "Created app/main.py"
  fi
  
  # Install dependencies
  echo "Installing dependencies using $PKG_MANAGER..."
  case $PKG_MANAGER in
    poetry)
      poetry add boto3 botocore
      ;;
    pipenv)
      pipenv install boto3 botocore
      ;;
    pdm)
      pdm add boto3 botocore
      ;;
    pip)
      if [ -f "requirements.txt" ]; then
        if ! grep -q "boto3" requirements.txt; then
          echo "boto3" >> requirements.txt
        fi
        if ! grep -q "botocore" requirements.txt; then
          echo "botocore" >> requirements.txt
        fi
        pip install -r requirements.txt
      else
        pip install boto3 botocore
      fi
      ;;
  esac
  
  echo "✅ Lazy Beanstalk deployment setup complete!"
}

main