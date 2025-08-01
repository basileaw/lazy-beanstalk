# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Local Development
- `make serve` - Run the application locally (executes `python app/main.py`)
- `make spin` - Run the application in Docker container for production-like testing (port 8000)

### Deployment Commands
- `make ship` - Deploy to AWS Elastic Beanstalk (creates/updates environment)
- `make secure` - Enable HTTPS using AWS Certificate Manager and Route 53
- `make shield` - Configure OIDC authentication on the load balancer
- `make scrap` - Remove all AWS resources created by Lazy Beanstalk

### Environment Setup
- Python 3.12+ required
- Uses Poetry for dependency management
- Environment variables stored in `.env` file (not tracked in git)
- Variables starting with `LB_` are deployment-only and not passed to the application

## Architecture Overview

### Core Structure
Lazy Beanstalk is a deployment template that simplifies shipping Python applications to AWS Elastic Beanstalk. The architecture consists of:

1. **Main Application** (`app/main.py`): 
   - Uses terminaide to serve a chatline interface explaining Lazy Beanstalk
   - Entry point for the Docker container

2. **Deployment System** (`deployment/`):
   - `manage.py`: CLI entry point for all deployment commands
   - `modules/`: Core deployment functionality
     - `setup.py`: Configuration management and AWS client initialization
     - `ship.py`: Application deployment logic
     - `secure.py`: HTTPS configuration with ACM/Route53
     - `shield.py`: OIDC authentication setup
     - `scrap.py`: Resource cleanup
     - `support.py`: Shared utilities and error handling

3. **Configuration** (`lazy-beanstalk.yml`):
   - YAML-based configuration with variable interpolation
   - Supports ${VARIABLE} syntax for dynamic values
   - Manages AWS resources, IAM roles, and deployment settings

### Docker Support
- Multi-package manager support (Poetry, PDM, Pipenv, Conda, pip, etc.)
- Auto-detects and uses appropriate package manager
- Builds optimized Python slim images
- Mounts AWS credentials for local testing

### AWS Integration
- Creates and manages IAM roles automatically
- Supports custom IAM policies via `deployment/policies/`
- Uses Application Load Balancer for HTTPS/OIDC
- Spot instance support for cost optimization
- Tag-based resource management

## Key Implementation Details

### Configuration Management
- ConfigurationManager handles YAML loading with variable substitution
- Caches AWS platform information to reduce API calls
- Integrates with EB CLI configuration when available

### Deployment Flow
1. Validates configuration and AWS credentials
2. Creates/updates IAM roles and instance profiles
3. Packages application into Docker image
4. Uploads to S3 and creates application version
5. Creates/updates Elastic Beanstalk environment

### HTTPS Setup
- Interactive certificate selection from ACM
- Configures ALB listener rules
- Creates Route53 DNS records based on domain mode
- Supports root, subdomain, and custom domain configurations

### OIDC Authentication
- Requires complete OIDC provider configuration in `.env`
- Configures ALB authentication rules
- Protects all application paths behind login

### IAM Policy Management (1:1 Local:Cloud Sync)
- Automatically syncs local policy files with AWS on each deployment
- Compares policy content and updates AWS when local changes are detected
- Creates new policy versions in AWS (maintains history)
- Manages policy version limits (keeps max 5 versions)
- Removes policies from AWS that no longer exist locally
- Policies are named as `{role_name}-{policy_filename}` in AWS