# configure.py 

"""
Configuration utilities for Elastic Beanstalk deployment operations.
Handles loading configuration files, path resolution, and AWS client management.
"""

import re
import os
import yaml
import boto3
import logging
from pathlib import Path
from typing import Dict, Any

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('deployment.configure')

class ConfigurationError(Exception):
    """Exception raised for configuration errors."""
    pass

def get_project_root() -> Path:
    """Return the project root directory."""
    # Navigate up from the current file to find the project root
    # configure.py is in deployment/modules/, so we need to go up two levels
    return Path(__file__).parent.parent.parent

def get_project_name() -> str:
    """Return the name of the root-level folder (project)."""
    return get_project_root().name

def get_deployment_dir() -> Path:
    """Return the deployment directory."""
    return get_project_root() / 'deployment'

def get_config_path() -> Path:
    """Return the path to the config.yml file."""
    return get_deployment_dir() / 'configurations' / 'config.yml'

def get_policies_dir() -> Path:
    """Return the path to the policies directory."""
    return get_deployment_dir() / 'policies'

def get_policy_path(filename: str) -> Path:
    """Return the path to a specific policy file."""
    policy_path = get_policies_dir() / filename
    if not policy_path.exists():
        raise ConfigurationError(f"Policy file not found: {policy_path}")
    return policy_path

def load_policy(filename: str) -> Dict:
    """Load a JSON policy file."""
    import json
    try:
        policy_path = get_policy_path(filename)
        policy_content = policy_path.read_text()
        logger.debug(f"Loaded policy content from {filename}: {policy_content[:100]}...")
        return json.loads(policy_content)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in policy file {filename}: {e}")
        raise ConfigurationError(f"Failed to parse JSON in {filename}: {e}")
    except Exception as e:
        logger.error(f"Failed to load {filename}: {e}")
        raise ConfigurationError(f"Failed to load {filename}: {e}")

def get_aws_region() -> str:
    """
    Get the AWS region from the configured profile.
    If region cannot be determined, returns the first available region.
    """
    try:
        session = boto3.Session()
        region = session.region_name
        
        if not region:
            # Try to get from configured profile
            profile = session.profile_name
            if profile:
                config = session.client('config')
                region = config.get_discovered_resource_counts(
                    resourceType='AWS::Config::ResourceCompliance',
                    limit=1
                ).get('region')
            
            # If still no region, get first available region
            if not region:
                available_regions = session.get_available_regions('elasticbeanstalk')
                if available_regions:
                    region = available_regions[0]
                    logger.info(f"No AWS region specified. Using first available region: {region}")
                else:
                    raise ConfigurationError("No available regions found")
        
        return region
    except Exception as e:
        logger.error(f"Could not determine AWS region: {str(e)}")
        raise ConfigurationError(f"Unable to determine AWS region: {e}")

def get_latest_docker_platform() -> str:
    """
    Get the latest Docker platform from Elastic Beanstalk.
    Returns the exact solution stack name needed for environment creation.
    """
    try:
        region = get_aws_region()
        session = boto3.Session(region_name=region)
        eb_client = session.client('elasticbeanstalk')
        
        # Get all available solution stacks directly
        logger.info("Retrieving available solution stacks...")
        solution_stacks = eb_client.list_available_solution_stacks()['SolutionStacks']
        logger.info(f"Found {len(solution_stacks)} solution stacks")
        
        # Filter for Docker stacks
        docker_stacks = [s for s in solution_stacks if 'Docker' in s]
        logger.info(f"Found {len(docker_stacks)} Docker solution stacks")
        
        if not docker_stacks:
            raise ConfigurationError("No Docker solution stacks found in this region")
        
        # First try to find Amazon Linux 2023 Docker stacks
        al2023_stacks = [s for s in docker_stacks if 'Amazon Linux 2023' in s]
        
        if al2023_stacks:
            # Sort to get the latest version (sort alphabetically since version is in the name)
            latest_stack = sorted(al2023_stacks, reverse=True)[0]
            logger.info(f"Using latest Amazon Linux 2023 Docker stack: {latest_stack}")
            return latest_stack
        
        # If no AL2023 stacks, try Amazon Linux 2
        al2_stacks = [s for s in docker_stacks if 'Amazon Linux 2' in s and 'Amazon Linux 2023' not in s]
        
        if al2_stacks:
            latest_stack = sorted(al2_stacks, reverse=True)[0]
            logger.info(f"Using latest Amazon Linux 2 Docker stack: {latest_stack}")
            return latest_stack
        
        # If all else fails, use the latest Docker stack available
        latest_stack = sorted(docker_stacks, reverse=True)[0]
        logger.info(f"Using Docker stack: {latest_stack}")
        return latest_stack
        
    except Exception as e:
        logger.error(f"Could not determine Docker platform: {str(e)}")
        raise ConfigurationError(f"Unable to determine Docker platform: {str(e)}")

def replace_placeholders(obj: Any, replacements: Dict[str, str]) -> Any:
    """
    Recursively replace placeholder variables in strings.
    
    Args:
        obj: Object to process (string, dict, list)
        replacements: Dictionary of {placeholder: value} pairs
    
    Returns:
        Object with placeholders replaced
    """
    if isinstance(obj, str) and '${' in obj and '}' in obj:
        result = obj
        for placeholder, value in replacements.items():
            if f"${{{placeholder}}}" in result:
                result = result.replace(f"${{{placeholder}}}", value)
        
        # Handle environment variables for any remaining ${VAR_NAME} patterns
        env_vars = re.findall(r'\${([A-Za-z0-9_]+)}', result)
        for var in env_vars:
            if var in os.environ:
                result = result.replace(f"${{{var}}}", os.environ[var])
        return result
    elif isinstance(obj, dict):
        return {k: replace_placeholders(v, replacements) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [replace_placeholders(i, replacements) for i in obj]
    return obj

def load_config() -> Dict:
    """
    Load configuration from YAML and replace placeholders.
    
    Returns:
        Dict: The loaded and processed configuration
    """
    try:
        config_path = get_config_path()
        config = yaml.safe_load(config_path.read_text())
        
        # Get values for placeholders
        project_name = get_project_name()
        aws_region = get_aws_region()
        docker_platform = get_latest_docker_platform()
        
        # Define replacements
        replacements = {
            'PROJECT_NAME': project_name,
            'AWS_REGION': aws_region,
            'LATEST_DOCKER_PLATFORM': docker_platform
        }
        
        # Replace placeholders
        config = replace_placeholders(config, replacements)
        
        # Log the resolved values
        logger.info(f"Using AWS Region: {aws_region}")
        logger.info(f"Using Platform: {docker_platform}")
        logger.info(f"Project Name: {project_name}")
        
        # Validate required fields
        validate_config(config)
        
        return config
    except Exception as e:
        logger.error(f"Configuration error: {str(e)}")
        raise ConfigurationError(f"Failed to load configuration: {e}")

def validate_config(config: Dict) -> None:
    """
    Validate that the configuration contains all required fields.
    
    Args:
        config: The loaded configuration dict
    
    Raises:
        ConfigurationError: If validation fails
    """
    required = {
        'aws': ['region', 'platform'],
        'application': ['name', 'environment'],
        'instance': ['type', 'elb_type', 'autoscaling'],
        'iam': ['service_role_name', 'instance_role_name', 'instance_profile_name']
    }
    
    for section, fields in required.items():
        if section not in config:
            raise ConfigurationError(f"Missing required section '{section}' in configuration")
            
        for field in fields:
            if field not in config[section]:
                raise ConfigurationError(f"Missing required field '{field}' in '{section}' section")

def get_eb_cli_platform_name(platform: str) -> str:
    """
    Convert AWS solution stack name to EB CLI platform name format.
    
    Args:
        platform: AWS solution stack name
    
    Returns:
        str: EB CLI compatible platform name
    """
    platform_parts = platform.split(" ")
    default_platform = "Docker"
    
    # Try to construct a more specific platform name based on the solution stack
    if "Docker" in platform:
        # Look for common patterns in platform names
        if "Amazon Linux" in platform:
            # Find the OS details (e.g., "64bit Amazon Linux 2023")
            os_parts = []
            for i, part in enumerate(platform_parts):
                if part == "Amazon" and i+2 < len(platform_parts):
                    os_parts = platform_parts[i-1:i+3]  # Get bits, Amazon, Linux, version
                    break
            
            if os_parts:
                default_platform = f"Docker running on {' '.join(os_parts)}"
    
    return default_platform

def get_aws_clients(config: Dict) -> Dict:
    """
    Initialize and return AWS clients using the configuration.
    
    Args:
        config: The loaded configuration
        
    Returns:
        Dict: Dictionary of AWS clients
    """
    region = config['aws']['region']
    session = boto3.Session(region_name=region)
    
    return {
        'eb': session.client('elasticbeanstalk'),
        'iam': session.client('iam'),
        's3': session.client('s3'),
        'elbv2': session.client('elbv2'),
        'acm': session.client('acm'),
        'r53': session.client('route53'),
        'ec2': session.client('ec2'),
        'sts': session.client('sts')
    }

def ensure_env_in_gitignore() -> None:
    """Ensure .env is listed in .gitignore file."""
    gitignore_path = get_project_root() / '.gitignore'
    
    # Check if .gitignore exists
    if not gitignore_path.exists():
        logger.info("Creating .gitignore file with .env entry")
        with open(gitignore_path, 'w') as f:
            f.write(".env\n")
        return
    
    # Check if .env is already in .gitignore
    with open(gitignore_path, 'r') as f:
        content = f.read()
    
    if ".env" not in content.splitlines():
        logger.info("Adding .env to .gitignore")
        with open(gitignore_path, 'a') as f:
            # Add newline if needed
            if not content.endswith('\n'):
                f.write('\n')
            f.write(".env\n")