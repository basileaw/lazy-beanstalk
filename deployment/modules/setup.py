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
from typing import Dict, Any, Optional

# Set up standardized logging
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, 
                   datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger('deployment')

class ConfigurationError(Exception):
    """Exception raised for configuration errors."""
    pass

class ProgressIndicator:
    """Simple progress logging without animations."""
    
    @staticmethod
    def start(message):
        """Log the start of an operation."""
        logger.info(f"{message}")
    
    @staticmethod
    def step(char=None):
        """No-op for compatibility."""
        pass
    
    @staticmethod
    def complete(message=None):
        """Log the completion of an operation."""
        if message:
            logger.info(f"{message}")
        else:
            logger.info("Complete")


class ClientManager:
    """
    AWS client manager that handles caching and consistent region usage.
    """
    _clients = {}
    _session = None
    _region = None
    
    @classmethod
    def initialize(cls, region=None):
        """Initialize the client manager with a region."""
        if region:
            cls._region = region
        else:
            # Try to get from environment or default
            cls._region = os.environ.get('AWS_REGION')
        
        # Create session with region if we have one
        if cls._region:
            cls._session = boto3.Session(region_name=cls._region)
        else:
            cls._session = boto3.Session()
            cls._region = cls._session.region_name
        
        # Reset clients cache
        cls._clients = {}
        
        return cls._region
    
    @classmethod
    def get_region(cls):
        """Get the current AWS region."""
        if not cls._region:
            cls.initialize()
        return cls._region
    
    @classmethod
    def get_client(cls, service_name):
        """Get an AWS client (cached)."""
        if service_name not in cls._clients:
            if not cls._session:
                cls.initialize()
            cls._clients[service_name] = cls._session.client(service_name)
        return cls._clients[service_name]
    
    @classmethod
    def get_all_clients(cls, services=None):
        """Get multiple AWS clients as a dictionary."""
        if not services:
            services = ['elasticbeanstalk', 'iam', 's3', 'elbv2', 'acm', 'route53', 'ec2', 'sts']
        
        return {
            service: cls.get_client(service)
            for service in services
        }


class ConfigurationManager:
    """
    Manages and caches application configuration.
    Prioritizes .elasticbeanstalk/config.yml when available.
    """
    _config = None
    _eb_config = None
    _project_root = None
    _project_name = None
    _solution_stack_cache = None
    
    @classmethod
    def get_project_root(cls) -> Path:
        """Return the project root directory."""
        if not cls._project_root:
            # Navigate up from the current file to find the project root
            # configure.py is in deployment/modules/, so we need to go up two levels
            cls._project_root = Path(__file__).parent.parent.parent
        return cls._project_root
    
    @classmethod
    def get_project_name(cls) -> str:
        """Return the name of the root-level folder (project)."""
        if not cls._project_name:
            cls._project_name = cls.get_project_root().name
        return cls._project_name
    
    @classmethod
    def get_deployment_dir(cls) -> Path:
        """Return the deployment directory."""
        return cls.get_project_root() / 'deployment'
    
    @classmethod
    def get_config_path(cls) -> Path:
        """Return the path to the config.yml file."""
        return cls.get_deployment_dir() / 'config.yml'  # Changed from configurations/config.yml
    
    @classmethod
    def get_policies_dir(cls) -> Path:
        """Return the path to the policies directory."""
        return cls.get_deployment_dir() / 'policies'
    
    @classmethod
    def get_policy_path(cls, filename: str) -> Path:
        """Return the path to a specific policy file."""
        policy_path = cls.get_policies_dir() / filename
        if not policy_path.exists():
            raise ConfigurationError(f"Policy file not found: {policy_path}")
        return policy_path
    
    @classmethod
    def get_eb_config_path(cls) -> Optional[Path]:
        """Return the path to .elasticbeanstalk/config.yml if it exists."""
        path = cls.get_project_root() / '.elasticbeanstalk' / 'config.yml'
        return path if path.exists() else None
    
    @classmethod
    def get_solution_stack_cache_path(cls) -> Path:
        """Return the path to the solution stack cache file."""
        eb_dir = cls.get_project_root() / '.elasticbeanstalk'
        return eb_dir / '.stack_cache'
    
    @classmethod
    def save_solution_stack(cls, solution_stack: str) -> None:
        """Save solution stack name to cache file for future reference."""
        if not solution_stack:
            return
            
        cache_path = cls.get_solution_stack_cache_path()
        # Create directory if it doesn't exist
        cache_path.parent.mkdir(exist_ok=True)
        
        with open(cache_path, 'w') as f:
            f.write(solution_stack)
        
        # Update in-memory cache
        cls._solution_stack_cache = solution_stack
    
    @classmethod
    def get_cached_solution_stack(cls) -> Optional[str]:
        """Get solution stack from cache file if it exists."""
        if cls._solution_stack_cache is not None:
            return cls._solution_stack_cache
            
        cache_path = cls.get_solution_stack_cache_path()
        if cache_path.exists():
            try:
                stack = cache_path.read_text().strip()
                if stack:
                    cls._solution_stack_cache = stack
                    return stack
            except Exception:
                pass
        
        return None
    
    @classmethod
    def load_eb_config(cls) -> Optional[Dict]:
        """Load the .elasticbeanstalk/config.yml configuration if it exists."""
        if cls._eb_config is not None:
            return cls._eb_config
            
        eb_config_path = cls.get_eb_config_path()
        if eb_config_path:
            try:
                cls._eb_config = yaml.safe_load(eb_config_path.read_text())
                logger.debug("Loaded EB CLI configuration from .elasticbeanstalk/config.yml")
                return cls._eb_config
            except Exception as e:
                logger.warning(f"Failed to load EB CLI configuration: {e}")
        
        return None
    
    @classmethod
    def get_aws_region_from_eb_config(cls) -> Optional[str]:
        """Get AWS region from EB CLI configuration."""
        eb_config = cls.load_eb_config()
        if eb_config and 'global' in eb_config and 'default_region' in eb_config['global']:
            region = eb_config['global']['default_region']
            if region:
                logger.debug(f"Using region from EB CLI config: {region}")
                return region
        return None
    
    @classmethod
    def get_platform_from_eb_config(cls) -> Optional[str]:
        """Get platform from EB CLI configuration or stack cache."""
        # First check cached solution stack - this is the most efficient
        cached_stack = cls.get_cached_solution_stack()
        if cached_stack:
            logger.debug(f"Using cached solution stack: {cached_stack}")
            return cached_stack
            
        # If no cache, try the EB config
        eb_config = cls.load_eb_config()
        if eb_config and 'global' in eb_config and 'default_platform' in eb_config['global']:
            platform = eb_config['global']['default_platform']
            if platform:
                logger.debug(f"Using platform from EB CLI config: {platform}")
                return platform
        return None
    
    @classmethod
    def load_policy(cls, filename: str) -> Dict:
        """Load a JSON policy file."""
        import json
        try:
            policy_path = cls.get_policy_path(filename)
            policy_content = policy_path.read_text()
            logger.debug(f"Loaded policy content from {filename}")
            return json.loads(policy_content)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in policy file {filename}: {e}")
            raise ConfigurationError(f"Failed to parse JSON in {filename}: {e}")
        except Exception as e:
            logger.error(f"Failed to load {filename}: {e}")
            raise ConfigurationError(f"Failed to load {filename}: {e}")
            
    @classmethod
    def get_aws_region(cls) -> str:
        """
        Get the AWS region from multiple sources in priority order:
        1. EB CLI config
        2. AWS_REGION environment variable
        3. Boto3 session region
        4. First available region
        """
        # Try to get from EB CLI config
        region = cls.get_aws_region_from_eb_config()
        if region:
            return region
            
        # Try to get from environment variable
        region = os.environ.get('AWS_REGION')
        if region:
            logger.debug(f"Using region from AWS_REGION environment variable: {region}")
            return region
        
        # Try to get from boto3 session
        try:
            session = boto3.Session()
            region = session.region_name
            if region:
                logger.debug(f"Using region from boto3 session: {region}")
                return region
                
            # Try to get from configured profile
            profile = session.profile_name
            if profile:
                logger.debug(f"Looking up region from AWS profile: {profile}")
                config = session.client('config')
                region = config.get_discovered_resource_counts(
                    resourceType='AWS::Config::ResourceCompliance',
                    limit=1
                ).get('region')
                if region:
                    logger.debug(f"Using region from profile {profile}: {region}")
                    return region
            
            # If still no region, get first available region
            available_regions = session.get_available_regions('elasticbeanstalk')
            if available_regions:
                region = available_regions[0]
                logger.info(f"No AWS region specified. Using first available region: {region}")
                return region
            else:
                raise ConfigurationError("No available regions found")
        
        except Exception as e:
            logger.error(f"Could not determine AWS region: {str(e)}")
            raise ConfigurationError(f"Unable to determine AWS region: {e}")
    
    @classmethod
    def get_latest_docker_platform(cls) -> str:
        """
        Get the latest Docker platform from Elastic Beanstalk if not in EB config.
        Returns the exact solution stack name needed for environment creation.
        """
        # First check for cached solution stack
        cached_stack = cls.get_cached_solution_stack()
        if cached_stack:
            logger.debug(f"Using cached solution stack: {cached_stack}")
            return cached_stack
        
        # Try to get platform from EB CLI config
        platform = cls.get_platform_from_eb_config()
        if platform:
            # Check if this is already a solution stack name (starts with bit architecture)
            if platform.startswith('64bit'):
                # This is already a solution stack name, we can use it directly
                return platform
                
            # If it's a platform name like "Docker running on 64bit Amazon Linux 2023"
            # we need to convert it to a solution stack name
            platform_name = platform.lower()
            if 'docker' in platform_name:
                logger.debug(f"Converting EB CLI platform name to solution stack: {platform}")
                # Get the solution stack from AWS API
                solution_stack = cls._discover_latest_platform(platform_name)
                # Cache it for future use
                cls.save_solution_stack(solution_stack)
                return solution_stack
        
        # No platform in EB config or cache, discover latest
        solution_stack = cls._discover_latest_platform()
        # Cache the discovered solution stack
        cls.save_solution_stack(solution_stack)
        return solution_stack
    
    @classmethod
    def _discover_latest_platform(cls, platform_hint=None) -> str:
        """
        Discover the latest Docker platform from AWS.
        Used when no platform is specified in EB config or when converting 
        from EB CLI format to solution stack.
        
        Args:
            platform_hint: Optional string to filter solution stacks (e.g., "amazon linux 2023")
        
        Returns:
            str: The solution stack name
        """
        try:
            # Use ClientManager to get the client
            region = ClientManager.get_region()
            eb_client = ClientManager.get_client('elasticbeanstalk')
            
            ProgressIndicator.start("Retrieving available solution stacks")
            solution_stacks = eb_client.list_available_solution_stacks()['SolutionStacks']
            logger.debug(f"Found {len(solution_stacks)} solution stacks")
            
            # Filter for Docker stacks
            docker_stacks = [s for s in solution_stacks if 'Docker' in s]
            logger.debug(f"Found {len(docker_stacks)} Docker solution stacks")
            
            if not docker_stacks:
                raise ConfigurationError("No Docker solution stacks found in this region")
            
            # If we have a platform hint, filter for matching stacks
            if platform_hint:
                platform_hint = platform_hint.lower()
                filtered_stacks = [s for s in docker_stacks if platform_hint in s.lower()]
                if filtered_stacks:
                    docker_stacks = filtered_stacks
            
            # First try to find Amazon Linux 2023 Docker stacks
            al2023_stacks = [s for s in docker_stacks if 'Amazon Linux 2023' in s]
            
            if al2023_stacks:
                # Sort to get the latest version
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
            
    @classmethod
    def replace_placeholders(cls, obj: Any, replacements: Dict[str, str]) -> Any:
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
            return {k: cls.replace_placeholders(v, replacements) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [cls.replace_placeholders(i, replacements) for i in obj]
        return obj
            
    @classmethod
    def load_config(cls, reset_cache=False, verbose_logging=False) -> Dict:
        """
        Load configuration from YAML and replace placeholders.
        Uses cached version if already loaded.
        
        Args:
            reset_cache: Force reload config even if cached
            verbose_logging: Whether to log basic config details
                
        Returns:
            Dict: The loaded and processed configuration
        """
        if cls._config is not None and not reset_cache:
            return cls._config
            
        try:
            config_path = cls.get_config_path()
            config = yaml.safe_load(config_path.read_text())
            
            # Get values for placeholders
            project_name = cls.get_project_name()
            aws_region = cls.get_aws_region()
            
            # Initialize the client manager with our region
            ClientManager.initialize(aws_region)
            
            # Check if we already have platform info cached
            cached_stack = cls.get_cached_solution_stack()
            is_first_run = not cached_stack
            
            # Get platform - use eb config if available
            docker_platform = cls.get_latest_docker_platform()
            
            # Define replacements
            replacements = {
                'PROJECT_NAME': project_name,
                'AWS_REGION': aws_region,
                'LATEST_DOCKER_PLATFORM': docker_platform
            }
            
            # Add EB_CLI_PLATFORM for backwards compatibility
            eb_cli_platform = get_eb_cli_platform_name(docker_platform)
            replacements['EB_CLI_PLATFORM'] = eb_cli_platform
            
            # Replace placeholders
            config = cls.replace_placeholders(config, replacements)
            
            # Only log the basic config info during first run or when verbose_logging is enabled
            if is_first_run or verbose_logging:
                logger.info(f"Project Name: {project_name}")
                logger.info(f"AWS Region: {aws_region}")
                logger.info(f"Platform: {docker_platform}")
            
            # Validate required fields
            validate_config(config)
            
            # Cache the config
            cls._config = config
            
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
    if not platform or not isinstance(platform, str):
        return "Docker running on 64bit Amazon Linux 2023"
        
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
    Legacy function that uses ClientManager internally for compatibility.
    
    Args:
        config: The loaded configuration
        
    Returns:
        Dict: Dictionary of AWS clients
    """
    # Initialize client manager with the region from config
    region = config['aws']['region']
    ClientManager.initialize(region)
    
    # Return all clients
    return ClientManager.get_all_clients()


def ensure_env_in_gitignore() -> None:
    """Ensure .env is listed in .gitignore file."""
    gitignore_path = ConfigurationManager.get_project_root() / '.gitignore'
    
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


# Legacy functions that use ConfigurationManager internally for compatibility

def get_project_root() -> Path:
    """Return the project root directory."""
    return ConfigurationManager.get_project_root()

def get_project_name() -> str:
    """Return the name of the root-level folder (project)."""
    return ConfigurationManager.get_project_name()

def get_deployment_dir() -> Path:
    """Return the deployment directory."""
    return ConfigurationManager.get_deployment_dir()

def get_config_path() -> Path:
    """Return the path to the config.yml file."""
    return ConfigurationManager.get_deployment_dir() / 'config.yml'  # Changed from configurations/config.yml

def get_policies_dir() -> Path:
    """Return the path to the policies directory."""
    return ConfigurationManager.get_policies_dir()

def get_policy_path(filename: str) -> Path:
    """Return the path to a specific policy file."""
    return ConfigurationManager.get_policy_path(filename)

def load_policy(filename: str) -> Dict:
    """Load a JSON policy file."""
    return ConfigurationManager.load_policy(filename)

def get_aws_region() -> str:
    """Get the AWS region from multiple sources."""
    return ConfigurationManager.get_aws_region()

def get_latest_docker_platform() -> str:
    """Get the latest Docker platform from Elastic Beanstalk."""
    return ConfigurationManager.get_latest_docker_platform()

def load_config(reset_cache=False) -> Dict:
    """Load configuration from YAML and replace placeholders."""
    return ConfigurationManager.load_config(reset_cache)