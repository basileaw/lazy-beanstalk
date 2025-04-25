# setup.py

"""
Configuration utilities for Elastic Beanstalk deployment operations.
Handles loading configuration files, path resolution, and AWS client management.
"""

import re
import os
import yaml
import boto3
import json
import logging
import time
import fnmatch
from pathlib import Path
from typing import Dict, Any, Optional, List, Set

# Set up standardized logging with UTC time
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.Formatter.converter = time.gmtime  # Use UTC time
logging.basicConfig(
    level=logging.INFO, format=LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S UTC"
)
logger = logging.getLogger("deployment")


class ConfigurationError(Exception):
    """Exception raised for configuration errors."""

    pass


class ClientManager:
    """AWS client manager that handles caching and consistent region usage."""

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
            cls._region = os.environ.get("AWS_REGION")

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
            services = [
                "elasticbeanstalk",
                "iam",
                "s3",
                "elbv2",
                "acm",
                "route53",
                "ec2",
                "sts",
            ]
        return {service: cls.get_client(service) for service in services}


class EnvironmentManager:
    """Manages environment variables for both deployment and application."""

    @classmethod
    def load_env_file(cls, file_path: Path) -> Dict[str, str]:
        """
        Load environment variables from a .env file.

        Args:
            file_path: Path to the .env file

        Returns:
            Dictionary of environment variables
        """
        env_vars = {}

        if not file_path.exists():
            logger.debug(f"Environment file not found: {file_path}")
            return env_vars

        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "=" in line:
                        key, value = line.split("=", 1)
                        env_vars[key.strip()] = value.strip()

            logger.debug(f"Loaded {len(env_vars)} variables from {file_path}")
            return env_vars
        except Exception as e:
            logger.warning(f"Error loading environment file {file_path}: {e}")
            return env_vars

    @classmethod
    def filter_env_vars(
        cls, env_vars: Dict[str, str], exclude_patterns: List[str]
    ) -> Dict[str, str]:
        """
        Filter environment variables based on exclusion patterns.

        Args:
            env_vars: Dictionary of environment variables
            exclude_patterns: List of glob patterns to exclude

        Returns:
            Filtered dictionary of environment variables
        """
        if not exclude_patterns:
            return env_vars

        filtered_vars = {}

        for key, value in env_vars.items():
            excluded = False
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(key, pattern):
                    excluded = True
                    break

            if not excluded:
                filtered_vars[key] = value

        logger.debug(
            f"Filtered environment variables: {len(env_vars)} -> {len(filtered_vars)}"
        )
        return filtered_vars

    @classmethod
    def get_application_env_vars(cls, config: Dict) -> Dict[str, str]:
        """
        Get application environment variables based on configuration.

        Args:
            config: Configuration dictionary

        Returns:
            Dictionary of application environment variables
        """
        env_section = config.get("environment", {})

        # If environment section is not enabled, return empty dict
        if not env_section.get("enabled", False):
            return {}

        sources = env_section.get("sources", [])
        exclude_patterns = env_section.get("exclude_patterns", ["LB_*"])
        all_vars = {}

        for source in sources:
            if "file" in source:
                file_path = ConfigurationManager.get_project_root() / source["file"]
                file_vars = cls.load_env_file(file_path)
                all_vars.update(file_vars)

        # Filter variables based on exclude patterns
        return cls.filter_env_vars(all_vars, exclude_patterns)

    @classmethod
    def get_old_to_new_env_mapping(cls) -> Dict[str, str]:
        """
        Get mapping from old environment variable names to new prefixed names.

        Returns:
            Dictionary mapping old names to new names with LB_ prefix
        """
        return {
            "OIDC_CLIENT_ID": "LB_OIDC_CLIENT_ID",
            "OIDC_CLIENT_SECRET": "LB_OIDC_CLIENT_SECRET",
            "OIDC_ISSUER": "LB_OIDC_ISSUER",
            "OIDC_AUTH_ENDPOINT": "LB_OIDC_AUTH_ENDPOINT",
            "OIDC_TOKEN_ENDPOINT": "LB_OIDC_TOKEN_ENDPOINT",
            "OIDC_USERINFO_ENDPOINT": "LB_OIDC_USERINFO_ENDPOINT",
        }

    @classmethod
    def migrate_env_variables(cls, env_file_path: Path) -> bool:
        """
        Migrate old environment variable names to new prefixed format.

        Args:
            env_file_path: Path to the .env file

        Returns:
            True if migration occurred, False otherwise
        """
        if not env_file_path.exists():
            return False

        env_vars = cls.load_env_file(env_file_path)
        mapping = cls.get_old_to_new_env_mapping()

        # Check if any old variable names are present
        old_vars_present = any(old_name in env_vars for old_name in mapping.keys())

        if not old_vars_present:
            return False

        # Create updated content
        lines = []
        updated = set()

        with open(env_file_path, "r") as f:
            for line in f:
                original_line = line
                line = line.strip()

                if not line or line.startswith("#"):
                    lines.append(original_line)
                    continue

                if "=" in line:
                    key, value = line.split("=", 1)
                    key = key.strip()

                    if key in mapping:
                        new_key = mapping[key]
                        lines.append(f"{new_key}={value.strip()}\n")
                        updated.add(key)
                    else:
                        lines.append(original_line)
                else:
                    lines.append(original_line)

        # Add warning comment at the top if we made changes
        if updated:
            header = [
                "# WARNING: Environment variable names have been updated with LB_ prefix\n",
                "# The following variables were renamed:\n",
            ]

            for old_name in updated:
                header.append(f"# {old_name} -> {mapping[old_name]}\n")

            header.append("#\n")
            lines = header + lines

            # Write updated content
            with open(env_file_path, "w") as f:
                f.writelines(lines)

            logger.info(
                f"Migrated {len(updated)} environment variables to use LB_ prefix"
            )

            # Update os.environ with new values
            for old_name in updated:
                new_name = mapping[old_name]
                if old_name in os.environ:
                    os.environ[new_name] = os.environ[old_name]

            return True

        return False


class ConfigurationManager:
    """
    Manages and caches application configuration.
    Prioritizes .elasticbeanstalk/lazy-beanstalk.yml when available.
    """

    _config = None
    _eb_config = None
    _project_root = None
    _project_name = None
    _solution_stack_cache = None
    _custom_policies_cache = None

    # Trust policies should be excluded from automatic attachment
    _TRUST_POLICY_NAMES = {"eb-trust-policy.json", "ec2-trust-policy.json"}

    @classmethod
    def get_project_root(cls) -> Path:
        """Return the project root directory."""
        if not cls._project_root:
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
        return cls.get_project_root() / "deployment"

    @classmethod
    def get_config_path(cls) -> Path:
        """Return the path to the Lazy Beanstalk config file."""
        return cls.get_project_root() / "lazy-beanstalk.yml"

    @classmethod
    def get_env_file_path(cls) -> Path:
        """Return the path to the .env file."""
        return cls.get_project_root() / ".env"

    @classmethod
    def get_policies_dir(cls) -> Path:
        """Return the path to the policies directory."""
        return cls.get_deployment_dir() / "policies"

    @classmethod
    def get_policy_path(cls, filename: str) -> Path:
        """Return the path to a specific policy file."""
        policy_path = cls.get_policies_dir() / filename
        if not policy_path.exists():
            raise ConfigurationError(f"Policy file not found: {policy_path}")
        return policy_path

    @classmethod
    def get_custom_policies(
        cls, exclude_patterns: Optional[List[str]] = None
    ) -> List[str]:
        """
        Scan the policies directory and return all JSON files that aren't trust policies.

        Args:
            exclude_patterns: Optional list of patterns to exclude (uses simple string matching)

        Returns:
            List of policy file names (not full paths)
        """
        if cls._custom_policies_cache is not None:
            return cls._custom_policies_cache.copy()

        policies_dir = cls.get_policies_dir()
        if not policies_dir.exists():
            logger.warning(f"Policies directory not found: {policies_dir}")
            return []

        # Determine exclusions
        excluded_files = set(cls._TRUST_POLICY_NAMES)
        if exclude_patterns:
            for pattern in exclude_patterns:
                for file_path in policies_dir.glob(pattern):
                    excluded_files.add(file_path.name)

        # Get all JSON files in the policies directory
        all_policies = []
        invalid_files = []

        for file_path in policies_dir.glob("*.json"):
            if file_path.name not in excluded_files:
                # Validate JSON before including
                try:
                    with open(file_path, "r") as f:
                        json.load(f)
                    all_policies.append(file_path.name)
                except json.JSONDecodeError:
                    invalid_files.append(file_path.name)
                    logger.warning(f"Skipping invalid JSON file: {file_path.name}")

        if invalid_files:
            logger.warning(
                f"Found {len(invalid_files)} invalid policy files: {', '.join(invalid_files)}"
            )

        # Sort for consistent ordering
        all_policies.sort()

        # Cache the result
        cls._custom_policies_cache = all_policies

        return all_policies

    @classmethod
    def is_trust_policy(cls, policy_name: str) -> bool:
        """Check if a policy name is a trust policy."""
        return policy_name in cls._TRUST_POLICY_NAMES

    @classmethod
    def get_eb_config_path(cls) -> Optional[Path]:
        """Return the path to .elasticbeanstalk/config.yml if it exists."""
        path = cls.get_project_root() / ".elasticbeanstalk" / "config.yml"
        return path if path.exists() else None

    @classmethod
    def get_solution_stack_cache_path(cls) -> Path:
        """Return the path to the solution stack cache file."""
        eb_dir = cls.get_project_root() / ".elasticbeanstalk"
        return eb_dir / ".stack_cache"

    @classmethod
    def save_solution_stack(cls, solution_stack: str) -> None:
        """Save solution stack name to cache file for future reference."""
        if not solution_stack:
            return

        cache_path = cls.get_solution_stack_cache_path()
        # Create directory if it doesn't exist
        cache_path.parent.mkdir(exist_ok=True)

        with open(cache_path, "w") as f:
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
                logger.debug(
                    "Loaded EB CLI configuration from .elasticbeanstalk/config.yml"
                )
                return cls._eb_config
            except Exception as e:
                logger.warning(f"Failed to load EB CLI configuration: {e}")

        return None

    @classmethod
    def get_aws_region_from_eb_config(cls) -> Optional[str]:
        """Get AWS region from EB CLI configuration."""
        eb_config = cls.load_eb_config()
        if (
            eb_config
            and "global" in eb_config
            and "default_region" in eb_config["global"]
        ):
            region = eb_config["global"]["default_region"]
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
        if (
            eb_config
            and "global" in eb_config
            and "default_platform" in eb_config["global"]
        ):
            platform = eb_config["global"]["default_platform"]
            if platform:
                logger.debug(f"Using platform from EB CLI config: {platform}")
                return platform
        return None

    @classmethod
    def load_policy(cls, filename: str) -> Dict:
        """Load a JSON policy file."""
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
        region = os.environ.get("AWS_REGION")
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
                config = session.client("config")
                region = config.get_discovered_resource_counts(
                    resourceType="AWS::Config::ResourceCompliance", limit=1
                ).get("region")
                if region:
                    logger.debug(f"Using region from profile {profile}: {region}")
                    return region

            # If still no region, get first available region
            available_regions = session.get_available_regions("elasticbeanstalk")
            if available_regions:
                region = available_regions[0]
                logger.info(
                    f"No AWS region specified. Using first available region: {region}"
                )
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
            if platform.startswith("64bit"):
                # This is already a solution stack name, we can use it directly
                return platform

            # If it's a platform name like "Docker running on 64bit Amazon Linux 2023"
            # we need to convert it to a solution stack name
            platform_name = platform.lower()
            if "docker" in platform_name:
                logger.debug(
                    f"Converting EB CLI platform name to solution stack: {platform}"
                )
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
            eb_client = ClientManager.get_client("elasticbeanstalk")

            logger.info("Retrieving available solution stacks")
            solution_stacks = eb_client.list_available_solution_stacks()[
                "SolutionStacks"
            ]
            logger.debug(f"Found {len(solution_stacks)} solution stacks")

            # Filter for Docker stacks
            docker_stacks = [s for s in solution_stacks if "Docker" in s]
            logger.debug(f"Found {len(docker_stacks)} Docker solution stacks")

            if not docker_stacks:
                raise ConfigurationError(
                    "No Docker solution stacks found in this region"
                )

            # If we have a platform hint, filter for matching stacks
            if platform_hint:
                platform_hint = platform_hint.lower()
                filtered_stacks = [
                    s for s in docker_stacks if platform_hint in s.lower()
                ]
                if filtered_stacks:
                    docker_stacks = filtered_stacks

            # First try to find Amazon Linux 2023 Docker stacks
            al2023_stacks = [s for s in docker_stacks if "Amazon Linux 2023" in s]

            if al2023_stacks:
                # Sort to get the latest version
                latest_stack = sorted(al2023_stacks, reverse=True)[0]
                logger.info(
                    f"Using latest Amazon Linux 2023 Docker stack: {latest_stack}"
                )
                return latest_stack

            # If no AL2023 stacks, try Amazon Linux 2
            al2_stacks = [
                s
                for s in docker_stacks
                if "Amazon Linux 2" in s and "Amazon Linux 2023" not in s
            ]

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
        if isinstance(obj, str) and "${" in obj and "}" in obj:
            result = obj
            for placeholder, value in replacements.items():
                if f"${{{placeholder}}}" in result:
                    result = result.replace(f"${{{placeholder}}}", value)

            # Handle environment variables for any remaining ${VAR_NAME} patterns
            env_vars = re.findall(r"\${([A-Za-z0-9_]+)}", result)
            for var in env_vars:
                if var in os.environ:
                    result = result.replace(f"${{{var}}}", os.environ[var])
            return result
        elif isinstance(obj, dict):
            return {
                k: cls.replace_placeholders(v, replacements) for k, v in obj.items()
            }
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
                "PROJECT_NAME": project_name,
                "AWS_REGION": aws_region,
                "LATEST_DOCKER_PLATFORM": docker_platform,
            }

            # Add EB_CLI_PLATFORM for backwards compatibility
            eb_cli_platform = get_eb_cli_platform_name(docker_platform)
            replacements["EB_CLI_PLATFORM"] = eb_cli_platform

            # Check and migrate environment variables if needed
            env_file_path = cls.get_env_file_path()
            EnvironmentManager.migrate_env_variables(env_file_path)

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
        "aws": ["region", "platform"],
        "application": ["name", "environment"],
        "instance": ["type", "elb_type", "autoscaling"],
        "iam": ["service_role_name", "instance_role_name", "instance_profile_name"],
    }

    for section, fields in required.items():
        if section not in config:
            raise ConfigurationError(
                f"Missing required section '{section}' in configuration"
            )

        for field in fields:
            if field not in config[section]:
                raise ConfigurationError(
                    f"Missing required field '{field}' in '{section}' section"
                )


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
                if part == "Amazon" and i + 2 < len(platform_parts):
                    os_parts = platform_parts[
                        i - 1 : i + 3
                    ]  # Get bits, Amazon, Linux, version
                    break

            if os_parts:
                default_platform = f"Docker running on {' '.join(os_parts)}"

    return default_platform


def ensure_env_in_gitignore() -> None:
    """Ensure .env is listed in .gitignore file."""
    gitignore_path = ConfigurationManager.get_project_root() / ".gitignore"

    # Check if .gitignore exists
    if not gitignore_path.exists():
        logger.info("Creating .gitignore file with .env entry")
        with open(gitignore_path, "w") as f:
            f.write(".env\n")
        return

    # Check if .env is already in .gitignore
    with open(gitignore_path, "r") as f:
        content = f.read()

    if ".env" not in content.splitlines():
        logger.info("Adding .env to .gitignore")
        with open(gitignore_path, "a") as f:
            # Add newline if needed
            if not content.endswith("\n"):
                f.write("\n")
            f.write(".env\n")
