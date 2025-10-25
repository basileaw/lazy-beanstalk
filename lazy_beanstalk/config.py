# config.py

"""
Configuration management for lazy-beanstalk.

Implements config hierarchy: defaults → env vars → state file → API parameters
Manages state file for change detection and deployment tracking.
"""

import os
import json
import yaml
import boto3
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# Set up standardized logging with UTC time
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.Formatter.converter = time.gmtime  # Use UTC time
logging.basicConfig(
    level=logging.INFO, format=LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S UTC"
)
logger = logging.getLogger("lazy_beanstalk")


class ConfigurationError(Exception):
    """Exception raised for configuration errors."""
    pass


class DeploymentError(Exception):
    """Exception raised for deployment errors."""
    pass


# Smart defaults for configuration
DEFAULTS = {
    "region": "us-west-2",
    "instance_type": "t4g.nano",
    "spot_instances": False,
    "min_instances": 1,
    "max_instances": 1,
    "dockerfile_path": "./Dockerfile",
    "tags": {
        "Environment": "development",
        "ManagedBy": "lazy-beanstalk",
    },
    "elb_type": "application",
    "https_ttl": 300,
    "https_domain_mode": "sub",
    "oidc_session_timeout": 36000,
    "oidc_session_cookie_name": "federate_id_token",
    "oidc_scope": "openid",
}

# AWS managed policies
MANAGED_POLICIES = {
    "service_role": [
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService",
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
    ],
    "instance_role": [
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkMulticontainerDocker",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier",
    ],
}


def get_env_var(name: str, fallback: Optional[str] = None, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """
    Get environment variable with optional fallback to standard name.

    Priority:
    1. LB_{name} (canonical lazy-beanstalk var)
    2. {fallback} (standard/common name if provided)
    3. {default} (default value if provided)
    4. Raise error if required=True and not found

    Args:
        name: Variable name (will be prefixed with LB_)
        fallback: Alternative env var name to try if LB_{name} not found
        default: Default value if neither var is found
        required: Raise ConfigurationError if not found and no default

    Returns:
        Environment variable value or None

    Examples:
        # Region with AWS standard fallback
        get_env_var("REGION", fallback="AWS_REGION", default="us-west-2")

        # Certificate ARN (optional)
        get_env_var("CERTIFICATE_ARN")

        # Required parameter
        get_env_var("OIDC_CLIENT_ID", required=True)
    """
    # Try canonical LB_ prefixed name first
    lb_name = f"LB_{name}"
    value = os.getenv(lb_name)
    if value is not None:
        return value

    # Try fallback name if provided
    if fallback:
        value = os.getenv(fallback)
        if value is not None:
            return value

    # Use default if provided
    if default is not None:
        return default

    # Raise if required and not found
    if required:
        fallback_msg = f" or {fallback}" if fallback else ""
        raise ConfigurationError(f"Missing required environment variable: {lb_name}{fallback_msg}")

    return None


def get_oidc_env_var(name: str, required: bool = False) -> Optional[str]:
    """
    Get OIDC environment variable with fallback to unprefixed standard name.

    Provider credentials (client_id, client_secret, issuer, endpoints) accept
    both LB_OIDC_{name} and OIDC_{name} for reusability across tools.

    Args:
        name: OIDC variable name (e.g., "CLIENT_ID")
        required: Raise ConfigurationError if not found

    Returns:
        Environment variable value or None

    Example:
        get_oidc_env_var("CLIENT_ID")
        # Tries: LB_OIDC_CLIENT_ID, then OIDC_CLIENT_ID
    """
    # Try LB_OIDC_{name} first, then fall back to OIDC_{name}
    lb_name = f"LB_OIDC_{name}"
    oidc_name = f"OIDC_{name}"

    value = os.getenv(lb_name)
    if value is not None:
        return value

    value = os.getenv(oidc_name)
    if value is not None:
        return value

    if required:
        raise ConfigurationError(f"Missing required OIDC parameter: {lb_name} or {oidc_name}")

    return None


def load_app_env_vars(deployment_env_file: str = ".env.lb") -> Dict[str, str]:
    """
    Load all .env* files and return vars to pass to EB environment.

    Filtering rules:
    1. Vars from deployment env file (.env.lb) are excluded
    2. Vars starting with LB_ prefix are excluded (deployment-only)

    This allows separation of:
    - App vars (.env, .env.production, etc.) → passed to EB
    - Deployment vars (.env.lb or LB_* prefix) → used locally only

    Args:
        deployment_env_file: File containing deployment-only vars (default: .env.lb)

    Returns:
        Dict of environment variables to pass to EB

    Examples:
        # Separate files (explicit separation)
        # .env
        DATABASE_URL=postgres://...

        # .env.lb
        AWS_REGION=us-west-2
        LB_INSTANCE_TYPE=t4g.nano

        # Result: only DATABASE_URL passed to EB

        # Single file (prefix-based filtering)
        # .env
        DATABASE_URL=postgres://...
        AWS_REGION=us-west-2              # ← Passed to EB
        LB_INSTANCE_TYPE=t4g.nano         # ← NOT passed (LB_ prefix)
        LB_OIDC_CLIENT_SECRET=secret      # ← NOT passed (LB_ prefix)

        # Result: only DATABASE_URL and AWS_REGION passed to EB
    """
    from dotenv import dotenv_values
    from pathlib import Path

    # Find all .env* files in current directory
    env_files = sorted(Path.cwd().glob(".env*"))
    deployment_path = Path.cwd() / deployment_env_file

    # Load deployment vars (to exclude from EB)
    deployment_vars = set()
    if deployment_path.exists():
        deployment_vars = set(dotenv_values(str(deployment_path)).keys())
        logger.debug(f"Loaded {len(deployment_vars)} deployment vars from {deployment_env_file}")

    # Load all .env* files and merge (except deployment file)
    app_vars = {}
    for env_file in env_files:
        if env_file.resolve() != deployment_path.resolve():
            file_vars = dotenv_values(str(env_file))
            logger.debug(f"Loading {len(file_vars)} vars from {env_file.name}")
            app_vars.update(file_vars)

    # Filter out deployment vars and LB_ prefixed vars
    filtered_vars = {
        k: v for k, v in app_vars.items()
        if k not in deployment_vars and not k.startswith("LB_")
    }

    if filtered_vars:
        logger.info(f"Auto-loaded {len(filtered_vars)} app environment variables from .env files")

    return filtered_vars


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


class StateManager:
    """Manages state in .elasticbeanstalk/config.yml for deployment tracking."""

    @classmethod
    def get_eb_config_path(cls, working_dir: Optional[Path] = None) -> Path:
        """Get the path to the EB CLI config file."""
        if working_dir is None:
            working_dir = Path.cwd()
        return working_dir / ".elasticbeanstalk" / "config.yml"

    @classmethod
    def load_eb_config(cls, working_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Load complete EB CLI config including lazy_beanstalk section."""
        config_file = cls.get_eb_config_path(working_dir)
        if not config_file.exists():
            return None

        try:
            with open(config_file, "r") as f:
                config = yaml.safe_load(f)
            logger.debug(f"Loaded EB config from {config_file}")
            return config
        except Exception as e:
            logger.warning(f"Error loading EB config file: {e}")
            return None

    @classmethod
    def load_state(cls, working_dir: Optional[Path] = None) -> Optional[Dict[str, Any]]:
        """Load lazy-beanstalk state from EB CLI config."""
        eb_config = cls.load_eb_config(working_dir)
        if not eb_config:
            return None

        # Extract lazy_beanstalk section
        return eb_config.get("lazy_beanstalk")

    @classmethod
    def save_state(cls, state: Dict[str, Any], eb_cli_config: Optional[Dict[str, Any]] = None, working_dir: Optional[Path] = None) -> None:
        """
        Save lazy-beanstalk state to EB CLI config.

        Args:
            state: Lazy-beanstalk state to save
            eb_cli_config: EB CLI config structure (if provided, updates the EB sections)
            working_dir: Working directory
        """
        config_file = cls.get_eb_config_path(working_dir)

        # Load existing config or use provided one
        if eb_cli_config:
            eb_config = eb_cli_config
        else:
            eb_config = cls.load_eb_config(working_dir) or {}

        # Add timestamp
        state["last_updated"] = datetime.utcnow().isoformat() + "Z"

        # Update lazy_beanstalk section
        eb_config["lazy_beanstalk"] = state

        try:
            # Ensure directory exists
            config_file.parent.mkdir(parents=True, exist_ok=True)

            with open(config_file, "w") as f:
                yaml.safe_dump(eb_config, f, sort_keys=True, default_flow_style=False)
            logger.info(f"Saved configuration to {config_file}")
        except Exception as e:
            logger.error(f"Error saving state to EB config: {e}")
            raise ConfigurationError(f"Failed to save state: {e}")

    @classmethod
    def delete_state(cls, working_dir: Optional[Path] = None) -> None:
        """Delete lazy_beanstalk section from EB CLI config."""
        eb_config = cls.load_eb_config(working_dir)
        if not eb_config:
            return

        # Remove lazy_beanstalk section
        if "lazy_beanstalk" in eb_config:
            del eb_config["lazy_beanstalk"]

            config_file = cls.get_eb_config_path(working_dir)
            try:
                with open(config_file, "w") as f:
                    yaml.safe_dump(eb_config, f, sort_keys=True, default_flow_style=False)
                logger.debug(f"Deleted lazy_beanstalk state from {config_file}")
            except Exception as e:
                logger.warning(f"Error deleting state: {e}")


def get_default_app_name() -> str:
    """Infer app name from current directory."""
    return Path.cwd().name


def get_default_environment_name(app_name: str) -> str:
    """Generate default environment name from app name."""
    return f"{app_name}-env"


def get_iam_role_names(app_name: str) -> Dict[str, str]:
    """Generate IAM role names from app name."""
    return {
        "service_role_name": f"{app_name}-eb-role",
        "instance_role_name": f"{app_name}-ec2-role",
        "instance_profile_name": f"{app_name}-ec2-profile",
    }


def get_latest_docker_platform() -> str:
    """
    Get the latest Docker platform from Elastic Beanstalk.
    Returns the exact solution stack name needed for environment creation.
    """
    try:
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


def merge_config(**kwargs) -> Dict[str, Any]:
    """
    Merge configuration from multiple sources.

    Priority (lowest to highest):
    1. Hardcoded defaults
    2. Environment variables
    3. EB CLI config (.elasticbeanstalk/config.yml)
    4. lazy_beanstalk state section
    5. API parameters (kwargs)

    Args:
        **kwargs: API parameters to override

    Returns:
        Merged configuration dictionary
    """
    config = {}

    # Start with defaults
    config.update(DEFAULTS)

    # Apply environment variables (layer 2)
    # Region: Try LB_REGION, then AWS_REGION, then AWS_DEFAULT_REGION
    region_var = get_env_var("REGION", fallback="AWS_REGION")
    if not region_var:
        region_var = os.getenv("AWS_DEFAULT_REGION")
    if region_var:
        config["region"] = region_var

    # Deployment parameters
    if instance_type := get_env_var("INSTANCE_TYPE"):
        config["instance_type"] = instance_type

    if spot_instances := get_env_var("SPOT_INSTANCES"):
        config["spot_instances"] = spot_instances.lower() in ("true", "1", "yes")

    if min_instances := get_env_var("MIN_INSTANCES"):
        config["min_instances"] = int(min_instances)

    if max_instances := get_env_var("MAX_INSTANCES"):
        config["max_instances"] = int(max_instances)

    # Load EB CLI config to get app_name, environment_name, region
    eb_config = StateManager.load_eb_config()
    if eb_config:
        # Extract from EB CLI global section
        global_config = eb_config.get("global", {})
        if "application_name" in global_config:
            config["app_name"] = global_config["application_name"]
        if "default_region" in global_config:
            config["region"] = global_config["default_region"]

        # Extract environment name from branch-defaults
        branch_defaults = eb_config.get("branch-defaults", {})
        main_branch = branch_defaults.get("main", {})
        if "environment" in main_branch:
            config["environment_name"] = main_branch["environment"]

        # Load lazy_beanstalk state section
        state = eb_config.get("lazy_beanstalk")
        if state:
            # Merge lazy-beanstalk-specific state
            for key in ["instance_type", "spot_instances", "min_instances", "max_instances", "platform", "env_vars", "tags"]:
                if key in state:
                    config[key] = state[key]

    # Fall back to defaults if not in EB CLI config
    if "app_name" not in config:
        config["app_name"] = get_default_app_name()
    if "environment_name" not in config:
        config["environment_name"] = get_default_environment_name(config["app_name"])

    # Apply API parameters (highest priority)
    for key, value in kwargs.items():
        if value is not None:
            config[key] = value

    # Initialize AWS client manager with the region
    ClientManager.initialize(config["region"])

    # Get platform if not set
    if "platform" not in config:
        config["platform"] = get_latest_docker_platform()

    # Generate IAM role names
    iam_roles = get_iam_role_names(config["app_name"])
    config.update(iam_roles)

    # Ensure env_vars is a dict
    if "env_vars" not in config:
        config["env_vars"] = {}

    # Ensure tags is a dict
    if "tags" not in config:
        config["tags"] = DEFAULTS["tags"].copy()

    return config


def detect_changes(current_config: Dict[str, Any], state: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Detect changes between current config and previous state.

    Args:
        current_config: Current configuration
        state: Previous state from file

    Returns:
        Dictionary of changes with keys: changed, changes_list
    """
    if not state:
        return {"changed": True, "changes_list": ["Initial deployment"]}

    changes = []

    # Check for changes in key deployment parameters
    check_keys = [
        "instance_type",
        "spot_instances",
        "min_instances",
        "max_instances",
        "platform",
        "region",
    ]

    for key in check_keys:
        old_value = state.get(key)
        new_value = current_config.get(key)
        if old_value != new_value:
            changes.append(f"{key}: {old_value} → {new_value}")

    # Check environment variables
    old_env = state.get("env_vars", {})
    new_env = current_config.get("env_vars", {})
    if old_env != new_env:
        changes.append("Environment variables updated")

    # Check tags
    old_tags = state.get("tags", {})
    new_tags = current_config.get("tags", {})
    if old_tags != new_tags:
        changes.append("Tags updated")

    return {
        "changed": len(changes) > 0,
        "changes_list": changes if changes else ["No changes detected"]
    }


def validate_dockerfile_exists(dockerfile_path: str) -> None:
    """Validate that Dockerfile exists at the specified path."""
    path = Path(dockerfile_path)
    if not path.exists():
        raise ConfigurationError(
            f"Dockerfile not found at {dockerfile_path}\n"
            f"lazy-beanstalk requires you to provide your own Dockerfile.\n"
            f"Please create a Dockerfile in your project root before deploying."
        )
    logger.debug(f"Found Dockerfile at {dockerfile_path}")


def get_custom_policies_dir(policies_dir: Optional[str] = None) -> Optional[Path]:
    """Get the custom policies directory if it exists."""
    if not policies_dir:
        # Default to ./policies if it exists
        default_path = Path.cwd() / "policies"
        if default_path.exists():
            logger.info(f"Using default policies directory: {default_path}")
            return default_path
        return None

    policies_path = Path(policies_dir)
    if not policies_path.exists():
        logger.warning(f"Custom policies directory not found: {policies_dir}")
        return None

    return policies_path


def load_custom_policies(policies_dir: Optional[Path]) -> Dict[str, Any]:
    """Load custom IAM policies from directory."""
    if not policies_dir or not policies_dir.exists():
        return {}

    policies = {}
    trust_policy_names = {"eb-trust-policy.json", "ec2-trust-policy.json"}

    for policy_file in policies_dir.glob("*.json"):
        # Skip trust policies
        if policy_file.name in trust_policy_names:
            continue

        try:
            with open(policy_file, "r") as f:
                policy_content = json.load(f)
            policies[policy_file.name] = policy_content
            logger.debug(f"Loaded custom policy: {policy_file.name}")
        except json.JSONDecodeError as e:
            logger.warning(f"Skipping invalid JSON file {policy_file.name}: {e}")
        except Exception as e:
            logger.warning(f"Error loading policy {policy_file.name}: {e}")

    return policies


def get_default_trust_policies() -> Dict[str, Path]:
    """Get paths to default trust policies."""
    package_dir = Path(__file__).parent
    policies_dir = package_dir / "defaults" / "policies"

    return {
        "eb_trust_policy": policies_dir / "eb-trust-policy.json",
        "ec2_trust_policy": policies_dir / "ec2-trust-policy.json",
    }


def load_trust_policy(policy_name: str) -> Dict[str, Any]:
    """Load a trust policy by name."""
    trust_policies = get_default_trust_policies()

    if policy_name == "eb":
        policy_path = trust_policies["eb_trust_policy"]
    elif policy_name == "ec2":
        policy_path = trust_policies["ec2_trust_policy"]
    else:
        raise ConfigurationError(f"Unknown trust policy: {policy_name}")

    if not policy_path.exists():
        raise ConfigurationError(f"Trust policy not found: {policy_path}")

    try:
        with open(policy_path, "r") as f:
            return json.load(f)
    except Exception as e:
        raise ConfigurationError(f"Failed to load trust policy {policy_name}: {e}")
