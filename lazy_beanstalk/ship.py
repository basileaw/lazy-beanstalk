# ship.py

"""
Handles deployment of Elastic Beanstalk application and associated AWS resources.
"""

import os
import yaml
import time
import zipfile
import fnmatch
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional, Any, List
from botocore.exceptions import ClientError

from . import support
from .config import (
    ClientManager,
    StateManager,
    logger,
    DeploymentError,
    ConfigurationError,
    merge_config,
    validate_dockerfile_exists,
    get_custom_policies_dir,
    MANAGED_POLICIES,
    detect_changes,
)


def create_app_bundle(working_dir: Optional[Path] = None) -> str:
    """Create a ZIP archive of application files based on .ebignore or .gitignore."""
    logger.info("Creating application bundle")
    if working_dir is None:
        working_dir = Path.cwd()

    ebignore_path = working_dir / ".ebignore"
    gitignore_path = working_dir / ".gitignore"

    # Parse .ebignore file, fall back to .gitignore if .ebignore doesn't exist
    patterns = []
    negated_patterns = []
    ignore_file = None

    # Always exclude these files and directories
    # .env* files should never be bundled - env vars passed via EB configuration
    default_excludes = [".git", ".gitignore", ".ebignore", ".env*"]
    patterns.extend(default_excludes)

    if ebignore_path.exists():
        ignore_file = ebignore_path
        logger.debug("Using .ebignore for bundle exclusions")
    elif gitignore_path.exists():
        ignore_file = gitignore_path
        logger.debug("Using .gitignore for bundle exclusions (no .ebignore found)")

    if ignore_file:
        with open(ignore_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if line.startswith("!"):
                        negated_patterns.append(line[1:])
                    else:
                        patterns.append(line)

    # Helper function to check if path should be excluded
    def should_exclude(path_normalized: str) -> bool:
        """Check if a path should be excluded based on patterns."""
        for pattern in patterns:
            # Handle directory patterns ending with slash
            test_pattern = pattern + "**" if pattern.endswith("/") else pattern

            # Handle single directory matching
            if "/" not in test_pattern and "/" in path_normalized:
                dirs = path_normalized.split("/")
                if any(fnmatch.fnmatch(d, test_pattern) for d in dirs):
                    return True
            # Direct pattern match
            elif fnmatch.fnmatch(path_normalized, test_pattern):
                return True
            # Handle ** patterns
            elif "**" in test_pattern:
                parts = test_pattern.split("**")
                if (
                    test_pattern.startswith("**")
                    and path_normalized.endswith(parts[1])
                ) or (
                    test_pattern.endswith("**")
                    and path_normalized.startswith(parts[0])
                ):
                    return True
        return False

    # Create bundle
    bundle_path = (
        Path(tempfile.gettempdir()) / f"app_bundle_{datetime.now():%Y%m%d_%H%M%S}.zip"
    )
    file_count = 0

    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(str(working_dir)):
            # Get relative path of current directory
            root_rel = os.path.relpath(root, str(working_dir))
            root_normalized = root_rel.replace(os.sep, "/") if root_rel != "." else ""

            # Filter out directories that should be excluded (modifies dirs in-place)
            dirs_to_remove = []
            for dir_name in dirs:
                dir_path = os.path.join(root_normalized, dir_name) if root_normalized else dir_name
                dir_path_normalized = dir_path.replace(os.sep, "/")

                if should_exclude(dir_path_normalized):
                    dirs_to_remove.append(dir_name)

            for dir_name in dirs_to_remove:
                dirs.remove(dir_name)

            # Process files
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, str(working_dir))

                # Convert Windows paths to forward slashes for pattern matching
                rel_path_normalized = rel_path.replace(os.sep, "/")

                # Check if file should be excluded
                excluded = should_exclude(rel_path_normalized)

                # Check if excluded file should be re-included
                if excluded:
                    for pattern in negated_patterns:
                        if fnmatch.fnmatch(rel_path_normalized, pattern):
                            excluded = False
                            break

                # Add file if not excluded and not the ignore file itself
                if not excluded and rel_path not in [".ebignore", ".gitignore"]:
                    zipf.write(file_path, rel_path)
                    file_count += 1

    logger.info(f"added {file_count} files")
    return str(bundle_path)


@support.aws_handler
def ensure_instance_profile(config: Dict[str, Any]) -> None:
    """Set up instance profile and its associated role."""
    iam_client = ClientManager.get_client("iam")
    profile_name = config["instance_profile_name"]
    role_name = config["instance_role_name"]

    # Set up the role first
    custom_policies_dir = get_custom_policies_dir(config.get("policies_dir"))

    support.manage_iam_role(
        role_name=role_name,
        trust_policy_name="ec2",
        managed_policy_arns=MANAGED_POLICIES["instance_role"],
        custom_policies_dir=custom_policies_dir,
    )

    try:
        iam_client.get_instance_profile(InstanceProfileName=profile_name)
        profile = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        # Check if role is attached
        roles = profile["InstanceProfile"].get("Roles", [])
        if not roles or roles[0]["RoleName"] != role_name:
            # Remove any existing roles
            for existing_role in roles:
                logger.info(
                    f"Removing role {existing_role['RoleName']} from profile {profile_name}"
                )
                iam_client.remove_role_from_instance_profile(
                    InstanceProfileName=profile_name, RoleName=existing_role["RoleName"]
                )
            # Add our role
            logger.info(f"Adding role {role_name} to profile {profile_name}")
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchEntity":
            logger.info(f"Creating instance profile {profile_name}")
            iam_client.create_instance_profile(InstanceProfileName=profile_name)
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
            # Allow time for profile propagation
            logger.info("Waiting for instance profile propagation")
            time.sleep(10)
        else:
            raise


def wait_for_version(app_name: str, version: str) -> None:
    """Wait for application version to be processed."""
    eb_client = ClientManager.get_client("elasticbeanstalk")
    logger.info("Waiting for application version to be processed")

    while True:
        versions = eb_client.describe_application_versions(
            ApplicationName=app_name, VersionLabels=[version]
        )["ApplicationVersions"]

        if not versions:
            raise DeploymentError(f"Version {version} not found")

        status = versions[0]["Status"]
        if status == "PROCESSED":
            break
        elif status == "FAILED":
            raise DeploymentError(f"Version {version} processing failed")

        time.sleep(3)


@support.aws_handler
def preserve_env_state(env_name: str, project_name: str) -> Optional[Dict[str, Any]]:
    """
    Preserve environment state before update, including HTTPS configuration.

    Args:
        env_name: Environment name
        project_name: Project name for tag prefix

    Returns:
        Dictionary containing state to preserve, or None if no state to preserve
    """
    # Get load balancer ARN
    lb_arn = support.find_environment_load_balancer(env_name)
    if not lb_arn:
        return None

    # Preserve HTTPS configuration if it exists
    https_config = support.preserve_https_config(lb_arn, project_name)
    if not https_config:
        return None

    return {"https_config": https_config, "load_balancer_arn": lb_arn}


def restore_env_state(state: Dict[str, Any], project_name: str) -> None:
    """
    Restore environment state after update, including HTTPS configuration.

    Args:
        state: State dictionary from preserve_env_state
        project_name: Project name for tag prefix
    """
    if not state:
        return

    if "https_config" in state and state["https_config"]:
        logger.info("Restoring HTTPS configuration...")
        support.restore_https_config(
            state["load_balancer_arn"], state["https_config"], project_name
        )


def format_env_vars_for_eb(env_vars: Dict[str, str]) -> List[Dict[str, str]]:
    """
    Format environment variables for Elastic Beanstalk option settings format.

    Args:
        env_vars: Dictionary of environment variables

    Returns:
        List of formatted option settings
    """
    settings = []

    for key, value in env_vars.items():
        settings.append(
            {
                "Namespace": "aws:elasticbeanstalk:application:environment",
                "OptionName": key,
                "Value": str(value),
            }
        )

    return settings


def create_or_update_env(config: Dict[str, Any], version: str) -> None:
    """Create or update Elastic Beanstalk environment."""
    eb_client = ClientManager.get_client("elasticbeanstalk")
    app_name = config["app_name"]
    env_name = config["environment_name"]

    # Check if environment exists
    envs = eb_client.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=False
    )["Environments"]
    env_exists = bool(envs)

    # Get basic settings
    settings = support.get_env_settings(config)

    # Get application environment variables
    env_vars = config.get("env_vars", {})
    if env_vars:
        logger.info(f"Found {len(env_vars)} application environment variables")
        env_var_settings = format_env_vars_for_eb(env_vars)
        settings.extend(env_var_settings)

    # Extract tags from configuration
    tags = []
    if "tags" in config:
        for key, value in config["tags"].items():
            tags.append({"Key": key, "Value": str(value)})
        if tags:
            logger.info(f"Found {len(tags)} tags to apply")

    state = None

    if env_exists:
        logger.info(f"Updating existing environment: {env_name}")

        # Check for changes to immutable settings
        current_env = envs[0]

        # Check platform/solution stack
        if current_env["SolutionStackName"] != config["platform"]:
            logger.warning("Platform change detected but cannot be updated after environment creation")
            logger.warning(f"  Current: {current_env['SolutionStackName']}")
            logger.warning(f"  Configured: {config['platform']}")
            logger.warning("  To change platform, you must terminate and recreate the environment")

        # Check load balancer type
        try:
            config_settings = eb_client.describe_configuration_settings(
                ApplicationName=app_name,
                EnvironmentName=env_name
            )["ConfigurationSettings"][0]

            # Find current load balancer type
            current_lb_type = None
            for option in config_settings.get("OptionSettings", []):
                if (option["Namespace"] == "aws:elasticbeanstalk:environment" and
                    option["OptionName"] == "LoadBalancerType"):
                    current_lb_type = option["Value"]
                    break

            if current_lb_type and current_lb_type != config["elb_type"]:
                logger.warning("Load balancer type change detected but cannot be updated after environment creation")
                logger.warning(f"  Current: {current_lb_type}")
                logger.warning(f"  Configured: {config['elb_type']}")
                logger.warning("  To change load balancer type, you must terminate and recreate the environment")
        except Exception as e:
            logger.debug(f"Could not check load balancer type: {e}")

        # Preserve state before update
        state = preserve_env_state(env_name, app_name)

        # Note: update_environment does not support Tags parameter
        # Tags can only be set during environment creation
        update_params = {
            "EnvironmentName": env_name,
            "VersionLabel": version,
            "OptionSettings": settings
        }

        eb_client.update_environment(**update_params)
    else:
        logger.info(f"Creating new environment: {env_name}")
        settings.append(
            {
                "Namespace": "aws:elasticbeanstalk:environment",
                "OptionName": "LoadBalancerType",
                "Value": config["elb_type"],
            }
        )
        create_params = {
            "ApplicationName": app_name,
            "EnvironmentName": env_name,
            "VersionLabel": version,
            "SolutionStackName": config["platform"],
            "OptionSettings": settings,
        }
        if tags:
            create_params["Tags"] = tags

        eb_client.create_environment(**create_params)

    # Wait for environment to be ready
    support.wait_for_env_status(env_name, "Ready")

    # Restore state if needed
    if state:
        restore_env_state(state, app_name)


def build_eb_cli_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build EB CLI configuration structure (without writing to file).

    Args:
        config: The merged configuration dictionary

    Returns:
        EB CLI config dictionary
    """
    # Convert solution stack to EB CLI platform name
    solution_stack = config["platform"]
    # Simple conversion - just extract the Docker + Amazon Linux part
    if "Amazon Linux 2023" in solution_stack:
        platform_name = "Docker running on 64bit Amazon Linux 2023"
    elif "Amazon Linux 2" in solution_stack:
        platform_name = "Docker running on 64bit Amazon Linux 2"
    else:
        platform_name = "Docker"

    eb_config = {
        "branch-defaults": {
            "main": {
                "environment": config["environment_name"],
                "group_suffix": None,
            }
        },
        "global": {
            "application_name": config["app_name"],
            "branch": None,
            "default_ec2_keyname": None,
            "default_platform": platform_name,
            "default_region": config["region"],
            "include_git_submodules": True,
            "instance_profile": None,
            "platform_name": None,
            "platform_version": None,
            "profile": None,
            "repository": None,
            "sc": "git",
            "workspace_type": "Application",
        },
    }

    return eb_config


def ship(**kwargs) -> Dict[str, Any]:
    """
    Deploy application to AWS Elastic Beanstalk.

    Args:
        app_name (str): Application name (default: current directory name)
        environment_name (str): EB environment name (default: {app_name}-env)
        region (str): AWS region (default: us-west-2)
        instance_type (str): EC2 instance type (default: t4g.nano)
        spot_instances (bool): Use spot instances (default: False)
        min_instances (int): Min autoscaling instances (default: 1)
        max_instances (int): Max autoscaling instances (default: 1)
        policies_dir (str): Path to custom IAM policies directory (default: None)
        env_vars (dict): Environment variables to pass to application (default: {})
        tags (dict): AWS resource tags (default: {"Environment": "development", "ManagedBy": "lazy-beanstalk"})
        dockerfile_path (str): Path to Dockerfile (default: ./Dockerfile)
        aws_profile (str): AWS profile name (default: None, uses boto3 defaults)

    Returns:
        Dict with deployment details (environment URL, app name, version, etc.)
    """
    # Load existing state
    prev_state = StateManager.load_state()

    # Merge configuration
    config = merge_config(**kwargs)

    # Validate Dockerfile exists
    validate_dockerfile_exists(config["dockerfile_path"])

    # Detect changes
    if prev_state:
        change_info = detect_changes(config, prev_state)
        if change_info["changed"]:
            logger.info("Detected changes:")
            for change in change_info["changes_list"]:
                logger.info(f"  - {change}")

    logger.info("Starting deployment")
    logger.info(f"App: {config['app_name']}")
    logger.info(f"Environment: {config['environment_name']}")
    logger.info(f"Region: {config['region']}")
    logger.info(f"Platform: {config['platform']}")

    # Build EB CLI config structure
    eb_cli_config = build_eb_cli_config(config)

    # Set up AWS clients
    eb_client = ClientManager.get_client("elasticbeanstalk")
    s3_client = ClientManager.get_client("s3")

    # Set up service role
    custom_policies_dir = get_custom_policies_dir(config.get("policies_dir"))
    support.manage_iam_role(
        role_name=config["service_role_name"],
        trust_policy_name="eb",
        managed_policy_arns=MANAGED_POLICIES["service_role"],
        custom_policies_dir=None,  # Service role doesn't get custom policies
    )

    # Set up instance profile
    ensure_instance_profile(config)

    # Create/update application
    app_name = config["app_name"]
    app_description = f"{app_name} application deployed with lazy-beanstalk"

    if not eb_client.describe_applications(ApplicationNames=[app_name])["Applications"]:
        logger.info(f"Creating application: {app_name}")
        eb_client.create_application(
            ApplicationName=app_name,
            Description=app_description,
        )
    else:
        logger.info(f"Using existing application: {app_name}")
        # Update application description
        logger.info(f"Updating application description")
        eb_client.update_application(
            ApplicationName=app_name,
            Description=app_description
        )

    # Create and upload application version
    version = f"v{datetime.now():%Y%m%d_%H%M%S}"
    region = config["region"]
    bucket = f"elasticbeanstalk-{region}-{app_name.lower()}"

    # Check if bucket exists
    try:
        s3_client.head_bucket(Bucket=bucket)
        logger.info(f"Using existing S3 bucket: {bucket}")
    except ClientError:
        # For regions other than us-east-1, we need to specify the LocationConstraint
        logger.info(f"Creating S3 bucket: {bucket}")
        create_bucket_args = {"Bucket": bucket}
        if region != "us-east-1":
            create_bucket_args["CreateBucketConfiguration"] = {
                "LocationConstraint": region
            }

        s3_client.create_bucket(**create_bucket_args)

    # Create application bundle
    bundle = create_app_bundle()
    key = f"app-{version}.zip"

    # Upload to S3
    logger.info(f"Uploading application bundle to S3")
    with open(bundle, "rb") as f:
        s3_client.upload_fileobj(f, bucket, key)

    # Clean up local bundle
    os.remove(bundle)

    # Create application version
    logger.info(f"Creating application version: {version}")
    eb_client.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version,
        SourceBundle={"S3Bucket": bucket, "S3Key": key},
        Process=True,
    )

    # Wait for version to be processed
    wait_for_version(app_name, version)

    # Create or update environment
    create_or_update_env(config, version)

    # Get environment URL
    env = eb_client.describe_environments(
        EnvironmentNames=[config["environment_name"]], IncludeDeleted=False
    )["Environments"][0]

    environment_url = env.get("EndpointURL") or env.get("CNAME")

    logger.info(f"Deployment completed successfully!")
    logger.info(f"Application URL: http://{environment_url}")

    # Save state
    deployment_state = {
        "instance_type": config["instance_type"],
        "spot_instances": config["spot_instances"],
        "min_instances": config["min_instances"],
        "max_instances": config["max_instances"],
        "platform": config["platform"],
        "env_vars": config.get("env_vars", {}),
        "tags": config.get("tags", {}),
        "last_version": version,
        "environment_url": environment_url,
    }

    StateManager.save_state(deployment_state, eb_cli_config=eb_cli_config)

    # Return deployment details
    return {
        "app_name": app_name,
        "environment_name": config["environment_name"],
        "environment_url": environment_url,
        "version": version,
        "region": region,
    }
