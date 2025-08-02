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
from .setup import (
    ConfigurationManager,
    ClientManager,
    logger,
    get_eb_cli_platform_name,
    EnvironmentManager,
)


def create_app_bundle() -> str:
    """Create a ZIP archive of application files based on .ebignore."""
    logger.info("Creating application bundle")
    project_root = ConfigurationManager.get_project_root()
    ebignore_path = project_root / ".ebignore"

    # Parse .ebignore file
    patterns = []
    negated_patterns = []
    if ebignore_path.exists():
        with open(ebignore_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if line.startswith("!"):
                        negated_patterns.append(line[1:])
                    else:
                        patterns.append(line)

    # Create bundle
    bundle_path = (
        Path(tempfile.gettempdir()) / f"app_bundle_{datetime.now():%Y%m%d_%H%M%S}.zip"
    )
    file_count = 0

    with zipfile.ZipFile(bundle_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(str(project_root)):
            for filename in files:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, str(project_root))

                # Convert Windows paths to forward slashes for pattern matching
                rel_path_normalized = rel_path.replace(os.sep, "/")

                # Check if file should be excluded
                excluded = False
                for pattern in patterns:
                    # Handle directory patterns ending with slash
                    if pattern.endswith("/"):
                        pattern = pattern + "**"
                    # Handle single directory matching
                    if "/" not in pattern and "/" in rel_path_normalized:
                        dirs = rel_path_normalized.split("/")
                        if any(fnmatch.fnmatch(d, pattern) for d in dirs):
                            excluded = True
                            break
                    # Direct pattern match
                    elif fnmatch.fnmatch(rel_path_normalized, pattern):
                        excluded = True
                        break
                    # Handle ** patterns
                    elif "**" in pattern:
                        parts = pattern.split("**")
                        if (
                            pattern.startswith("**")
                            and rel_path_normalized.endswith(parts[1])
                        ) or (
                            pattern.endswith("**")
                            and rel_path_normalized.startswith(parts[0])
                        ):
                            excluded = True
                            break

                # Check if excluded file should be re-included
                if excluded:
                    for pattern in negated_patterns:
                        if fnmatch.fnmatch(rel_path_normalized, pattern):
                            excluded = False
                            break

                # Add file if not excluded
                if not excluded and not rel_path == ".ebignore":
                    zipf.write(file_path, rel_path)
                    file_count += 1
                    # No progress indicator needed - removed

    logger.info(f"added {file_count} files")
    return str(bundle_path)


@support.aws_handler
def ensure_instance_profile(config: Dict[str, Any]) -> None:
    """Set up instance profile and its associated role."""
    iam_client = ClientManager.get_client("iam")
    profile_name = config["iam"]["instance_profile_name"]
    role_name = config["iam"]["instance_role_name"]

    # Set up the role first
    support.manage_iam_role(role_name, config["iam"]["instance_role_policies"])

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
            raise support.DeploymentError(f"Version {version} not found")

        status = versions[0]["Status"]
        if status == "PROCESSED":
            break
        elif status == "FAILED":
            raise support.DeploymentError(f"Version {version} processing failed")

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
    project_name = ConfigurationManager.get_project_name()
    env_name = config["application"]["environment"]

    # Check if environment exists
    envs = eb_client.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=False
    )["Environments"]
    env_exists = bool(envs)

    # Get basic settings
    settings = support.get_env_settings(config)

    # Get application environment variables if enabled
    env_vars = EnvironmentManager.get_application_env_vars(config)
    if env_vars:
        logger.info(f"Found {len(env_vars)} application environment variables")
        env_var_settings = format_env_vars_for_eb(env_vars)
        settings.extend(env_var_settings)

    # Extract tags from configuration
    tags = []
    if "aws" in config and "tags" in config["aws"]:
        for key, value in config["aws"]["tags"].items():
            tags.append({"Key": key, "Value": str(value)})
        if tags:
            logger.info(f"Found {len(tags)} tags to apply")

    state = None

    if env_exists:
        logger.info(f"Updating existing environment: {env_name}")
        
        # Check for changes to immutable settings
        current_env = envs[0]
        
        # Check platform/solution stack
        if current_env["SolutionStackName"] != config["aws"]["platform"]:
            logger.warning("Platform change detected but cannot be updated after environment creation")
            logger.warning(f"  Current: {current_env['SolutionStackName']}")
            logger.warning(f"  Configured: {config['aws']['platform']}")
            logger.warning("  To change platform, you must terminate and recreate the environment")
        
        # Check load balancer type
        try:
            config_settings = eb_client.describe_configuration_settings(
                ApplicationName=config["application"]["name"],
                EnvironmentName=env_name
            )["ConfigurationSettings"][0]
            
            # Find current load balancer type
            current_lb_type = None
            for option in config_settings.get("OptionSettings", []):
                if (option["Namespace"] == "aws:elasticbeanstalk:environment" and
                    option["OptionName"] == "LoadBalancerType"):
                    current_lb_type = option["Value"]
                    break
            
            if current_lb_type and current_lb_type != config["instance"]["elb_type"]:
                logger.warning("Load balancer type change detected but cannot be updated after environment creation")
                logger.warning(f"  Current: {current_lb_type}")
                logger.warning(f"  Configured: {config['instance']['elb_type']}")
                logger.warning("  To change load balancer type, you must terminate and recreate the environment")
        except Exception as e:
            logger.debug(f"Could not check load balancer type: {e}")
        
        # Preserve state before update
        state = preserve_env_state(env_name, project_name)

        update_params = {
            "EnvironmentName": env_name,
            "VersionLabel": version,
            "OptionSettings": settings
        }
        if tags:
            update_params["Tags"] = tags
            
        eb_client.update_environment(**update_params)
    else:
        logger.info(f"Creating new environment: {env_name}")
        settings.append(
            {
                "Namespace": "aws:elasticbeanstalk:environment",
                "OptionName": "LoadBalancerType",
                "Value": config["instance"]["elb_type"],
            }
        )
        create_params = {
            "ApplicationName": config["application"]["name"],
            "EnvironmentName": env_name,
            "VersionLabel": version,
            "SolutionStackName": config["aws"]["platform"],
            "OptionSettings": settings,
        }
        if tags:
            create_params["Tags"] = tags
            
        eb_client.create_environment(**create_params)

    # Wait for environment to be ready
    support.wait_for_env_status(env_name, "Ready")

    # Restore state if needed
    if state:
        restore_env_state(state, project_name)


def create_eb_cli_config(config: Dict[str, Any]) -> None:
    """
    Create EB CLI configuration file from the main config.yml.

    Args:
        config: The loaded and processed config dictionary
    """
    project_root = ConfigurationManager.get_project_root()
    eb_dir = project_root / ".elasticbeanstalk"
    eb_dir.mkdir(exist_ok=True)

    # Get the solution stack name and save it to cache
    solution_stack = config["aws"]["platform"]
    ConfigurationManager.save_solution_stack(solution_stack)

    eb_config = {
        "branch-defaults": {
            "main": {
                "environment": config["application"]["environment"],
                "group_suffix": None,
            }
        },
        "global": {
            "application_name": config["application"]["name"],
            "branch": None,
            "default_ec2_keyname": None,
            "default_platform": get_eb_cli_platform_name(solution_stack),
            "default_region": config["aws"]["region"],
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

    # Write the config file
    config_path = eb_dir / "config.yml"
    with open(config_path, "w") as f:
        yaml.safe_dump(eb_config, f, sort_keys=True)
    logger.info(f"Created EB CLI configuration in {config_path}")


def deploy_application(config: Dict[str, Any]) -> None:
    """Deploy the application to Elastic Beanstalk."""
    project_name = ConfigurationManager.get_project_name()
    region = config["aws"]["region"]
    platform = config["aws"]["platform"]

    logger.info("Starting deployment")
    logger.info(f"Deploying to region: {region}")
    logger.info(f"Using platform: {platform}")

    # Create EB CLI config file
    create_eb_cli_config(config)

    # Set up IAM resources
    eb_client = ClientManager.get_client("elasticbeanstalk")
    iam_client = ClientManager.get_client("iam")
    s3_client = ClientManager.get_client("s3")
    sts_client = ClientManager.get_client("sts")

    # Set up service role
    support.manage_iam_role(
        config["iam"]["service_role_name"], config["iam"]["service_role_policies"]
    )

    # Set up instance profile
    ensure_instance_profile(config)

    # Create/update application
    app_name = config["application"]["name"]
    if not eb_client.describe_applications(ApplicationNames=[app_name])["Applications"]:
        logger.info(f"Creating application: {app_name}")
        eb_client.create_application(
            ApplicationName=app_name,
            Description=config.get("application", {}).get(
                "description", "Application created by deployment script"
            ),
        )
    else:
        logger.info(f"Using existing application: {app_name}")
        # Update application description if provided
        description = config.get("application", {}).get("description")
        if description:
            logger.info(f"Updating application description")
            eb_client.update_application(
                ApplicationName=app_name,
                Description=description
            )

    # Create and upload application version
    version = f"v{datetime.now():%Y%m%d_%H%M%S}"
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

    logger.info(f"Deployment completed successfully: {app_name} {version}")
