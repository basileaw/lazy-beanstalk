# modules/support.py

"""Common utilities for Elastic Beanstalk deployment operations."""

import json
import time
from functools import wraps
from datetime import datetime
from botocore.exceptions import ClientError
from typing import Dict, Set, Optional, List, Callable, Tuple, Any

from .setup import (
    ConfigurationManager,
    ClientManager,
    ProgressIndicator,
    load_policy,
    logger,
)


class DeploymentError(Exception):
    """Base exception for deployment operations."""

    pass


def aws_handler(func: Callable) -> Callable:
    """Decorator to handle AWS API errors."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ["NoSuchEntity", "NoSuchBucket", "NoSuchKey"]:
                error_message = f"AWS {code}: {e.response['Error']['Message']}"
                logger.error(error_message)
                raise DeploymentError(error_message)
            # For resource not found errors, return None if appropriate
            if code in ["NoSuchEntity", "NoSuchBucket", "NoSuchKey"]:
                logger.debug(f"Resource not found: {e.response['Error']['Message']}")
                return None

    return wrapper


def print_events(env_name: str, after: Optional[datetime], seen: Set[str]) -> datetime:
    """Print and track new environment events."""
    eb_client = ClientManager.get_client("elasticbeanstalk")

    kwargs = {"EnvironmentName": env_name, "MaxRecords": 10}
    if after:
        kwargs["StartTime"] = after

    events = eb_client.describe_events(**kwargs).get("Events", [])
    latest_time = after

    for event in reversed(events):
        # Create a unique key for each event to avoid duplicates
        key = f"{event['EventDate'].isoformat()}-{event['Message']}"
        if key not in seen:
            print(
                f"{event['EventDate']:%Y-%m-%d %H:%M:%S} [{event['Severity']}] {event['Message']}"
            )
            seen.add(key)
            if not latest_time or event["EventDate"] > latest_time:
                latest_time = event["EventDate"]

    return latest_time


def wait_for_env_status(env_name: str, target: str) -> None:
    """Wait for environment to reach target status."""
    ProgressIndicator.start(f"Waiting for environment to be {target}")
    eb_client = ClientManager.get_client("elasticbeanstalk")
    last_time, seen = None, set()
    status = None

    while True:
        try:
            envs = eb_client.describe_environments(
                EnvironmentNames=[env_name], IncludeDeleted=False
            )["Environments"]

            if not envs:
                if target == "Terminated":
                    ProgressIndicator.complete("environment terminated")
                    break
                raise DeploymentError(f"Environment {env_name} not found")

            status = envs[0]["Status"]
            last_time = print_events(env_name, last_time, seen)

            if status == target:
                ProgressIndicator.complete(f"reached {target} state")
                break
            if status == "Failed":
                raise DeploymentError(f"Environment failed to reach {target} status")

            # Show progress
            ProgressIndicator.step()

        except ClientError as e:
            if (
                target == "Terminated"
                and e.response["Error"]["Code"] == "ResourceNotFoundException"
            ):
                ProgressIndicator.complete("environment terminated")
                break
            ProgressIndicator.complete("error")
            raise

        time.sleep(5)

    return status


def check_env_exists() -> bool:
    """Check if any environments exist."""
    eb_client = ClientManager.get_client("elasticbeanstalk")
    return bool(eb_client.describe_environments(IncludeDeleted=False)["Environments"])


def get_env_settings(config: Dict) -> List[Dict[str, str]]:
    """Get environment settings from config."""
    return [
        {
            "Namespace": "aws:autoscaling:launchconfiguration",
            "OptionName": "IamInstanceProfile",
            "Value": config["iam"]["instance_profile_name"],
        },
        {
            "Namespace": "aws:elasticbeanstalk:environment",
            "OptionName": "ServiceRole",
            "Value": config["iam"]["service_role_name"],
        },
        {
            "Namespace": "aws:autoscaling:launchconfiguration",
            "OptionName": "InstanceType",
            "Value": config["instance"]["type"],
        },
        {
            "Namespace": "aws:autoscaling:asg",
            "OptionName": "MinSize",
            "Value": str(config["instance"]["autoscaling"]["min_instances"]),
        },
        {
            "Namespace": "aws:autoscaling:asg",
            "OptionName": "MaxSize",
            "Value": str(config["instance"]["autoscaling"]["max_instances"]),
        },
    ]


@aws_handler
def manage_iam_role(role_name: str, policies: Dict, action: str = "create") -> None:
    """Create or clean up IAM role and policies."""
    iam_client = ClientManager.get_client("iam")

    if action == "create":
        try:
            logger.info(f"Checking if role {role_name} exists")
            iam_client.get_role(RoleName=role_name)
            logger.info(f"Role {role_name} already exists, skipping creation")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                raise

            logger.info(f"Creating role {role_name}")
            # Create role
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(
                    load_policy(policies["trust_policy"])
                ),
            )
            logger.info(f"Role {role_name} created successfully")

        # Attach managed policies
        for arn in policies.get("managed_policies", []):
            logger.info(f"Attaching policy {arn} to role {role_name}")
            try:
                iam_client.attach_role_policy(RoleName=role_name, PolicyArn=arn)
                logger.info(f"Policy {arn} attached to role {role_name}")
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    logger.error(f"Failed to attach policy {arn}: Policy not found")
                else:
                    raise

        # Handle custom policies
        sts_client = ClientManager.get_client("sts")
        account = sts_client.get_caller_identity()["Account"]

        # Get list of policy files - either from config or auto-discover
        custom_policy_files = []

        # Check if custom_policies is explicitly defined in config
        if "custom_policies" in policies:
            custom_policy_files = policies["custom_policies"]
            logger.info(
                f"Using {len(custom_policy_files)} explicitly configured custom policies"
            )
        else:
            # Auto-discover custom policies from the policies directory
            custom_policy_files = ConfigurationManager.get_custom_policies()
            if custom_policy_files:
                logger.info(
                    f"Auto-discovered {len(custom_policy_files)} custom policies from policies directory"
                )
            else:
                logger.info("No custom policies discovered in policies directory")

        for policy_file in custom_policy_files:
            name = f"{role_name}-{policy_file.replace('.json', '')}"
            policy_arn = f"arn:aws:iam::{account}:policy/{name}"

            # Load the policy document
            logger.info(f"Loading policy from {policy_file}")
            try:
                policy_doc = load_policy(policy_file)
            except Exception as e:
                logger.error(f"Failed to load policy {policy_file}: {e}")
                continue

            # Check if policy exists
            policy_exists = False
            try:
                iam_client.get_policy(PolicyArn=policy_arn)
                policy_exists = True
                logger.info(f"Policy {name} already exists with ARN: {policy_arn}")
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    logger.error(f"Error checking policy existence: {e}")
                    raise
                logger.info(f"Policy {name} does not exist, will create it")

            # Create policy if it doesn't exist
            if not policy_exists:
                try:
                    logger.info(f"Creating policy {name} from {policy_file}")
                    policy = iam_client.create_policy(
                        PolicyName=name, PolicyDocument=json.dumps(policy_doc)
                    )
                    policy_arn = policy["Policy"]["Arn"]
                    logger.info(f"Created policy {name} with ARN: {policy_arn}")
                except ClientError as e:
                    if e.response["Error"]["Code"] == "EntityAlreadyExists":
                        logger.info(f"Policy {name} already exists, fetching ARN")
                        # If the policy exists but we couldn't fetch it earlier,
                        # try to list and find it
                        try:
                            policies_response = iam_client.list_policies(Scope="Local")
                            matching_policy = next(
                                (
                                    p
                                    for p in policies_response["Policies"]
                                    if p["PolicyName"] == name
                                ),
                                None,
                            )
                            if matching_policy:
                                policy_arn = matching_policy["Arn"]
                                logger.info(
                                    f"Found existing policy {name} with ARN: {policy_arn}"
                                )
                        except Exception as list_err:
                            logger.error(f"Error listing policies: {list_err}")
                    else:
                        logger.error(f"Failed to create policy {name}: {e}")
                        raise

            # Attach policy to role
            try:
                # Check if policy is already attached to avoid redundant operations
                attached_policies = iam_client.list_attached_role_policies(
                    RoleName=role_name
                )
                is_attached = any(
                    p["PolicyArn"] == policy_arn
                    for p in attached_policies["AttachedPolicies"]
                )

                if not is_attached:
                    logger.info(f"Attaching policy {name} to role {role_name}")
                    iam_client.attach_role_policy(
                        RoleName=role_name, PolicyArn=policy_arn
                    )
                    logger.info(f"Attached policy {name} to role {role_name}")
                else:
                    logger.info(
                        f"Policy {name} is already attached to role {role_name}"
                    )
            except ClientError as e:
                logger.error(f"Failed to attach policy {name} to role {role_name}: {e}")
                raise

        logger.info(f"Waiting for role {role_name} to be fully created and available")
        iam_client.get_waiter("role_exists").wait(RoleName=role_name)
        logger.info(f"Role {role_name} is ready")

    elif action == "cleanup":
        logger.info(f"Cleaning up role {role_name}")
        # Detach and clean up policies
        sts_client = ClientManager.get_client("sts")
        account = sts_client.get_caller_identity()["Account"]

        for arn in policies.get("managed_policies", []):
            try:
                logger.info(f"Detaching policy {arn} from role {role_name}")
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=arn)
                logger.info(f"Detached policy {arn} from role {role_name}")
            except ClientError as e:
                logger.warning(
                    f"Error detaching policy {arn} from role {role_name}: {e}"
                )
                continue

        # Get custom policies to clean up - either from config or auto-discover
        custom_policy_files = []

        # Try config first
        if "custom_policies" in policies:
            custom_policy_files = policies["custom_policies"]

        # If no custom policies in config or empty list, auto-discover
        if not custom_policy_files:
            custom_policy_files = ConfigurationManager.get_custom_policies()

        for policy_file in custom_policy_files:
            try:
                name = f"{role_name}-{policy_file.replace('.json', '')}"
                policy_arn = f"arn:aws:iam::{account}:policy/{name}"
                logger.info(f"Detaching and deleting policy {name}")

                # Try to detach the policy
                try:
                    iam_client.detach_role_policy(
                        RoleName=role_name, PolicyArn=policy_arn
                    )
                    logger.info(f"Detached policy {name} from role {role_name}")
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchEntity":
                        logger.warning(f"Error detaching policy {name}: {e}")

                # Try to delete the policy
                try:
                    iam_client.delete_policy(PolicyArn=policy_arn)
                    logger.info(f"Deleted policy {name}")
                except ClientError as e:
                    if e.response["Error"]["Code"] != "NoSuchEntity":
                        logger.warning(f"Error deleting policy {name}: {e}")
            except Exception as e:
                logger.warning(f"Error cleaning up policy {policy_file}: {e}")
                continue

        try:
            logger.info(f"Deleting role {role_name}")
            iam_client.delete_role(RoleName=role_name)
            logger.info(f"Deleted role {role_name}")
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchEntity":
                logger.error(f"Error deleting role {role_name}: {e}")
                raise
            logger.info(f"Role {role_name} doesn't exist, skipping deletion")


# HTTPS Management Functions


def get_resource_prefix(project_name: str) -> str:
    """Generate consistent prefix for resource tags."""
    return f"{project_name}:https"


@aws_handler
def get_https_status(lb_arn: str, project_name: str) -> Tuple[bool, Optional[str]]:
    """
    Check if HTTPS is enabled and return status + certificate ARN.

    Args:
        lb_arn: Load balancer ARN
        project_name: Project name for tag prefix

    Returns:
        Tuple of (is_https_enabled, certificate_arn)
    """
    # Check load balancer tags
    elbv2_client = ClientManager.get_client("elbv2")
    tags = elbv2_client.describe_tags(ResourceArns=[lb_arn])["TagDescriptions"][0][
        "Tags"
    ]

    prefix = get_resource_prefix(project_name)
    is_enabled = any(
        t["Key"] == f"{prefix}:enabled" and t["Value"].lower() == "true" for t in tags
    )
    cert_arn = next(
        (t["Value"] for t in tags if t["Key"] == f"{prefix}:certificate-arn"), None
    )

    return is_enabled, cert_arn


@aws_handler
def find_environment_load_balancer(env_name: str) -> Optional[str]:
    """
    Find the ALB ARN for an environment.

    Args:
        env_name: Environment name

    Returns:
        Load balancer ARN if found, None otherwise
    """
    eb_client = ClientManager.get_client("elasticbeanstalk")
    elbv2_client = ClientManager.get_client("elbv2")

    env = eb_client.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=False
    )["Environments"][0]

    lbs = elbv2_client.describe_load_balancers()["LoadBalancers"]
    for lb in lbs:
        if lb["Type"].lower() == "application":
            tags = elbv2_client.describe_tags(ResourceArns=[lb["LoadBalancerArn"]])[
                "TagDescriptions"
            ][0]["Tags"]

            if any(
                t["Key"] == "elasticbeanstalk:environment-name"
                and t["Value"] == env_name
                for t in tags
            ):
                return lb["LoadBalancerArn"]

    return None


@aws_handler
def preserve_https_config(lb_arn: str, project_name: str) -> Optional[Dict[str, Any]]:
    """
    Capture existing HTTPS configuration for preservation.

    Args:
        lb_arn: Load balancer ARN
        project_name: Project name for tag prefix

    Returns:
        Dict containing HTTPS configuration if enabled, None otherwise
    """
    is_enabled, cert_arn = get_https_status(lb_arn, project_name)
    if not is_enabled:
        return None

    elbv2_client = ClientManager.get_client("elbv2")
    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    https_listener = next((l for l in listeners if l["Port"] == 443), None)

    if not https_listener:
        return None

    return {
        "certificate_arn": cert_arn,
        "ssl_policy": https_listener["SslPolicy"],
        "default_actions": https_listener["DefaultActions"],
    }


@aws_handler
def setup_https_listener(
    lb_arn: str,
    cert_arn: str,
    project_name: str,
    ssl_policy: str = "ELBSecurityPolicy-2016-08",
) -> None:
    """
    Create or update HTTPS listener with proper configuration.

    Args:
        lb_arn: Load balancer ARN
        cert_arn: Certificate ARN
        project_name: Project name for tag prefix
        ssl_policy: SSL policy name
    """
    elbv2_client = ClientManager.get_client("elbv2")

    # Get HTTP listener for default actions
    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    http_listener = next((l for l in listeners if l["Port"] == 80), None)
    if not http_listener:
        raise DeploymentError("No HTTP listener found")

    # Check if HTTPS listener exists
    https_listener = next((l for l in listeners if l["Port"] == 443), None)

    if https_listener:
        # Update existing listener
        elbv2_client.modify_listener(
            ListenerArn=https_listener["ListenerArn"],
            Certificates=[{"CertificateArn": cert_arn}],
            SslPolicy=ssl_policy,
        )
    else:
        # Create new listener
        elbv2_client.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol="HTTPS",
            Port=443,
            Certificates=[{"CertificateArn": cert_arn}],
            SslPolicy=ssl_policy,
            DefaultActions=http_listener["DefaultActions"],
        )

    # Update tags
    prefix = get_resource_prefix(project_name)
    elbv2_client.add_tags(
        ResourceArns=[lb_arn],
        Tags=[
            {"Key": f"{prefix}:enabled", "Value": "true"},
            {"Key": f"{prefix}:certificate-arn", "Value": cert_arn},
        ],
    )


@aws_handler
def restore_https_config(
    lb_arn: str, config: Dict[str, Any], project_name: str
) -> None:
    """
    Restore HTTPS configuration after environment update.

    Args:
        lb_arn: Load balancer ARN
        config: HTTPS configuration dict from preserve_https_config
        project_name: Project name for tag prefix
    """
    if not config:
        return

    setup_https_listener(
        lb_arn, config["certificate_arn"], project_name, config["ssl_policy"]
    )
