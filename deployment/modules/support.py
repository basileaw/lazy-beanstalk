# support.py

"""Common utilities for Elastic Beanstalk deployment operations."""

import json
import time
from functools import wraps
from datetime import datetime
from botocore.exceptions import ClientError
from typing import Dict, Set, Optional, List, Callable, Tuple, Any

COMMAND_START_TIME = datetime.utcnow()

from .setup import (
    ConfigurationManager,
    ClientManager,
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
    from datetime import timezone  # Import here for clarity

    eb_client = ClientManager.get_client("elasticbeanstalk")

    # If no start time is provided, use the current time with timezone info
    if after is None:
        after = datetime.now(timezone.utc)
    # Make sure 'after' has timezone info
    elif after.tzinfo is None:
        after = after.replace(tzinfo=timezone.utc)

    kwargs = {"EnvironmentName": env_name, "MaxRecords": 10}
    if after:
        kwargs["StartTime"] = after

    events = eb_client.describe_events(**kwargs).get("Events", [])
    latest_time = after

    for event in reversed(events):
        # Create a unique key for each event to avoid duplicates
        key = f"{event['EventDate'].isoformat()}-{event['Message']}"
        if key not in seen:
            # Use logger instead of print for consistent formatting
            logger.info(f"{event['Message']}")
            seen.add(key)

            # Event dates from AWS API are timezone-aware, so we need to make sure
            # our comparison variable is also timezone-aware
            if not latest_time or event["EventDate"] > latest_time:
                latest_time = event["EventDate"]

    return latest_time


def wait_for_env_status(env_name: str, target: str) -> None:
    """Wait for environment to reach target status."""
    logger.info(f"Waiting for environment to be {target}")
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
                    logger.info("environment terminated")
                    break
                raise DeploymentError(f"Environment {env_name} not found")

            status = envs[0]["Status"]
            last_time = print_events(env_name, last_time, seen)

            if status == target:
                logger.info(f"reached {target} state")
                break
            if status == "Failed":
                raise DeploymentError(f"Environment failed to reach {target} status")

        except ClientError as e:
            if (
                target == "Terminated"
                and e.response["Error"]["Code"] == "ResourceNotFoundException"
            ):
                logger.info("environment terminated")
                break
            logger.info("error")
            raise

        time.sleep(5)

    return status


def check_env_exists() -> bool:
    """Check if any environments exist."""
    eb_client = ClientManager.get_client("elasticbeanstalk")
    return bool(eb_client.describe_environments(IncludeDeleted=False)["Environments"])


def get_env_settings(config: Dict) -> List[Dict[str, str]]:
    """Get environment settings from config."""
    settings = [
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

    # Add spot instance configuration - always set EnableSpot for 1:1 sync
    spot_enabled = (
        "spot_options" in config["instance"] 
        and config["instance"]["spot_options"].get("enabled", False)
    )
    
    settings.append(
        {
            "Namespace": "aws:ec2:instances",
            "OptionName": "EnableSpot",
            "Value": "true" if spot_enabled else "false",
        }
    )

    if spot_enabled:
        # Configure spot instance settings when enabled
        settings.append(
            {
                "Namespace": "aws:ec2:instances",
                "OptionName": "SpotFleetOnDemandBase",
                "Value": "0",
            }
        )

        settings.append(
            {
                "Namespace": "aws:ec2:instances",
                "OptionName": "SpotFleetOnDemandAboveBasePercentage",
                "Value": "0",
            }
        )

        # If a max price is specified, add it
        if "max_price" in config["instance"]["spot_options"]:
            settings.append(
                {
                    "Namespace": "aws:ec2:instances",
                    "OptionName": "SpotMaxPrice",
                    "Value": str(config["instance"]["spot_options"]["max_price"]),
                }
            )
    else:
        # Reset spot fleet settings to defaults when spot is disabled
        settings.append(
            {
                "Namespace": "aws:ec2:instances",
                "OptionName": "SpotFleetOnDemandBase",
                "Value": "0",  # Default: start with on-demand instances
            }
        )

        settings.append(
            {
                "Namespace": "aws:ec2:instances",
                "OptionName": "SpotFleetOnDemandAboveBasePercentage",
                "Value": "100",  # Default: use 100% on-demand above base
            }
        )

    return settings


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
                    ConfigurationManager.load_policy(policies["trust_policy"])
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

        # Track which policies we've processed locally
        processed_policy_arns = set()

        for policy_file in custom_policy_files:
            name = f"{role_name}-{policy_file.replace('.json', '')}"
            policy_arn = f"arn:aws:iam::{account}:policy/{name}"

            # Load the policy document
            logger.info(f"Loading policy from {policy_file}")
            try:
                policy_doc = ConfigurationManager.load_policy(policy_file)
            except Exception as e:
                logger.error(f"Failed to load policy {policy_file}: {e}")
                continue

            # Check if policy exists and needs updating
            policy_exists = False
            policy_needs_update = False
            try:
                policy_response = iam_client.get_policy(PolicyArn=policy_arn)
                policy_exists = True
                logger.info(f"Policy {name} already exists with ARN: {policy_arn}")
                
                # Get current policy document to compare with local version
                default_version_id = policy_response['Policy']['DefaultVersionId']
                policy_version = iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=default_version_id
                )
                current_policy_doc = json.loads(
                    policy_version['PolicyVersion']['Document']
                )
                
                # Compare normalized policy documents
                if json.dumps(policy_doc, sort_keys=True) != json.dumps(current_policy_doc, sort_keys=True):
                    policy_needs_update = True
                    logger.info(f"Policy {name} content has changed, will update")
                else:
                    logger.info(f"Policy {name} content is up to date")
                    
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    logger.error(f"Error checking policy existence: {e}")
                    raise
                logger.info(f"Policy {name} does not exist, will create it")

            # Create policy if it doesn't exist or update if needed
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
            
            # Update policy if it exists but content has changed
            elif policy_needs_update:
                try:
                    logger.info(f"Creating new version for policy {name}")
                    
                    # Create new policy version
                    iam_client.create_policy_version(
                        PolicyArn=policy_arn,
                        PolicyDocument=json.dumps(policy_doc),
                        SetAsDefault=True
                    )
                    logger.info(f"Updated policy {name} with new version")
                    
                    # Clean up old versions (AWS allows max 5 versions)
                    try:
                        versions_response = iam_client.list_policy_versions(PolicyArn=policy_arn)
                        versions = versions_response['Versions']
                        
                        # Sort by creation date and keep only non-default versions
                        non_default_versions = [v for v in versions if not v['IsDefaultVersion']]
                        non_default_versions.sort(key=lambda x: x['CreateDate'])
                        
                        # Delete oldest versions if we have more than 4 non-default
                        # (keeping 1 default + 4 non-default = 5 total)
                        while len(non_default_versions) > 4:
                            oldest = non_default_versions.pop(0)
                            logger.info(f"Deleting old policy version {oldest['VersionId']} for {name}")
                            iam_client.delete_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=oldest['VersionId']
                            )
                    except Exception as e:
                        logger.warning(f"Error cleaning up old policy versions: {e}")
                        
                except ClientError as e:
                    logger.error(f"Failed to update policy {name}: {e}")
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
                    
                # Add to processed set
                processed_policy_arns.add(policy_arn)
                
            except ClientError as e:
                logger.error(f"Failed to attach policy {name} to role {role_name}: {e}")
                raise

        # Clean up policies that are no longer in local directory
        logger.info("Checking for policies to remove that are no longer in local directory")
        try:
            attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            
            for policy in attached_policies['AttachedPolicies']:
                policy_arn = policy['PolicyArn']
                policy_name = policy['PolicyName']
                
                # Check if this is a custom policy (has our role name prefix) and wasn't processed
                if (policy_name.startswith(f"{role_name}-") and 
                    policy_arn.startswith(f"arn:aws:iam::{account}:policy/") and
                    policy_arn not in processed_policy_arns):
                    
                    logger.info(f"Policy {policy_name} no longer exists locally, detaching from role")
                    
                    # Detach the policy
                    iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                    logger.info(f"Detached policy {policy_name} from role {role_name}")
                    
                    # Optionally delete the policy if it's not attached to any other roles
                    try:
                        # Check if policy has any other attachments
                        entities = iam_client.list_entities_for_policy(PolicyArn=policy_arn)
                        
                        if (not entities['PolicyGroups'] and 
                            not entities['PolicyUsers'] and 
                            len(entities['PolicyRoles']) == 0):  # Was only attached to this role
                            
                            logger.info(f"Deleting orphaned policy {policy_name}")
                            iam_client.delete_policy(PolicyArn=policy_arn)
                            logger.info(f"Deleted policy {policy_name}")
                    except Exception as e:
                        logger.warning(f"Error checking/deleting orphaned policy {policy_name}: {e}")
                        
        except Exception as e:
            logger.warning(f"Error cleaning up removed policies: {e}")

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
def configure_http_to_https_redirection(lb_arn: str) -> None:
    """
    Configure HTTP to HTTPS redirection on the load balancer.
    Creates or modifies the HTTP listener (port 80) to redirect all traffic to HTTPS (port 443).
    """
    elbv2_client = ClientManager.get_client("elbv2")

    logger.info("Configuring HTTP to HTTPS redirection")

    # Check if HTTP listener exists
    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
    http_listener = next((l for l in listeners if l["Port"] == 80), None)

    # Configure redirect action
    redirect_action = {
        "Type": "redirect",
        "RedirectConfig": {
            "Protocol": "HTTPS",
            "Port": "443",
            "StatusCode": "HTTP_301",  # Permanent redirect
            "Host": "#{host}",
            "Path": "/#{path}",
            "Query": "#{query}",
        },
    }

    if http_listener:
        logger.info("Modifying existing HTTP listener to redirect to HTTPS")
        elbv2_client.modify_listener(
            ListenerArn=http_listener["ListenerArn"], DefaultActions=[redirect_action]
        )
    else:
        logger.info("Creating new HTTP listener with redirection to HTTPS")
        elbv2_client.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol="HTTP",
            Port=80,
            DefaultActions=[redirect_action],
        )

    logger.info("HTTP to HTTPS redirection configured successfully")


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

    # Configure HTTP to HTTPS redirection
    configure_http_to_https_redirection(lb_arn)


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
