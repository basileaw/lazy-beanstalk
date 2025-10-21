# scrap.py

"""Clean up Elastic Beanstalk environment and associated resources."""

import shutil
from pathlib import Path
from typing import Dict, Optional
from botocore.exceptions import ClientError

from . import support
from .config import (
    ClientManager,
    StateManager,
    logger,
    DeploymentError,
    get_custom_policies_dir,
    MANAGED_POLICIES,
)
from .secure import get_domains_from_certificate_config


def cleanup_local_config(working_dir: Optional[Path] = None) -> None:
    """Remove local EB CLI configuration."""
    if working_dir is None:
        working_dir = Path.cwd()

    config_dir = working_dir / ".elasticbeanstalk"
    if config_dir.exists():
        logger.info("Removing .elasticbeanstalk configuration directory")
        shutil.rmtree(config_dir)
        logger.info("Removed .elasticbeanstalk configuration directory")


@support.aws_handler
def cleanup_oidc(env_name: str) -> None:
    """Clean up OIDC authentication rules from ALB listener."""
    elbv2_client = ClientManager.get_client("elbv2")

    logger.info("Checking for OIDC authentication rules")
    lb_arn = support.find_environment_load_balancer(env_name)
    if not lb_arn:
        logger.info("Load balancer not found")
        return

    # Find HTTPS listener
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
        https_listener = next((l for l in listeners if l["Port"] == 443), None)

        if not https_listener:
            logger.info("No HTTPS listener found, skipping OIDC cleanup")
            return

        # Check for OIDC rules
        rules = elbv2_client.describe_rules(ListenerArn=https_listener["ListenerArn"])[
            "Rules"
        ]
        oidc_rules = [
            r
            for r in rules
            if not r.get("IsDefault", False)
            and any(a.get("Type") == "authenticate-oidc" for a in r.get("Actions", []))
        ]

        if not oidc_rules:
            logger.info("No OIDC authentication rules found")
            return

        logger.info(f"Found {len(oidc_rules)} OIDC rules")

        # Delete OIDC rules
        logger.info("Removing OIDC authentication rules")
        for rule in oidc_rules:
            elbv2_client.delete_rule(RuleArn=rule["RuleArn"])

        # Restore default action to forward traffic
        logger.info("Restoring default forward action")
        try:
            target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn)[
                "TargetGroups"
            ]
            if target_groups:
                target_group_arn = target_groups[0]["TargetGroupArn"]
                elbv2_client.modify_listener(
                    ListenerArn=https_listener["ListenerArn"],
                    DefaultActions=[
                        {"Type": "forward", "TargetGroupArn": target_group_arn}
                    ],
                )
                logger.info("OIDC authentication rules removed successfully")
        except ClientError as e:
            if e.response["Error"]["Code"] == "ListenerNotFound":
                logger.info("Listener was removed during cleanup")
            else:
                raise

    except ClientError as e:
        if e.response["Error"]["Code"] not in [
            "LoadBalancerNotFound",
            "ListenerNotFound",
        ]:
            raise


@support.aws_handler
def cleanup_https(env_name: str, app_name: str) -> None:
    """Clean up HTTPS listener and DNS records if they exist."""
    elbv2_client = ClientManager.get_client("elbv2")
    r53_client = ClientManager.get_client("route53")

    logger.info("Checking HTTPS configuration")
    lb_arn = support.find_environment_load_balancer(env_name)
    if not lb_arn:
        logger.info("Load balancer not found")
        return

    # Check if HTTPS is enabled
    is_https_enabled, cert_arn = support.get_https_status(lb_arn, app_name)
    if not is_https_enabled:
        logger.info("HTTPS not enabled")
        return

    logger.info("Found HTTPS configuration, cleaning up")

    # Clean up HTTPS listener
    try:
        logger.info("Removing HTTPS listener")
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
        https_listener = next((l for l in listeners if l["Port"] == 443), None)
        if https_listener:
            elbv2_client.delete_listener(ListenerArn=https_listener["ListenerArn"])
            logger.info("Removed HTTPS listener")

        # Reset HTTP listener to forward
        http_listener = next((l for l in listeners if l["Port"] == 80), None)
        if http_listener:
            default_actions = http_listener.get("DefaultActions", [])
            is_https_redirect = any(
                action.get("Type") == "redirect"
                and action.get("RedirectConfig", {}).get("Protocol") == "HTTPS"
                for action in default_actions
            )

            if is_https_redirect:
                target_groups = elbv2_client.describe_target_groups(
                    LoadBalancerArn=lb_arn
                )["TargetGroups"]
                if target_groups:
                    logger.info("Resetting HTTP listener to forward traffic")
                    target_group_arn = target_groups[0]["TargetGroupArn"]
                    elbv2_client.modify_listener(
                        ListenerArn=http_listener["ListenerArn"],
                        DefaultActions=[
                            {"Type": "forward", "TargetGroupArn": target_group_arn}
                        ],
                    )
                    logger.info("Reset HTTP listener to default forward action")

    except ClientError as e:
        if e.response["Error"]["Code"] not in [
            "LoadBalancerNotFound",
            "ListenerNotFound",
        ]:
            raise

    # Clean up DNS records
    try:
        if cert_arn:
            logger.info("Cleaning up DNS records")
            acm_client = ClientManager.get_client("acm")
            cert = acm_client.describe_certificate(CertificateArn=cert_arn)[
                "Certificate"
            ]
            cert_domain = cert["DomainName"]

            # Get domains (use sub mode for cleanup)
            domains = get_domains_from_certificate_config(cert_domain, "sub", app_name, None, False)
            if not domains:
                return

            logger.info(f"Looking for DNS records for domains: {', '.join(domains)}")

            # Get load balancer DNS
            lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])[
                "LoadBalancers"
            ][0]
            lb_dns = lb["DNSName"]

            # Find hosted zone
            root_domain = cert_domain.replace("*.", "")
            zones = r53_client.list_hosted_zones()["HostedZones"]
            zone = next(
                (z for z in zones if root_domain.endswith(z["Name"].rstrip("."))), None
            )

            if zone:
                logger.info(f"Found hosted zone: {zone['Name']}")

                # Delete DNS records
                for domain in domains:
                    for record_type in ["A", "CNAME"]:
                        try:
                            records = r53_client.list_resource_record_sets(
                                HostedZoneId=zone["Id"],
                                StartRecordName=domain,
                                StartRecordType=record_type,
                                MaxItems="1",
                            )["ResourceRecordSets"]

                            record = next((r for r in records if r["Name"] == f"{domain}."), None)
                            if record:
                                logger.info(f"Removing {record_type} record for {domain}")
                                r53_client.change_resource_record_sets(
                                    HostedZoneId=zone["Id"],
                                    ChangeBatch={
                                        "Changes": [
                                            {"Action": "DELETE", "ResourceRecordSet": record}
                                        ]
                                    },
                                )
                        except ClientError:
                            continue

                logger.info("DNS records cleaned up")

    except ClientError as e:
        if e.response["Error"]["Code"] not in [
            "LoadBalancerNotFound",
            "NoSuchHostedZone",
        ]:
            raise


@support.aws_handler
def cleanup_instance_profile(
    profile_name: str,
    role_name: str,
    managed_policy_arns: list,
    custom_policies_dir: Optional[Path],
) -> None:
    """Clean up instance profile and role."""
    iam_client = ClientManager.get_client("iam")

    try:
        logger.info(f"Cleaning up instance profile {profile_name}")
        iam_client.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
        iam_client.delete_instance_profile(InstanceProfileName=profile_name)
        logger.info(f"Deleted instance profile: {profile_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise

    # Clean up the role
    support.manage_iam_role(
        role_name=role_name,
        trust_policy_name="ec2",
        managed_policy_arns=managed_policy_arns,
        custom_policies_dir=custom_policies_dir,
        action="cleanup",
    )


@support.aws_handler
def cleanup_s3_bucket(region: str, app_name: str) -> None:
    """Clean up the application version S3 bucket."""
    s3_client = ClientManager.get_client("s3")
    bucket = f"elasticbeanstalk-{region}-{app_name.lower()}"

    logger.info(f"Cleaning up S3 bucket {bucket}")

    try:
        # Delete all objects
        object_count = 0
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            if "Contents" in page:
                objects = [{"Key": obj["Key"]} for obj in page["Contents"]]
                s3_client.delete_objects(Bucket=bucket, Delete={"Objects": objects})
                object_count += len(objects)

        # Delete bucket
        s3_client.delete_bucket(Bucket=bucket)
        logger.info(f"Removed {object_count} objects and deleted S3 bucket")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ["NoSuchBucket", "NoSuchKey"]:
            raise


def scrap(
    app_name: Optional[str] = None,
    force: bool = False,
) -> Dict[str, str]:
    """
    Remove all AWS resources created by lazy-beanstalk.

    Args:
        app_name: Application name (default: from state file)
        force: Skip confirmation prompts (default: False)

    Returns:
        Dict with cleanup status
    """
    # Load full EB config (includes both EB CLI sections and lazy_beanstalk state)
    eb_config = StateManager.load_eb_config()
    if not eb_config:
        raise DeploymentError(
            "No deployment configuration found. Nothing to clean up."
        )

    # Get app_name from EB CLI global section or lazy_beanstalk section
    if not app_name:
        global_config = eb_config.get("global", {})
        app_name = global_config.get("application_name")
        if not app_name:
            # Fallback to lazy_beanstalk section if somehow it's there
            state = eb_config.get("lazy_beanstalk", {})
            app_name = state.get("app_name")

    # Get env_name from branch-defaults or lazy_beanstalk section
    branch_defaults = eb_config.get("branch-defaults", {})
    main_branch = branch_defaults.get("main", {})
    env_name = main_branch.get("environment")
    if not env_name:
        # Fallback to lazy_beanstalk section
        state = eb_config.get("lazy_beanstalk", {})
        env_name = state.get("environment_name")

    # Get region from global or lazy_beanstalk section
    global_config = eb_config.get("global", {})
    region = global_config.get("default_region")
    if not region:
        state = eb_config.get("lazy_beanstalk", {})
        region = state.get("region")

    if not app_name or not env_name:
        raise DeploymentError("Invalid configuration: missing app_name or environment_name")

    # Get state for policies_dir
    state = eb_config.get("lazy_beanstalk", {})

    # Initialize AWS clients
    ClientManager.initialize(region)

    # Confirmation prompt
    if not force:
        logger.warning(f"\nYou are about to delete the following resources:")
        logger.warning(f"  - Application: {app_name}")
        logger.warning(f"  - Environment: {env_name}")
        logger.warning(f"  - IAM roles and policies")
        logger.warning(f"  - S3 bucket")
        logger.warning(f"  - HTTPS and OIDC configurations")
        logger.warning(f"\nThis action cannot be undone!")

        response = input("\nAre you sure you want to continue? (yes/no): ")
        if response.lower() != "yes":
            logger.info("Cleanup cancelled")
            return {"status": "cancelled"}

    logger.info("Starting cleanup process")

    # Clean up OIDC rules first
    cleanup_oidc(env_name)

    # Clean up HTTPS resources
    cleanup_https(env_name, app_name)

    # Terminate environment
    try:
        eb_client = ClientManager.get_client("elasticbeanstalk")
        logger.info(f"Checking if environment {env_name} exists")

        env_exists = bool(
            eb_client.describe_environments(
                EnvironmentNames=[env_name], IncludeDeleted=False
            )["Environments"]
        )

        if env_exists:
            logger.info(f"Terminating environment: {env_name}")
            eb_client.terminate_environment(EnvironmentName=env_name)
            support.wait_for_env_status(env_name, "Terminated")
        else:
            logger.info("Environment not found")
    except ClientError:
        logger.info("Error checking environment")

    # Check if there are other environments
    logger.info("Checking for other active environments")
    no_other_envs = not support.check_env_exists()

    if no_other_envs:
        logger.info("No active environments found, cleaning up shared resources")

        # Get IAM role names
        service_role_name = f"{app_name}-eb-role"
        instance_role_name = f"{app_name}-ec2-role"
        instance_profile_name = f"{app_name}-ec2-profile"

        # Clean up IAM resources
        custom_policies_dir = get_custom_policies_dir(state.get("policies_dir"))

        cleanup_instance_profile(
            instance_profile_name,
            instance_role_name,
            MANAGED_POLICIES["instance_role"],
            custom_policies_dir,
        )

        support.manage_iam_role(
            role_name=service_role_name,
            trust_policy_name="eb",
            managed_policy_arns=MANAGED_POLICIES["service_role"],
            custom_policies_dir=None,
            action="cleanup",
        )

        # Clean up S3 bucket
        cleanup_s3_bucket(region, app_name)

        # Delete application
        logger.info(f"Deleting application {app_name}")
        try:
            eb_client.delete_application(
                ApplicationName=app_name, TerminateEnvByForce=True
            )
            logger.info(f"Deleted application: {app_name}")
        except ClientError:
            logger.info("Error deleting application or not found")
    else:
        logger.info("Other environments still active. Skipping resource cleanup.")

    # Remove local configuration
    cleanup_local_config()

    # Delete state file
    StateManager.delete_state()
    logger.info("Deleted state file")

    logger.info("Cleanup complete!")

    return {
        "status": "completed",
        "app_name": app_name,
        "environment_name": env_name,
    }
