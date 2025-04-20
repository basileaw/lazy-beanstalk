# scrap.py

"""Clean up Elastic Beanstalk environment and associated resources."""

import shutil
from typing import Dict, Optional
from botocore.exceptions import ClientError

from . import support
from .support import DeploymentError
from .setup import ConfigurationManager, ClientManager, logger
from .secure import get_domain_from_certificate  # Import the function we created


def cleanup_local_config() -> None:
    """Remove local EB CLI configuration."""
    config_dir = ConfigurationManager.get_project_root() / ".elasticbeanstalk"
    if config_dir.exists():
        logger.info("Removing .elasticbeanstalk configuration directory")
        shutil.rmtree(config_dir)
        logger.info("Removed .elasticbeanstalk configuration directory")


@support.aws_handler
def cleanup_oidc(env_name: str) -> None:
    """Clean up OIDC authentication rules from ALB listener."""
    eb_client = ClientManager.get_client("elasticbeanstalk")
    elbv2_client = ClientManager.get_client("elbv2")

    # Find load balancer first
    logger.info("Checking for OIDC authentication rules")
    lb_arn = support.find_environment_load_balancer(env_name)
    if not lb_arn:
        logger.info("load balancer not found")
        return

    # Find HTTPS listener
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)["Listeners"]
        https_listener = next((l for l in listeners if l["Port"] == 443), None)

        if not https_listener:
            logger.info("no HTTPS listener")
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
            logger.info("no rules found")
            logger.info("No OIDC authentication rules found")
            return

        logger.info(f"Found {len(oidc_rules)} rules")

        # Delete OIDC rules
        logger.info("Removing OIDC authentication rules")
        for rule in oidc_rules:
            logger.info(f"Removing rule: {rule['RuleArn']}")
            elbv2_client.delete_rule(RuleArn=rule["RuleArn"])

        # Try to restore default action to forward traffic
        logger.info("Checking target groups for default action restoration")
        try:
            target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn)[
                "TargetGroups"
            ]
            if target_groups:
                target_group_arn = target_groups[0]["TargetGroupArn"]
                try:
                    # Verify listener still exists before modifying it
                    elbv2_client.describe_listeners(
                        ListenerArns=[https_listener["ListenerArn"]]
                    )
                    elbv2_client.modify_listener(
                        ListenerArn=https_listener["ListenerArn"],
                        DefaultActions=[
                            {"Type": "forward", "TargetGroupArn": target_group_arn}
                        ],
                    )
                    logger.info("restored")
                    logger.info("OIDC authentication rules removed successfully")
                except ClientError as e:
                    if e.response["Error"]["Code"] == "ListenerNotFound":
                        logger.info("listener removed")
                        logger.info("Listener was removed during cleanup")
                    else:
                        raise
            else:
                # Handle case with no target groups more gracefully
                logger.info("no target groups")
                logger.info(
                    "OIDC rules removed, but no target groups found for default action"
                )
        except ClientError as e:
            if e.response["Error"]["Code"] in [
                "LoadBalancerNotFound",
                "TargetGroupNotFound",
            ]:
                logger.info("resources changed")
                logger.info(
                    f"Resources changed during cleanup: {e.response['Error']['Code']}"
                )
            else:
                raise

    except ClientError as e:
        if e.response["Error"]["Code"] not in [
            "LoadBalancerNotFound",
            "ListenerNotFound",
        ]:
            logger.info("error")
            raise
        logger.info("resource not found")


@support.aws_handler
def cleanup_https(env_name: str, project_name: str) -> None:
    """Clean up HTTPS listener and DNS record if they exist."""
    eb_client = ClientManager.get_client("elasticbeanstalk")
    elbv2_client = ClientManager.get_client("elbv2")
    r53_client = ClientManager.get_client("route53")

    # Load configuration directly from ConfigurationManager
    # This is the fix for the error
    config = ConfigurationManager.load_config()
    https_config = config.get("https", {})

    # Find load balancer first
    logger.info("Checking HTTPS configuration")
    lb_arn = support.find_environment_load_balancer(env_name)
    if not lb_arn:
        logger.info("load balancer not found")
        return

    # Check if HTTPS is enabled
    is_https_enabled, cert_arn = support.get_https_status(lb_arn, project_name)
    if not is_https_enabled:
        logger.info("not enabled")
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
        else:
            logger.info("not found")
    except ClientError as e:
        if e.response["Error"]["Code"] not in [
            "LoadBalancerNotFound",
            "ListenerNotFound",
        ]:
            logger.info("error")
            raise
        logger.info("resource not found")

    # Clean up DNS record
    try:
        if cert_arn:  # Only proceed if we have a certificate ARN
            # Get the domain from the certificate using our new function
            logger.info("Cleaning up DNS record")
            acm_client = ClientManager.get_client("acm")
            cert = acm_client.describe_certificate(CertificateArn=cert_arn)[
                "Certificate"
            ]
            cert_domain = cert["DomainName"]

            # Use the same domain determination function as in secure.py
            domain = get_domain_from_certificate(cert_domain, config)
            logger.info(f"Looking for DNS record for domain: {domain}")

            # Get the load balancer DNS name
            lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])[
                "LoadBalancers"
            ][0]
            lb_dns = lb["DNSName"]

            zones = r53_client.list_hosted_zones()["HostedZones"]
            zone = next(
                (z for z in zones if domain.endswith(z["Name"].rstrip("."))), None
            )

            if zone:
                # Determine record type - assume A for root domains, CNAME otherwise
                is_root_domain = domain.count(".") == 1 and all(
                    part.isalpha() for part in domain.split(".")
                )
                record_type = "A" if is_root_domain else "CNAME"

                # Get record set
                records = r53_client.list_resource_record_sets(
                    HostedZoneId=zone["Id"],
                    StartRecordName=domain,
                    StartRecordType=record_type,
                    MaxItems="1",
                )["ResourceRecordSets"]

                record = next((r for r in records if r["Name"] == f"{domain}."), None)

                # For CNAME records, we check if it points to our load balancer
                if (
                    record
                    and record.get("Type") == "CNAME"
                    and record.get("ResourceRecords")
                    and record["ResourceRecords"][0]["Value"] == lb_dns
                ):
                    logger.info(f"Removing CNAME record for {domain}")
                    r53_client.change_resource_record_sets(
                        HostedZoneId=zone["Id"],
                        ChangeBatch={
                            "Changes": [
                                {"Action": "DELETE", "ResourceRecordSet": record}
                            ]
                        },
                    )
                # For A records with Alias, we check if it points to our load balancer
                elif (
                    record
                    and record.get("Type") == "A"
                    and record.get("AliasTarget")
                    and record["AliasTarget"].get("DNSName") == lb_dns
                ):
                    logger.info(f"Removing A record for {domain}")
                    r53_client.change_resource_record_sets(
                        HostedZoneId=zone["Id"],
                        ChangeBatch={
                            "Changes": [
                                {"Action": "DELETE", "ResourceRecordSet": record}
                            ]
                        },
                    )
                else:
                    logger.info("no matching record")
            else:
                logger.info("no matching hosted zone")
    except ClientError as e:
        if e.response["Error"]["Code"] not in [
            "LoadBalancerNotFound",
            "NoSuchHostedZone",
        ]:
            logger.info("error")
            raise
        logger.info("resource not found")


@support.aws_handler
def cleanup_instance_profile(config: Dict) -> None:
    """Clean up instance profile and role."""
    iam_client = ClientManager.get_client("iam")
    profile_name = config["iam"]["instance_profile_name"]
    role_name = config["iam"]["instance_role_name"]

    try:
        logger.info(f"Cleaning up instance profile {profile_name}")

        # Remove role from profile
        iam_client.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
        logger.info(f"Removed role from instance profile: {role_name}")

        # Delete profile
        iam_client.delete_instance_profile(InstanceProfileName=profile_name)
        logger.info(f"Deleted instance profile: {profile_name}")
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            logger.info("error")
            raise
        logger.info("not found")

    # Clean up the role
    support.manage_iam_role(
        role_name, config["iam"]["instance_role_policies"], action="cleanup"
    )


@support.aws_handler
def cleanup_s3_bucket(config: Dict) -> None:
    """Clean up the application version S3 bucket."""
    s3_client = ClientManager.get_client("s3")
    bucket = f"elasticbeanstalk-{config['aws']['region']}-{config['application']['name'].lower()}"

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
                # Remove progress indicator step

        # Delete bucket
        s3_client.delete_bucket(Bucket=bucket)
        logger.info(f"Removed {object_count} objects")
        logger.info(f"Deleted S3 bucket: {bucket}")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ["NoSuchBucket", "NoSuchKey"]:
            logger.info("error")
            raise
        logger.info("not found")


def cleanup_application(config: Dict) -> None:
    """Clean up all Elastic Beanstalk resources."""
    project_name = ConfigurationManager.get_project_name()
    env_name = config["application"]["environment"]

    logger.info("Starting cleanup process")

    # Clean up OIDC rules first (before we remove the HTTPS listener)
    cleanup_oidc(env_name)

    # Clean up HTTPS resources next
    cleanup_https(env_name, project_name)

    # Terminate environment if it exists
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
            logger.info("not found")
    except ClientError:
        logger.info("error checking")

    # Check if there are any other environments before cleaning up shared resources
    logger.info("Checking for other active environments")
    no_other_envs = not support.check_env_exists()

    if no_other_envs:
        logger.info("No active environments found, cleaning up shared resources")

        # Clean up IAM resources
        cleanup_instance_profile(config)
        support.manage_iam_role(
            config["iam"]["service_role_name"],
            config["iam"]["service_role_policies"],
            action="cleanup",
        )

        # Clean up S3 bucket
        cleanup_s3_bucket(config)

        # Delete application
        logger.info(f"Deleting application {config['application']['name']}")
        try:
            eb_client = ClientManager.get_client("elasticbeanstalk")
            eb_client.delete_application(
                ApplicationName=config["application"]["name"], TerminateEnvByForce=True
            )
            logger.info(f"Deleted application: {config['application']['name']}")
        except ClientError:
            logger.info("error or not found")
    else:
        logger.info("Other environments still active. Skipping resource cleanup.")

    # Remove local configuration
    cleanup_local_config()

    logger.info("Cleanup complete!")
