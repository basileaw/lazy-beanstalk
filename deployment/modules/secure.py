# secure.py

"""
Secure your Elastic Beanstalk environment via HTTPS using ACM and Route 53.
Prompts for a certificate if multiple are ISSUED, otherwise auto-selects.
Supports subdomains, root domains, and custom subdomains.
"""

import time
from typing import Dict, Optional, Tuple

from . import support
from .support import DeploymentError
from .setup import ConfigurationManager, ClientManager, logger


@support.aws_handler
def pick_certificate(acm_client=None) -> str:
    """
    Choose or auto-select an ISSUED ACM certificate.
    Returns the ARN of the chosen certificate.
    """
    if acm_client is None:
        acm_client = ClientManager.get_client("acm")

    logger.info("Retrieving certificates from ACM")
    certs = acm_client.list_certificates(CertificateStatuses=["ISSUED"])[
        "CertificateSummaryList"
    ]

    if not certs:
        raise DeploymentError("No ISSUED certificates found in ACM.")

    if len(certs) == 1:
        cert = certs[0]
        logger.info(
            f"Using certificate: {cert['DomainName']} ({cert['CertificateArn']})"
        )
        return cert["CertificateArn"]
    print("\nMultiple ISSUED certificates found. Choose one:")

    for i, cert in enumerate(certs, 1):
        print(f"{i}) {cert.get('DomainName', '?')} ({cert['CertificateArn']})")

    while True:
        try:
            choice = int(input("\nEnter certificate number: "))
            if 1 <= choice <= len(certs):
                chosen = certs[choice - 1]
                logger.info(
                    f"Selected certificate: {chosen['DomainName']} ({chosen['CertificateArn']})"
                )
                return chosen["CertificateArn"]
        except ValueError:
            pass
        print("Invalid selection. Try again.")


def get_domain_from_certificate(cert_domain: str, config: Dict) -> str:
    """
    Determine the domain to use based on certificate domain and configuration.

    Args:
        cert_domain: Domain name from the certificate
        config: Configuration dictionary

    Returns:
        Domain name to use for HTTPS
    """
    project_name = ConfigurationManager.get_project_name()
    https_config = config.get("https", {})
    domain_mode = https_config.get("domain_mode", "subdomain")

    if domain_mode == "root":
        # Remove wildcard and use root domain
        return cert_domain.replace("*.", "")
    elif domain_mode == "custom":
        # Use custom subdomain if provided
        custom_subdomain = https_config.get("custom_subdomain", "")
        if custom_subdomain:
            if "*." in cert_domain:
                return f"{custom_subdomain}.{cert_domain.replace('*.', '')}"
            else:
                logger.warning(
                    f"Certificate domain '{cert_domain}' doesn't have a wildcard. "
                    f"Custom subdomain '{custom_subdomain}' may not be covered by this certificate."
                )
                return f"{custom_subdomain}.{cert_domain}"
        else:
            logger.warning(
                "Custom domain mode selected but no custom_subdomain provided. "
                "Falling back to subdomain mode."
            )
            return cert_domain.replace("*", project_name)
    else:  # subdomain (default)
        # Replace wildcard with project name (original behavior)
        return cert_domain.replace("*", project_name)


@support.aws_handler
def get_hosted_zone_id(domain: str) -> str:
    """
    Return the ID of the best-matching hosted zone for `domain`.
    """
    r53_client = ClientManager.get_client("route53")
    logger.info(f"Finding Route 53 hosted zone for {domain}")

    zones = r53_client.list_hosted_zones()["HostedZones"]
    matches = [z for z in zones if domain.endswith(z["Name"].rstrip("."))]

    if not matches:
        raise DeploymentError(f"No hosted zone found for domain {domain}")

    # Return the most specific matching zone
    best_zone = max(matches, key=lambda z: len(z["Name"]))
    logger.info(f"Found zone: {best_zone['Name']}")

    return best_zone["Id"]


@support.aws_handler
def ensure_security_group_https(lb_arn: str) -> None:
    """
    Authorize inbound and outbound HTTPS if missing on the LB's security group.
    """
    ec2_client = ClientManager.get_client("ec2")
    elbv2_client = ClientManager.get_client("elbv2")

    logger.info("Configuring security groups for HTTPS")

    lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])[
        "LoadBalancers"
    ][0]

    sg_updates = 0
    for sg_id in lb["SecurityGroups"]:
        sg = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]

        # Check inbound HTTPS rule
        has_inbound_https = any(
            p["IpProtocol"] == "tcp"
            and p.get("FromPort") == 443
            and p.get("ToPort") == 443
            for p in sg["IpPermissions"]
        )

        # Check outbound HTTPS rule
        has_outbound_https = any(
            p["IpProtocol"] == "tcp"
            and p.get("FromPort") == 443
            and p.get("ToPort") == 443
            for p in sg["IpPermissionsEgress"]
        )

        # Add inbound HTTPS if missing
        if not has_inbound_https:
            logger.info(f"Adding inbound HTTPS (443) to security group {sg_id}")
            ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [
                            {
                                "CidrIp": "0.0.0.0/0",
                                "Description": "HTTPS from anywhere",
                            }
                        ],
                    }
                ],
            )
            sg_updates += 1

        # Add outbound HTTPS if missing
        if not has_outbound_https:
            logger.info(f"Adding outbound HTTPS (443) to security group {sg_id}")
            ec2_client.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [
                            {"CidrIp": "0.0.0.0/0", "Description": "HTTPS to anywhere"}
                        ],
                    }
                ],
            )
            sg_updates += 1

    if sg_updates > 0:
        logger.info(f"Added {sg_updates} rules")
    else:
        logger.info("Already configured")


@support.aws_handler
def create_dns_record(zone_id: str, domain: str, lb_dns: str, config: Dict) -> dict:
    """
    Create a DNS record pointing `domain` to `lb_dns`.

    Args:
        zone_id: Route 53 hosted zone ID
        domain: Domain name to create record for
        lb_dns: Load balancer DNS name
        config: Configuration dictionary

    Returns:
        Response from Route 53 API
    """
    r53_client = ClientManager.get_client("route53")
    elbv2_client = ClientManager.get_client("elbv2")
    https_config = config.get("https", {})

    # Get TTL from config
    ttl = https_config.get("ttl", 300)

    # Determine if we're creating a root domain record (no subdomains)
    is_root_domain = domain.count(".") == 1 and all(
        part.isalpha() for part in domain.split(".")
    )

    logger.info(
        f"Updating DNS record for {domain} (type: {'A' if is_root_domain else 'CNAME'})"
    )

    # For root domains with Application Load Balancers, we should use an A record with Alias
    if is_root_domain:
        # We need to find the load balancer's canonical hosted zone ID
        # Extract the load balancer ID from the DNS name
        lb_name = lb_dns.split(".")[0]

        # Find matching load balancer to get its canonical hosted zone ID
        lbs = elbv2_client.describe_load_balancers()["LoadBalancers"]
        matching_lb = next((lb for lb in lbs if lb["DNSName"] == lb_dns), None)

        if not matching_lb:
            logger.warning(f"Could not find load balancer with DNS name {lb_dns}")
            # Fall back to CNAME record
            logger.info(f"Falling back to CNAME record for {domain}")
            change_batch = {
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "CNAME",
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": lb_dns}],
                        },
                    }
                ]
            }
        else:
            # Use A record with Alias for root domain
            change_batch = {
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": domain,
                            "Type": "A",
                            "AliasTarget": {
                                "HostedZoneId": matching_lb["CanonicalHostedZoneId"],
                                "DNSName": lb_dns,
                                "EvaluateTargetHealth": True,
                            },
                        },
                    }
                ]
            }
    else:
        # Use standard CNAME record (works for subdomains)
        change_batch = {
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": domain,
                        "Type": "CNAME",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": lb_dns}],
                    },
                }
            ]
        }

    resp = r53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch=change_batch,
    )

    logger.info("updated")
    return resp


def wait_for_dns_sync(change_id: str) -> None:
    """
    Poll Route53 until the record change is INSYNC.
    """
    r53_client = ClientManager.get_client("route53")

    logger.info("Waiting for DNS changes to propagate")

    while True:
        status = r53_client.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            break
        time.sleep(10)


def enable_https(config: Dict, cert_arn: str) -> None:
    """
    Main driver for enabling HTTPS on an Elastic Beanstalk environment.
    """
    project_name = ConfigurationManager.get_project_name()
    env_name = config["application"]["environment"]

    logger.info("Initializing HTTPS configuration")

    # Get ACM certificate details
    acm_client = ClientManager.get_client("acm")
    cert = acm_client.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    cert_domain = cert["DomainName"]

    # Determine the domain to use based on configuration
    domain = get_domain_from_certificate(cert_domain, config)
    logger.info(f"Using domain: {domain}")

    # Find load balancer
    logger.info("Locating environment load balancer")
    lb_arn = support.find_environment_load_balancer(env_name)
    if not lb_arn:
        raise DeploymentError("No load balancer found for environment")

    elbv2_client = ClientManager.get_client("elbv2")
    lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])[
        "LoadBalancers"
    ][0]

    # Configure security and HTTPS
    logger.info("Configuring HTTPS")
    ensure_security_group_https(lb_arn)
    support.setup_https_listener(lb_arn, cert_arn, project_name)

    # Set up DNS
    logger.info("Configuring DNS")
    zone_id = get_hosted_zone_id(domain)
    resp = create_dns_record(zone_id, domain, lb["DNSName"], config)
    wait_for_dns_sync(resp["ChangeInfo"]["Id"])

    logger.info(f"HTTPS configuration complete!")
    logger.info(
        f"Your application is now available at: https://{domain} (Note: DNS propagation may take up to 48 hours to complete globally)"
    )
