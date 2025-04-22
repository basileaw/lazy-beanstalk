# secure.py

"""
Secure your Elastic Beanstalk environment via HTTPS using ACM and Route 53.
Prompts for a certificate if multiple are ISSUED, otherwise auto-selects.
Supports subdomains, root domains, and multiple custom subdomains.
"""

import time
from typing import Dict, Optional, Tuple, List

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


def is_domain_covered_by_certificate(domain: str, cert: Dict) -> bool:
    """
    Check if a domain is covered by a certificate.

    Args:
        domain: Domain to check
        cert: Certificate dictionary from describe_certificate

    Returns:
        bool: True if the domain is covered by the certificate
    """
    domain = domain.lower()

    # Exact match for domain name
    if cert["DomainName"].lower() == domain:
        return True

    # Check subject alternative names (which include the primary domain and wildcards)
    for name in cert.get("SubjectAlternativeNames", []):
        name = name.lower()

        # Exact match
        if name == domain:
            return True

        # Wildcard match
        if name.startswith("*."):
            # Wildcard only covers one level of subdomain
            wildcard_domain = name[2:]  # Remove '*.'
            domain_parts = domain.split(".")

            # Check if it's a first-level subdomain of the wildcard domain
            if len(domain_parts) == len(
                wildcard_domain.split(".")
            ) + 1 and domain.endswith(wildcard_domain):
                return True

    return False


def get_domains_from_certificate_config(cert_domain: str, config: Dict) -> List[str]:
    """
    Determine which domains to use based on certificate domain and configuration.

    Args:
        cert_domain: Primary domain name from the certificate
        config: Configuration dictionary

    Returns:
        List of domain names to use for HTTPS
    """
    project_name = ConfigurationManager.get_project_name()
    https_config = config.get("https", {})
    domain_mode = https_config.get("domain_mode", "subdomain")
    domains = []

    root_domain = cert_domain.replace("*.", "")

    if domain_mode == "root":
        # Root domain mode - just return the root domain
        domains.append(root_domain)
    elif domain_mode == "subdomain":
        # Subdomain mode - use project name as subdomain
        domains.append(cert_domain.replace("*", project_name))
    elif domain_mode == "custom":
        # Custom subdomains mode
        include_root = https_config.get("include_root", False)
        custom_subdomains = https_config.get("custom_subdomains", [])

        # Add root domain if needed
        if include_root:
            domains.append(root_domain)

        # Add custom subdomains
        for subdomain in custom_subdomains:
            if subdomain:  # Skip empty subdomain names
                domains.append(f"{subdomain}.{root_domain}")

    return domains


def validate_domains_with_certificate(
    domains: List[str], cert: Dict
) -> List[Tuple[str, bool, str]]:
    """
    Validate each domain against the certificate.

    Args:
        domains: List of domain names to validate
        cert: Certificate dictionary from describe_certificate

    Returns:
        List of tuples (domain, is_valid, message)
    """
    results = []

    for domain in domains:
        is_covered = is_domain_covered_by_certificate(domain, cert)

        if is_covered:
            results.append((domain, True, "Domain is covered by certificate"))
        else:
            # Determine if it's a root domain or subdomain
            if "." in domain and len(domain.split(".")) > 2:
                # It's a subdomain
                message = f"Subdomain '{domain}' is not covered by certificate. Certificate may not include wildcard."
            else:
                # It's a root domain
                message = f"Root domain '{domain}' is not covered by certificate. Certificate may not include this domain."

            results.append((domain, False, message))

    return results


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

    # Determine domains to use based on configuration
    domains = get_domains_from_certificate_config(cert_domain, config)
    if not domains:
        raise DeploymentError("No domains configured for HTTPS")

    # Validate domains against certificate
    validation_results = validate_domains_with_certificate(domains, cert)

    # Check for any invalid domains
    invalid_domains = [
        (domain, msg) for domain, is_valid, msg in validation_results if not is_valid
    ]
    if invalid_domains:
        error_msgs = []
        for domain, msg in invalid_domains:
            error_msgs.append(f"- {domain}: {msg}")

        raise DeploymentError(
            f"Certificate validation failed for the following domains:\n"
            f"{chr(10).join(error_msgs)}\n"
            f"Certificate covers: {cert_domain} and {', '.join(cert.get('SubjectAlternativeNames', []))}"
        )

    # Domains are valid, proceed with setup
    logger.info(f"Setting up HTTPS for domains: {', '.join(domains)}")

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

    # Get hosted zone for the domain(s)
    # We use the root domain to find the hosted zone
    root_domain = cert_domain.replace("*.", "")
    zone_id = get_hosted_zone_id(root_domain)

    # Set up DNS records for each domain
    for domain in domains:
        logger.info(f"Configuring DNS for {domain}")
        resp = create_dns_record(zone_id, domain, lb["DNSName"], config)
        wait_for_dns_sync(resp["ChangeInfo"]["Id"])
        logger.info(f"DNS configuration complete for {domain}")

    # Log completion message with all domains
    domains_list = ", ".join([f"https://{d}" for d in domains])
    logger.info(f"HTTPS configuration complete!")
    logger.info(
        f"Your application is now available at: {domains_list} (Note: DNS propagation may take up to 48 hours to complete globally)"
    )
