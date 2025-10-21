# secure.py

"""
Secure your Elastic Beanstalk environment via HTTPS using ACM and Route 53.
"""

import os
import time
from typing import Dict, Optional, Tuple, List

from . import support
from .shield import shield
from .config import (
    ClientManager,
    StateManager,
    logger,
    DeploymentError,
    ConfigurationError,
    get_env_var,
    get_oidc_env_var,
)


@support.aws_handler
def pick_certificate(acm_client=None, certificate_arn: Optional[str] = None) -> str:
    """
    Choose or auto-select an ISSUED ACM certificate.

    Args:
        acm_client: ACM client (optional)
        certificate_arn: Explicit certificate ARN (optional)

    Returns:
        The ARN of the chosen certificate
    """
    if acm_client is None:
        acm_client = ClientManager.get_client("acm")

    # Check for explicit certificate ARN parameter
    if certificate_arn:
        logger.info(f"Using provided certificate ARN: {certificate_arn}")
        return certificate_arn

    # Check for environment variable with certificate ARN
    cert_arn = get_env_var("CERTIFICATE_ARN")
    if cert_arn:
        logger.info(f"Using certificate from environment: {cert_arn}")
        return cert_arn

    logger.info("Retrieving certificates from ACM")
    certs = acm_client.list_certificates(CertificateStatuses=["ISSUED"])[
        "CertificateSummaryList"
    ]

    if not certs:
        raise DeploymentError("No ISSUED certificates found in ACM.")

    # If only one certificate, use it automatically
    if len(certs) == 1:
        cert = certs[0]
        logger.info(
            f"Using certificate: {cert['DomainName']} ({cert['CertificateArn']})"
        )
        return cert["CertificateArn"]

    # Fall back to interactive selection
    print("\nMultiple ISSUED certificates found. Choose one:")
    print("(You can avoid this prompt by setting certificate_arn parameter or LB_CERTIFICATE_ARN env var)")

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
                print(
                    f"\nTip: Pass certificate_arn='{chosen['CertificateArn']}' to secure() to skip this prompt next time."
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

    # Check subject alternative names
    for name in cert.get("SubjectAlternativeNames", []):
        name = name.lower()

        # Exact match
        if name == domain:
            return True

        # Wildcard match
        if name.startswith("*."):
            wildcard_domain = name[2:]
            domain_parts = domain.split(".")

            # Check if it's a first-level subdomain of the wildcard domain
            if len(domain_parts) == len(
                wildcard_domain.split(".")
            ) + 1 and domain.endswith(wildcard_domain):
                return True

    return False


def get_domains_from_certificate_config(
    cert_domain: str,
    domain_mode: str,
    app_name: str,
    custom_subdomains: Optional[List[str]] = None,
    include_root: bool = False,
) -> List[str]:
    """
    Determine which domains to use based on certificate domain and mode.

    Args:
        cert_domain: Primary domain name from the certificate
        domain_mode: Domain mode (sub, root, custom)
        app_name: Application name
        custom_subdomains: List of custom subdomain prefixes for custom mode
        include_root: Whether to include root domain in custom mode

    Returns:
        List of domain names to use for HTTPS
    """
    domains = []
    root_domain = cert_domain.replace("*.", "")

    if domain_mode == "root":
        domains.append(root_domain)
    elif domain_mode == "sub":
        domains.append(cert_domain.replace("*", app_name))
    elif domain_mode == "custom":
        # Custom mode - use provided subdomains
        if not custom_subdomains:
            raise ConfigurationError(
                "Custom domain mode requires custom_subdomains parameter or LB_CUSTOM_SUBDOMAINS env var"
            )

        # Add root domain if requested
        if include_root:
            domains.append(root_domain)

        # Add custom subdomains
        for subdomain in custom_subdomains:
            if subdomain:  # Skip empty strings
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
            if "." in domain and len(domain.split(".")) > 2:
                message = f"Subdomain '{domain}' is not covered by certificate"
            else:
                message = f"Root domain '{domain}' is not covered by certificate"

            results.append((domain, False, message))

    return results


@support.aws_handler
def get_hosted_zone_id(domain: str) -> str:
    """Return the ID of the best-matching hosted zone for domain."""
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
    """Authorize inbound and outbound HTTPS if missing on the LB's security group."""
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
def create_dns_record(zone_id: str, domain: str, lb_dns: str, ttl: int = 300) -> dict:
    """
    Create a DNS record pointing domain to lb_dns.

    Args:
        zone_id: Route 53 hosted zone ID
        domain: Domain name to create record for
        lb_dns: Load balancer DNS name
        ttl: TTL for DNS record

    Returns:
        Response from Route 53 API
    """
    r53_client = ClientManager.get_client("route53")
    elbv2_client = ClientManager.get_client("elbv2")

    # Determine if we're creating a root domain record
    is_root_domain = domain.count(".") == 1 and all(
        part.isalpha() for part in domain.split(".")
    )

    logger.info(
        f"Updating DNS record for {domain} (type: {'A' if is_root_domain else 'CNAME'})"
    )

    # For root domains, use A record with Alias
    if is_root_domain:
        # Find matching load balancer to get its canonical hosted zone ID
        lbs = elbv2_client.describe_load_balancers()["LoadBalancers"]
        matching_lb = next((lb for lb in lbs if lb["DNSName"] == lb_dns), None)

        if not matching_lb:
            logger.warning(f"Could not find load balancer with DNS name {lb_dns}")
            # Fall back to CNAME record
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
        # Use standard CNAME record for subdomains
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
    """Poll Route53 until the record change is INSYNC."""
    r53_client = ClientManager.get_client("route53")

    logger.info("Waiting for DNS changes to propagate")

    while True:
        status = r53_client.get_change(Id=change_id)["ChangeInfo"]["Status"]
        if status == "INSYNC":
            break
        time.sleep(10)


def secure(
    domain: Optional[str] = None,
    domain_mode: Optional[str] = None,
    certificate_arn: Optional[str] = None,
    ttl: int = 300,
    custom_subdomains: Optional[List[str]] = None,
    include_root: bool = False,
) -> Dict[str, str]:
    """
    Enable HTTPS on your Elastic Beanstalk environment.

    If OIDC environment variables are detected (OIDC_CLIENT_ID or OIDC_ISSUER),
    this command will automatically configure OIDC authentication as well.

    Args:
        domain: Domain name for HTTPS (optional, inferred from certificate)
        domain_mode: Domain mode - "sub", "root", or "custom" (default: "sub")
        certificate_arn: ACM certificate ARN (default: None, will prompt if multiple)
        ttl: DNS record TTL in seconds (default: 300)
        custom_subdomains: List of subdomain prefixes for custom mode (e.g., ["api", "admin"])
        include_root: Include root domain in custom mode (default: False)

    Returns:
        Dict with HTTPS configuration details (and OIDC details if auto-configured)
    """
    # Load full EB config
    eb_config = StateManager.load_eb_config()
    if not eb_config:
        raise DeploymentError(
            "No deployment configuration found. Please run 'ship' command first."
        )

    # Get app_name from EB CLI global section
    global_config = eb_config.get("global", {})
    app_name = global_config.get("application_name")

    # Get env_name from branch-defaults
    branch_defaults = eb_config.get("branch-defaults", {})
    main_branch = branch_defaults.get("main", {})
    env_name = main_branch.get("environment")

    # Get region from global section
    region = global_config.get("default_region")

    if not app_name or not env_name:
        raise DeploymentError("Invalid configuration: missing app_name or environment_name")

    # Initialize AWS clients
    ClientManager.initialize(region)

    logger.info("Initializing HTTPS configuration")
    logger.info(f"App: {app_name}")
    logger.info(f"Environment: {env_name}")

    # Get ACM certificate
    acm_client = ClientManager.get_client("acm")
    chosen_cert_arn = pick_certificate(acm_client, certificate_arn)
    cert = acm_client.describe_certificate(CertificateArn=chosen_cert_arn)["Certificate"]
    cert_domain = cert["DomainName"]

    # Determine domain mode
    if not domain_mode:
        domain_mode = get_env_var("DOMAIN_MODE", default="sub")

    # Read custom subdomain configuration from env vars if not provided
    if domain_mode == "custom":
        if not custom_subdomains:
            # Try to read from env var as comma-separated list
            subdomains_str = get_env_var("CUSTOM_SUBDOMAINS")
            if subdomains_str:
                custom_subdomains = [s.strip() for s in subdomains_str.split(",") if s.strip()]

        if not include_root:
            # Check env var for include_root
            include_root_str = get_env_var("INCLUDE_ROOT")
            if include_root_str:
                include_root = include_root_str.lower() in ("true", "1", "yes")

    # Determine domains to use
    domains = get_domains_from_certificate_config(
        cert_domain, domain_mode, app_name, custom_subdomains, include_root
    )
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
            f"Certificate validation failed:\n"
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
    support.setup_https_listener(lb_arn, chosen_cert_arn, app_name)

    # Get hosted zone for the domain(s)
    root_domain = cert_domain.replace("*.", "")
    zone_id = get_hosted_zone_id(root_domain)

    # Set up DNS records for each domain
    for domain in domains:
        logger.info(f"Configuring DNS for {domain}")
        resp = create_dns_record(zone_id, domain, lb["DNSName"], ttl)
        wait_for_dns_sync(resp["ChangeInfo"]["Id"])
        logger.info(f"DNS configuration complete for {domain}")

    # Log completion message
    domains_list = ", ".join([f"https://{d}" for d in domains])
    primary_domain = domains[0]

    logger.info(f"HTTPS configuration complete!")
    logger.info(
        f"Your application is now available at: {domains_list}"
    )
    logger.info("Note: DNS propagation may take up to 48 hours to complete globally")

    # Output OIDC callback URLs for authentication configuration
    logger.info("\nOIDC Configuration URLs:")
    logger.info(f"  Callback URL:  https://{primary_domain}/oauth2/idpresponse")
    logger.info(f"  Logout URL:    https://{primary_domain}")

    # Auto-configure OIDC if env vars are present
    if get_oidc_env_var("CLIENT_ID") or get_oidc_env_var("ISSUER"):
        logger.info("\nOIDC configuration detected in environment variables")
        logger.info("Auto-configuring OIDC authentication...")
        try:
            shield_result = shield()
            logger.info("\nOIDC authentication successfully configured!")
            return {
                "domains": domains,
                "certificate_arn": chosen_cert_arn,
                "certificate_domain": cert_domain,
                "oidc_callback_url": f"https://{primary_domain}/oauth2/idpresponse",
                "oidc_logout_url": f"https://{primary_domain}",
                "oidc": shield_result,
            }
        except Exception as e:
            logger.warning(f"\nOIDC auto-configuration failed: {e}")
            logger.info("Run 'lb shield' command manually to configure OIDC")
    else:
        logger.info("\nTo enable OIDC authentication, add OIDC configuration to .env and run 'lb shield'")

    return {
        "domains": domains,
        "certificate_arn": chosen_cert_arn,
        "certificate_domain": cert_domain,
        "oidc_callback_url": f"https://{primary_domain}/oauth2/idpresponse",
        "oidc_logout_url": f"https://{primary_domain}",
    }
