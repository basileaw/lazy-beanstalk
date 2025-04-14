# secure.py 

"""
Secure your Elastic Beanstalk environment via HTTPS using ACM and Route 53.
Prompts for a certificate if multiple are ISSUED, otherwise auto-selects.
"""

import time
from typing import Dict

from . import common
from .common import DeploymentError
from .configure import (
    ConfigurationManager, ClientManager, ProgressIndicator, logger
)

@common.aws_handler
def pick_certificate(acm_client=None) -> str:
    """
    Choose or auto-select an ISSUED ACM certificate.
    Returns the ARN of the chosen certificate.
    """
    if acm_client is None:
        acm_client = ClientManager.get_client('acm')
    
    ProgressIndicator.start("Retrieving certificates from ACM")
    certs = acm_client.list_certificates(CertificateStatuses=['ISSUED'])['CertificateSummaryList']
    
    if not certs:
        raise DeploymentError("No ISSUED certificates found in ACM.")

    if len(certs) == 1:
        cert = certs[0]
        logger.info(f"Using certificate: {cert['DomainName']} ({cert['CertificateArn']})")
        return cert['CertificateArn']
    print("\nMultiple ISSUED certificates found. Choose one:")
    
    for i, cert in enumerate(certs, 1):
        print(f"{i}) {cert.get('DomainName', '?')} ({cert['CertificateArn']})")

    while True:
        try:
            choice = int(input("\nEnter certificate number: "))
            if 1 <= choice <= len(certs):
                chosen = certs[choice - 1]
                logger.info(f"Selected certificate: {chosen['DomainName']} ({chosen['CertificateArn']})")
                return chosen['CertificateArn']
        except ValueError:
            pass
        print("Invalid selection. Try again.")

@common.aws_handler
def get_hosted_zone_id(domain: str) -> str:
    """
    Return the ID of the best-matching hosted zone for `domain`.
    """
    r53_client = ClientManager.get_client('route53')
    ProgressIndicator.start(f"Finding Route 53 hosted zone for {domain}")
    
    zones = r53_client.list_hosted_zones()['HostedZones']
    matches = [z for z in zones if domain.endswith(z['Name'].rstrip('.'))]
    
    if not matches:
        raise DeploymentError(f"No hosted zone found for domain {domain}")
    
    # Return the most specific matching zone
    best_zone = max(matches, key=lambda z: len(z['Name']))
    ProgressIndicator.complete(f"Found zone: {best_zone['Name']}")
    
    return best_zone['Id']

@common.aws_handler
def ensure_security_group_https(lb_arn: str) -> None:
    """
    Authorize inbound and outbound HTTPS if missing on the LB's security group.
    """
    ec2_client = ClientManager.get_client('ec2')
    elbv2_client = ClientManager.get_client('elbv2')
    
    ProgressIndicator.start("Configuring security groups for HTTPS")
    
    lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
    
    sg_updates = 0
    for sg_id in lb['SecurityGroups']:
        sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        
        # Check inbound HTTPS rule
        has_inbound_https = any(
            p['IpProtocol'] == 'tcp' and 
            p.get('FromPort') == 443 and 
            p.get('ToPort') == 443
            for p in sg['IpPermissions']
        )
        
        # Check outbound HTTPS rule
        has_outbound_https = any(
            p['IpProtocol'] == 'tcp' and 
            p.get('FromPort') == 443 and 
            p.get('ToPort') == 443
            for p in sg['IpPermissionsEgress']
        )
        
        # Add inbound HTTPS if missing
        if not has_inbound_https:
            logger.info(f"Adding inbound HTTPS (443) to security group {sg_id}")
            ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS from anywhere'}]
                }]
            )
            sg_updates += 1
        
        # Add outbound HTTPS if missing
        if not has_outbound_https:
            logger.info(f"Adding outbound HTTPS (443) to security group {sg_id}")
            ec2_client.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS to anywhere'}]
                }]
            )
            sg_updates += 1
    
    if sg_updates > 0:
        ProgressIndicator.complete(f"Added {sg_updates} rules")
    else:
        ProgressIndicator.complete("Already configured")

@common.aws_handler
def create_dns_record(zone_id: str, domain: str, lb_dns: str) -> dict:
    """
    UPSERT a CNAME record pointing `domain` to `lb_dns`.
    """
    r53_client = ClientManager.get_client('route53')
    
    ProgressIndicator.start(f"Updating DNS record for {domain}")
    
    resp = r53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': domain,
                    'Type': 'CNAME',
                    'TTL': 300,
                    'ResourceRecords': [{'Value': lb_dns}]
                }
            }]
        }
    )
    
    ProgressIndicator.complete("updated")
    return resp

def wait_for_dns_sync(change_id: str) -> None:
    """
    Poll Route53 until the record change is INSYNC.
    """
    r53_client = ClientManager.get_client('route53')
    
    ProgressIndicator.start("Waiting for DNS changes to propagate")
    
    while True:
        status = r53_client.get_change(Id=change_id)['ChangeInfo']['Status']
        if status == 'INSYNC':
            break
        ProgressIndicator.step()
        time.sleep(10)

def enable_https(config: Dict, cert_arn: str) -> None:
    """
    Main driver for enabling HTTPS on an Elastic Beanstalk environment.
    """
    project_name = ConfigurationManager.get_project_name()
    env_name = config['application']['environment']
    
    logger.info("Initializing HTTPS configuration")
    
    # Get ACM certificate details
    acm_client = ClientManager.get_client('acm')
    cert = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
    domain = cert['DomainName'].replace('*', project_name)
    logger.info(f"Using domain: {domain}")

    # Find load balancer
    ProgressIndicator.start("Locating environment load balancer")
    lb_arn = common.find_environment_load_balancer(env_name)
    if not lb_arn:
        raise DeploymentError("No load balancer found for environment")
    
    elbv2_client = ClientManager.get_client('elbv2')
    lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]

    # Configure security and HTTPS
    logger.info("Configuring HTTPS")
    ensure_security_group_https(lb_arn)
    common.setup_https_listener(lb_arn, cert_arn, project_name)

    # Set up DNS
    logger.info("Configuring DNS")
    zone_id = get_hosted_zone_id(domain)
    resp = create_dns_record(zone_id, domain, lb['DNSName'])
    wait_for_dns_sync(resp['ChangeInfo']['Id'])

    logger.info(f"HTTPS configuration complete!")
    print(f"\nYour application is now available at: https://{domain}")
    print("Note: DNS propagation may take up to 48 hours to complete globally.")