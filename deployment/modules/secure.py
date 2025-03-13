"""
Secure your Elastic Beanstalk environment via HTTPS using ACM and Route 53.
Prompts for a certificate if multiple are ISSUED, otherwise auto-selects.
"""

import time
from pathlib import Path
from typing import Dict
import boto3

from . import common
from .common import DeploymentError

def get_project_name() -> str:
    """Return the name of the root-level folder (project)."""
    return Path(__file__).parent.parent.parent.name

@common.aws_handler
def pick_certificate(acm_client) -> str:
    """
    Choose or auto-select an ISSUED ACM certificate.
    Returns the ARN of the chosen certificate.
    """
    certs = acm_client.list_certificates(CertificateStatuses=['ISSUED'])['CertificateSummaryList']
    
    if not certs:
        raise DeploymentError("No ISSUED certificates found in ACM.")

    if len(certs) == 1:
        cert = certs[0]
        print(f"Using certificate:\n  Domain: {cert['DomainName']}\n  ARN: {cert['CertificateArn']}")
        return cert['CertificateArn']

    print("\nMultiple ISSUED certificates found. Choose one:")
    for i, cert in enumerate(certs, 1):
        print(f"{i}) {cert.get('DomainName', '?')} ({cert['CertificateArn']})")

    while True:
        try:
            choice = int(input("\nEnter certificate number: "))
            if 1 <= choice <= len(certs):
                chosen = certs[choice - 1]
                print(f"\nSelected: {chosen['DomainName']} ({chosen['CertificateArn']})")
                return chosen['CertificateArn']
        except ValueError:
            pass
        print("Invalid selection. Try again.")

@common.aws_handler
def get_hosted_zone_id(r53_client, domain: str) -> str:
    """
    Return the ID of the best-matching hosted zone for `domain`.
    """
    zones = r53_client.list_hosted_zones()['HostedZones']
    matches = [z for z in zones if domain.endswith(z['Name'].rstrip('.'))]
    
    if not matches:
        raise DeploymentError(f"No hosted zone found for domain {domain}")
    
    # Return the most specific matching zone
    return max(matches, key=lambda z: len(z['Name']))['Id']

@common.aws_handler
def ensure_security_group_https(ec2_client, elbv2_client, lb_arn: str) -> None:
    """
    Authorize inbound and outbound HTTPS if missing on the LB's security group.
    """
    lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
    
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
            print(f"Adding inbound HTTPS (443) to security group {sg_id}")
            ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS from anywhere'}]
                }]
            )
        
        # Add outbound HTTPS if missing
        if not has_outbound_https:
            print(f"Adding outbound HTTPS (443) to security group {sg_id}")
            ec2_client.authorize_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS to anywhere'}]
                }]
            )

@common.aws_handler
def create_dns_record(r53_client, zone_id: str, domain: str, lb_dns: str) -> dict:
    """
    UPSERT a CNAME record pointing `domain` to `lb_dns`.
    """
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
    print(f"DNS record updated for {domain}")
    return resp

def wait_for_dns_sync(r53_client, change_id: str) -> None:
    """
    Poll Route53 until the record change is INSYNC.
    """
    print("Waiting for DNS changes to propagate", end="", flush=True)
    while True:
        status = r53_client.get_change(Id=change_id)['ChangeInfo']['Status']
        if status == 'INSYNC':
            print("\nDNS changes are now in sync.")
            break
        print(".", end="", flush=True)
        time.sleep(15)

def enable_https(config: Dict, cert_arn: str) -> None:
    """
    Main driver for enabling HTTPS on an Elastic Beanstalk environment.
    """
    project_name = get_project_name()
    region = config['aws']['region']
    env_name = config['application']['environment']
    
    print("\nInitializing HTTPS configuration...")
    session = boto3.Session(region_name=region)
    
    # Initialize AWS clients
    acm_client = session.client('acm')
    r53_client = session.client('route53')
    eb_client = session.client('elasticbeanstalk')
    elbv2_client = session.client('elbv2')
    ec2_client = session.client('ec2')

    # Get certificate details
    cert = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
    domain = cert['DomainName'].replace('*', project_name)
    print(f"Using domain: {domain}")

    # Find load balancer
    print("Locating environment load balancer...")
    lb_arn = common.find_environment_load_balancer(eb_client, elbv2_client, env_name)
    if not lb_arn:
        raise DeploymentError("No load balancer found for environment")
    
    lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]

    # Configure security and HTTPS
    print("Configuring HTTPS...")
    ensure_security_group_https(ec2_client, elbv2_client, lb_arn)
    common.setup_https_listener(elbv2_client, lb_arn, cert_arn, project_name)

    # Set up DNS
    print("Configuring DNS...")
    zone_id = get_hosted_zone_id(r53_client, domain)
    resp = create_dns_record(r53_client, zone_id, domain, lb['DNSName'])
    wait_for_dns_sync(r53_client, resp['ChangeInfo']['Id'])

    print(f"\nHTTPS configuration complete!")
    print(f"Your application is now available at: https://{domain}")
    print("Note: DNS propagation may take up to 48 hours to complete globally.")