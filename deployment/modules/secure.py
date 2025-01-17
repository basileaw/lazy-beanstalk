"""
Secure your Elastic Beanstalk environment via HTTPS using ACM and Route 53.
Prompts for a certificate if multiple are ISSUED, otherwise auto-selects.
"""

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple
import boto3
import yaml
from botocore.exceptions import ClientError

# Add deployment directory to path so we can import modules.common
sys.path.append(str(Path(__file__).parent.parent))

from modules.common import aws_handler, DeploymentError

def get_project_name() -> str:
    """Return the name of the root-level folder (project)."""
    return Path(__file__).parent.parent.parent.name

def pick_certificate(acm_client) -> str:
    """
    Choose or auto-select an ISSUED ACM certificate.
    Returns the ARN of the chosen certificate.
    """
    try:
        certs = acm_client.list_certificates(CertificateStatuses=['ISSUED']).get('CertificateSummaryList', [])
    except ClientError as e:
        raise DeploymentError(f"Failed to list certificates: {e}")

    if not certs:
        raise DeploymentError("No ISSUED certificates found in ACM.")

    if len(certs) == 1:
        c = certs[0]
        print(f"Only one certificate:\n  Domain: {c['DomainName']}\n  ARN: {c['CertificateArn']}")
        return c['CertificateArn']

    print("Multiple ISSUED certificates found. Choose one:")
    for i, c in enumerate(certs, 1):
        print(f"{i}) {c.get('DomainName','?')} ({c['CertificateArn']})")

    while True:
        try:
            sel = int(input("Enter certificate number: "))
            if 1 <= sel <= len(certs):
                chosen = certs[sel - 1]
                print(f"Selected: {chosen['DomainName']} ({chosen['CertificateArn']})")
                return chosen['CertificateArn']
        except ValueError:
            pass
        print("Invalid selection. Try again.")

@aws_handler
def get_certificate_info(acm, cert_arn: str, project: str) -> Tuple[str, str]:
    """
    Return the certificate ARN and domain (replace '*' with project name).
    """
    try:
        c = acm.describe_certificate(CertificateArn=cert_arn)['Certificate']
        return cert_arn, c['DomainName'].replace('*', project)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise DeploymentError(f"Certificate {cert_arn} not found.")
        raise

@aws_handler
def get_hosted_zone_id(r53, domain: str) -> str:
    """
    Return the ID of the best-matching hosted zone for `domain`.
    """
    zones = r53.list_hosted_zones()['HostedZones']
    matches = [z for z in zones if domain.endswith(z['Name'].rstrip('.'))]
    if not matches:
        raise DeploymentError(f"No hosted zone found for domain {domain}")
    return max(matches, key=lambda z: len(z['Name']))['Id']

@aws_handler
def find_load_balancer(eb, elbv2, env_name: str) -> str:
    """
    Return the ALB ARN for the given EB environment name.
    """
    env = eb.describe_environments(EnvironmentNames=[env_name])['Environments'][0]
    lbs = elbv2.describe_load_balancers()['LoadBalancers']
    for lb in lbs:
        if lb['Type'].lower() == 'application':
            tags = elbv2.describe_tags(ResourceArns=[lb['LoadBalancerArn']])['TagDescriptions'][0]['Tags']
            env_tag = next((t for t in tags if t['Key'] == 'elasticbeanstalk:environment-name'), {})
            if env_tag.get('Value') == env_name:
                return lb['LoadBalancerArn']
    raise DeploymentError("No ALB found for environment.")

@aws_handler
def ensure_security_group_https(ec2, elbv2, lb_arn: str) -> None:
    """
    Authorize inbound HTTPS if missing on the LB's Security Group.
    """
    lb = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
    for sg_id in lb['SecurityGroups']:
        sg = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        has_https = any(
            p['IpProtocol'] == 'tcp' and p.get('FromPort') == 443 and p.get('ToPort') == 443
            for p in sg['IpPermissions']
        )
        if not has_https:
            print(f"Adding HTTPS rule to SG {sg_id}")
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp', 'FromPort': 443, 'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS from anywhere'}]
                }]
            )

@aws_handler
def configure_https(elbv2, lb_arn: str, cert_arn: str) -> None:
    """
    Create an HTTPS listener if it does not yet exist.
    """
    listeners = elbv2.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
    if any(l['Port'] == 443 for l in listeners):
        print("HTTPS listener already exists.")
        return

    http_listener = next((l for l in listeners if l['Port'] == 80), None)
    if not http_listener:
        raise DeploymentError("No HTTP listener found.")

    elbv2.create_listener(
        LoadBalancerArn=lb_arn, Protocol='HTTPS', Port=443,
        Certificates=[{'CertificateArn': cert_arn}],
        SslPolicy='ELBSecurityPolicy-2016-08',
        DefaultActions=[{'Type': 'forward', 'TargetGroupArn': http_listener['DefaultActions'][0]['TargetGroupArn']}]
    )
    print("HTTPS listener configured.")

@aws_handler
def create_dns_record(r53, zone_id: str, domain: str, lb_dns: str) -> dict:
    """
    UPSERT a CNAME record pointing `domain` to `lb_dns`.
    """
    resp = r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': domain, 'Type': 'CNAME', 'TTL': 300,
                    'ResourceRecords': [{'Value': lb_dns}]
                }
            }]
        }
    )
    print(f"DNS record UPSERT for {domain}")
    return resp

def wait_for_dns_sync(r53, change_id: str) -> None:
    """
    Poll Route53 until the record change is INSYNC.
    """
    print("Waiting for DNS changes to propagate in Route 53", end="", flush=True)
    while True:
        try:
            status = r53.get_change(Id=change_id)['ChangeInfo']['Status']
        except ClientError as e:
            print()  # newline before error
            raise DeploymentError(f"Error checking DNS change status: {e}")

        if status == 'INSYNC':
            print("\nDNS changes are now in sync (INSYNC).")
            break
        print(".", end="", flush=True)
        time.sleep(15)

def enable_https(config: Dict[str, Any], cert_id: str) -> None:
    """
    Main driver for enabling HTTPS on an Elastic Beanstalk environment.
    - Finds the correct ALB, security group, etc.
    - Sets up a new HTTPS listener with your chosen certificate.
    - Creates a DNS CNAME record in Route53.
    """
    region = config['aws']['region']
    session = boto3.Session(region_name=region)
    acm = session.client('acm')
    r53 = session.client('route53')
    eb = session.client('elasticbeanstalk')
    elbv2 = session.client('elbv2')
    ec2 = session.client('ec2')

    print("Finding certificate...")
    project_name = get_project_name()
    cert_arn, domain = get_certificate_info(acm, cert_id, project_name)

    print("Finding hosted zone...")
    zone_id = get_hosted_zone_id(r53, domain)

    print("Finding load balancer...")
    lb_arn = find_load_balancer(eb, elbv2, config['application']['environment'])
    lb_dns = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]['DNSName']

    print("Ensuring security group allows HTTPS...")
    ensure_security_group_https(ec2, elbv2, lb_arn)

    print("Configuring HTTPS listener...")
    configure_https(elbv2, lb_arn, cert_arn)

    print("Creating DNS record...")
    resp = create_dns_record(r53, zone_id, domain, lb_dns)
    wait_for_dns_sync(r53, resp['ChangeInfo']['Id'])

    print("\nHTTPS enabled!")
    print(f"Access your app at: https://{domain}")
    print("Note: Full global DNS propagation may require additional time.")
