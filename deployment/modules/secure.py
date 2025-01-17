"""
Enables HTTPS for an Elastic Beanstalk environment using ACM certificate and Route 53.
"""

import sys
import time
from pathlib import Path
from typing import Dict, Tuple
import yaml
import boto3
from botocore.exceptions import ClientError

# Add deployment directory to path for standalone testing
sys.path.append(str(Path(__file__).parent.parent))
from modules.common import aws_handler, DeploymentError

def load_config() -> Dict:
    """Load configuration from YAML."""
    config_path = Path(__file__).parent.parent / "configurations" / "config.yml"
    try:
        return yaml.safe_load(config_path.read_text())
    except Exception as e:
        raise DeploymentError(f"Failed to load config: {e}")

@aws_handler
def get_certificate_info(acm_client, certificate_id: str) -> Tuple[str, str]:
    """Get certificate ARN and domain name."""
    try:
        response = acm_client.describe_certificate(CertificateArn=certificate_id)
        cert = response['Certificate']
        domain = cert['DomainName'].replace('*', 'lazy-beanstalk')
        return certificate_id, domain
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise DeploymentError(f"Certificate {certificate_id} not found")
        raise

@aws_handler
def get_hosted_zone_id(route53_client, domain_name: str) -> str:
    """Find matching hosted zone for domain."""
    zones = route53_client.list_hosted_zones()['HostedZones']
    matching_zones = [
        zone for zone in zones 
        if domain_name.endswith(zone['Name'].rstrip('.'))
    ]
    
    if not matching_zones:
        raise DeploymentError(f"No hosted zone found for domain {domain_name}")
    
    # Use the most specific (longest) matching zone
    return max(matching_zones, key=lambda z: len(z['Name']))['Id']

@aws_handler
def find_load_balancer(eb_client, elbv2_client, env_name: str) -> str:
    """Get the ALB ARN for the environment."""
    env = eb_client.describe_environments(
        EnvironmentNames=[env_name]
    )['Environments'][0]
    
    # Find the matching load balancer
    load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
    
    for lb in load_balancers:
        if lb['Type'].lower() == 'application':
            tags = elbv2_client.describe_tags(
                ResourceArns=[lb['LoadBalancerArn']]
            )['TagDescriptions'][0]['Tags']
            
            env_tag = next((tag for tag in tags if tag['Key'] == 'elasticbeanstalk:environment-name'), None)
            if env_tag and env_tag['Value'] == env_name:
                return lb['LoadBalancerArn']
    
    raise DeploymentError("No application load balancer found for environment")

@aws_handler
def ensure_security_group_https(ec2_client, elbv2_client, lb_arn: str) -> None:
    """Ensure load balancer security group allows HTTPS."""
    # Get the security group ID from the load balancer
    lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
    security_groups = lb['SecurityGroups']
    
    for sg_id in security_groups:
        # Check if HTTPS rule exists
        sg = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        https_rule_exists = any(
            permission['IpProtocol'] == 'tcp' and
            permission.get('FromPort', 0) <= 443 and
            permission.get('ToPort', 0) >= 443
            for permission in sg['IpPermissions']
        )
        
        if not https_rule_exists:
            print(f"Adding HTTPS inbound rule to security group {sg_id}")
            ec2_client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS from anywhere'}]
                }]
            )

@aws_handler
def configure_https(elbv2_client, lb_arn: str, cert_arn: str) -> None:
    """Configure HTTPS listener on the load balancer."""
    # Check if HTTPS listener already exists
    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
    https_listener = next((l for l in listeners if l['Port'] == 443), None)
    
    if https_listener:
        print("HTTPS listener already exists")
        return

    # Find the target group from HTTP listener
    http_listener = next((l for l in listeners if l['Port'] == 80), None)
    if not http_listener:
        raise DeploymentError("No HTTP listener found")
    
    target_group_arn = http_listener['DefaultActions'][0]['TargetGroupArn']
    
    # Create HTTPS listener
    elbv2_client.create_listener(
        LoadBalancerArn=lb_arn,
        Protocol='HTTPS',
        Port=443,
        Certificates=[{'CertificateArn': cert_arn}],
        SslPolicy='ELBSecurityPolicy-2016-08',
        DefaultActions=[{
            'Type': 'forward',
            'TargetGroupArn': target_group_arn
        }]
    )
    print("HTTPS listener configured")

@aws_handler
def create_dns_record(route53_client, hosted_zone_id: str, domain_name: str, lb_dns: str) -> None:
    """Create CNAME record pointing to the load balancer."""
    route53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': domain_name,
                    'Type': 'CNAME',
                    'TTL': 300,
                    'ResourceRecords': [{'Value': lb_dns}]
                }
            }]
        }
    )
    print(f"DNS record created for {domain_name}")

def enable_https(config: Dict, certificate_id: str) -> None:
    """
    Enable HTTPS for the Elastic Beanstalk environment.
    
    Args:
        config: Application configuration dictionary
        certificate_id: ACM certificate ID or ARN
    """
    session = boto3.Session(region_name=config['aws']['region'])
    acm_client = session.client('acm')
    route53_client = session.client('route53')
    eb_client = session.client('elasticbeanstalk')
    elbv2_client = session.client('elbv2')
    ec2_client = session.client('ec2')
    
    print("Finding certificate...")
    cert_arn, domain = get_certificate_info(acm_client, certificate_id)
    
    print("Finding hosted zone...")
    zone_id = get_hosted_zone_id(route53_client, domain)
    
    print("Finding load balancer...")
    lb_arn = find_load_balancer(eb_client, elbv2_client, config['application']['environment'])
    lb_dns = elbv2_client.describe_load_balancers(
        LoadBalancerArns=[lb_arn]
    )['LoadBalancers'][0]['DNSName']
    
    print("Ensuring security group allows HTTPS...")
    ensure_security_group_https(ec2_client, elbv2_client, lb_arn)
    
    print("Configuring HTTPS listener...")
    configure_https(elbv2_client, lb_arn, cert_arn)
    
    print("Creating DNS record...")
    create_dns_record(route53_client, zone_id, domain, lb_dns)
    
    print(f"\nHTTPS enabled!")
    print(f"You can now access your application at: https://{domain}")
    print("Note: It may take a few minutes for DNS changes to propagate")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python secure.py <certificate-id>")
        sys.exit(1)
    
    try:
        config = load_config()
        enable_https(config, sys.argv[1])
    except DeploymentError as e:
        print(f"Error: {str(e)}")
        sys.exit(1)