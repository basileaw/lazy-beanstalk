# scrap.py

"""Clean up Elastic Beanstalk environment and associated resources."""

import shutil
import yaml
from pathlib import Path
from typing import Dict, Optional
import boto3
from botocore.exceptions import ClientError

from . import common
from .common import DeploymentError

def get_project_name() -> str:
    """Retrieve the project name from the root folder."""
    return Path(__file__).parent.parent.parent.name

def load_config() -> Dict:
    """Load configuration from YAML and replace placeholders."""
    config_path = Path(__file__).parent.parent / "configurations" / "config.yml"
    try:
        config = yaml.safe_load(config_path.read_text())
        project_name = get_project_name()

        # Replace placeholders with actual values
        def replace_placeholders(obj):
            if isinstance(obj, str):
                return obj.replace('${PROJECT_NAME}', project_name)
            elif isinstance(obj, dict):
                return {k: replace_placeholders(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_placeholders(i) for i in obj]
            return obj

        return replace_placeholders(config)
    except Exception as e:
        raise DeploymentError(f"Failed to load config: {e}")

def cleanup_local_config() -> None:
    """Remove local EB CLI configuration."""
    config_dir = Path(__file__).parent.parent.parent / '.elasticbeanstalk'
    if config_dir.exists():
        shutil.rmtree(config_dir)
        print("Removed .elasticbeanstalk configuration directory")

@common.aws_handler
def cleanup_oidc(eb_client, elbv2_client, config: Dict) -> None:
    """Clean up OIDC authentication rules from ALB listener."""
    env_name = config['application']['environment']
    
    # Find load balancer first
    lb_arn = common.find_environment_load_balancer(eb_client, elbv2_client, env_name)
    if not lb_arn:
        return

    print("Checking for OIDC authentication rules...")
    
    # Find HTTPS listener
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
        https_listener = next((l for l in listeners if l['Port'] == 443), None)
        
        if not https_listener:
            print("No HTTPS listener found, skipping OIDC cleanup")
            return
        
        # Check for OIDC rules
        rules = elbv2_client.describe_rules(ListenerArn=https_listener['ListenerArn'])['Rules']
        oidc_rules = [r for r in rules if not r.get('IsDefault', False) and 
                      any(a.get('Type') == 'authenticate-oidc' for a in r.get('Actions', []))]
        
        if not oidc_rules:
            print("No OIDC authentication rules found")
            return
        
        print(f"Found {len(oidc_rules)} OIDC authentication rules, removing...")
        
        # Delete OIDC rules
        for rule in oidc_rules:
            print(f"Removing rule: {rule['RuleArn']}")
            elbv2_client.delete_rule(RuleArn=rule['RuleArn'])
        
        # Restore default action to forward traffic
        # Get target group
        target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
        if target_groups:
            target_group_arn = target_groups[0]['TargetGroupArn']
            print("Restoring default HTTPS listener action to forward traffic")
            elbv2_client.modify_listener(
                ListenerArn=https_listener['ListenerArn'],
                DefaultActions=[{
                    'Type': 'forward',
                    'TargetGroupArn': target_group_arn
                }]
            )
        
        print("OIDC authentication rules removed successfully")
        
    except ClientError as e:
        if e.response['Error']['Code'] not in ['LoadBalancerNotFound', 'ListenerNotFound']:
            raise

@common.aws_handler
def cleanup_https(eb_client, elbv2_client, r53_client, config: Dict, project_name: str) -> None:
    """Clean up HTTPS listener and DNS record if they exist."""
    env_name = config['application']['environment']
    
    # Find load balancer first
    lb_arn = common.find_environment_load_balancer(eb_client, elbv2_client, env_name)
    if not lb_arn:
        return

    # Check if HTTPS is enabled
    is_https_enabled, cert_arn = common.get_https_status(elbv2_client, lb_arn, project_name)
    if not is_https_enabled:
        return

    print("Found HTTPS configuration, cleaning up...")
    
    # Clean up HTTPS listener
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
        https_listener = next((l for l in listeners if l['Port'] == 443), None)
        if https_listener:
            print("Removing HTTPS listener")
            elbv2_client.delete_listener(ListenerArn=https_listener['ListenerArn'])
    except ClientError as e:
        if e.response['Error']['Code'] not in ['LoadBalancerNotFound', 'ListenerNotFound']:
            raise

    # Clean up DNS record
    try:
        if cert_arn:  # Only proceed if we have a certificate ARN
            # Get the domain from the certificate
            acm_client = boto3.client('acm')
            cert = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
            domain = cert['DomainName'].replace('*', project_name)
            
            # Get the load balancer DNS name
            lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
        zones = r53_client.list_hosted_zones()['HostedZones']
        zone = next((z for z in zones if domain.endswith(z['Name'].rstrip('.'))), None)
        
        if zone:
            records = r53_client.list_resource_record_sets(
                HostedZoneId=zone['Id'],
                StartRecordName=domain,
                StartRecordType='CNAME',
                MaxItems='1'
            )['ResourceRecordSets']
            
            record = next((r for r in records if r['Name'] == f"{domain}."), None)
            if record and record['ResourceRecords'][0]['Value'] == lb['DNSName']:
                print(f"Removing DNS record for {domain}")
                r53_client.change_resource_record_sets(
                    HostedZoneId=zone['Id'],
                    ChangeBatch={
                        'Changes': [{
                            'Action': 'DELETE',
                            'ResourceRecordSet': record
                        }]
                    }
                )
    except ClientError as e:
        if e.response['Error']['Code'] not in ['LoadBalancerNotFound', 'NoSuchHostedZone']:
            raise

@common.aws_handler
def cleanup_instance_profile(iam_client, config: Dict) -> None:
    """Clean up instance profile and role."""
    profile_name = config['iam']['instance_profile_name']
    role_name = config['iam']['instance_role_name']

    try:
        # Remove role from profile
        iam_client.remove_role_from_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name
        )
        print(f"Removed role from instance profile: {role_name}")

        # Delete profile
        iam_client.delete_instance_profile(InstanceProfileName=profile_name)
        print(f"Deleted instance profile: {profile_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise

    # Clean up the role
    common.manage_iam_role(
        iam_client,
        role_name,
        config['iam']['instance_role_policies'],
        action='cleanup'
    )

@common.aws_handler
def cleanup_s3_bucket(s3_client, config: Dict) -> None:
    """Clean up the application version S3 bucket."""
    bucket = f"elasticbeanstalk-{config['aws']['region']}-{config['application']['name'].lower()}"
    
    try:
        # Delete all objects
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(Bucket=bucket, Delete={'Objects': objects})
                print(f"Deleted {len(objects)} application versions from S3")

        # Delete bucket
        s3_client.delete_bucket(Bucket=bucket)
        print(f"Deleted S3 bucket: {bucket}")
    except ClientError as e:
        if e.response['Error']['Code'] not in ['NoSuchBucket', 'NoSuchKey']:
            raise

def cleanup_application(config: Dict) -> None:
    """Clean up all Elastic Beanstalk resources."""
    project_name = get_project_name()
    session = boto3.Session(region_name=config['aws']['region'])
    eb_client = session.client('elasticbeanstalk')
    elbv2_client = session.client('elbv2')
    r53_client = session.client('route53')
    env_name = config['application']['environment']

    # Clean up OIDC rules first (before we remove the HTTPS listener)
    cleanup_oidc(eb_client, elbv2_client, config)
    
    # Clean up HTTPS resources next
    cleanup_https(eb_client, elbv2_client, r53_client, config, project_name)

    # Terminate environment if it exists
    try:
        env_exists = bool(eb_client.describe_environments(
            EnvironmentNames=[env_name],
            IncludeDeleted=False
        )['Environments'])

        if env_exists:
            print(f"Terminating environment: {env_name}")
            eb_client.terminate_environment(EnvironmentName=env_name)
            common.wait_for_env_status(eb_client, env_name, 'Terminated')
    except ClientError:
        pass

    # Clean up shared resources if no other environments exist
    if not common.check_env_exists(eb_client):
        print("No active environments found, cleaning up resources...")
        
        iam_client = session.client('iam')
        cleanup_instance_profile(iam_client, config)
        common.manage_iam_role(
            iam_client,
            config['iam']['service_role_name'],
            config['iam']['service_role_policies'],
            action='cleanup'
        )
        
        cleanup_s3_bucket(session.client('s3'), config)

        try:
            eb_client.delete_application(
                ApplicationName=config['application']['name'],
                TerminateEnvByForce=True
            )
            print(f"Deleted application: {config['application']['name']}")
        except ClientError:
            pass
    else:
        print("Other environments still active. Skipping resource cleanup.")

    cleanup_local_config()
    print("Cleanup complete!")