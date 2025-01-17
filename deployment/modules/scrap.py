"""Clean up Elastic Beanstalk environment and associated resources."""

import shutil
from pathlib import Path
from typing import Dict
import boto3
from botocore.exceptions import ClientError
import yaml

from . import common

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
        raise common.DeploymentError(f"Failed to load config: {e}")

def cleanup_local_config() -> None:
    """Remove local EB CLI configuration."""
    config_dir = Path(__file__).parent.parent.parent / '.elasticbeanstalk'
    if config_dir.exists():
        shutil.rmtree(config_dir)
        print("Removed .elasticbeanstalk configuration directory")

@common.aws_handler
def cleanup_https(config: Dict) -> None:
    """Clean up HTTPS listener and DNS record."""
    session = boto3.Session(region_name=config['aws']['region'])
    elbv2_client = session.client('elbv2')
    route53_client = session.client('route53')
    
    try:
        # Find and remove DNS record first (don't rely on load balancer existing)
        domain = f"{config['application']['name']}.basileaw.people.aws.dev"
        zones = route53_client.list_hosted_zones()['HostedZones']
        zone = next((z for z in zones if domain.endswith(z['Name'].rstrip('.'))), None)
        
        if zone:
            try:
                # First get the existing record
                records = route53_client.list_resource_record_sets(
                    HostedZoneId=zone['Id'],
                    StartRecordName=domain,
                    StartRecordType='CNAME',
                    MaxItems='1'
                )['ResourceRecordSets']
                
                record = next((r for r in records if r['Name'] == f"{domain}."), None)
                if record:
                    print(f"Removing DNS record for {domain}")
                    route53_client.change_resource_record_sets(
                        HostedZoneId=zone['Id'],
                        ChangeBatch={
                            'Changes': [{
                                'Action': 'DELETE',
                                'ResourceRecordSet': record
                            }]
                        }
                    )
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidChangeBatch':
                    raise

        # Find and remove HTTPS listener if load balancer still exists
        env_name = config['application']['environment']
        load_balancers = elbv2_client.describe_load_balancers()['LoadBalancers']
        
        lb_arn = None
        for lb in load_balancers:
            if lb['Type'].lower() == 'application':
                tags = elbv2_client.describe_tags(ResourceArns=[lb['LoadBalancerArn']])['TagDescriptions'][0]['Tags']
                if any(t['Key'] == 'elasticbeanstalk:environment-name' and t['Value'] == env_name for t in tags):
                    lb_arn = lb['LoadBalancerArn']
                    break

        if lb_arn:
            listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
            https_listener = next((l for l in listeners if l['Port'] == 443), None)
            
            if https_listener:
                print("Removing HTTPS listener")
                elbv2_client.delete_listener(ListenerArn=https_listener['ListenerArn'])

    except ClientError as e:
        if e.response['Error']['Code'] not in ['LoadBalancerNotFound', 'ListenerNotFound']:
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
    session = boto3.Session(region_name=config['aws']['region'])
    eb_client = session.client('elasticbeanstalk')
    env_name = config['application']['environment']

    # Clean up HTTPS resources first
    cleanup_https(config)

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
