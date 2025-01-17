"""
Handles cleanup of Elastic Beanstalk environment and associated AWS resources.
"""

import shutil
import time
from pathlib import Path
from typing import Dict, Any
import boto3
from botocore.exceptions import ClientError

from . import common

@common.aws_handler
def cleanup_instance_profile(iam_client, config: Dict[str, Any]) -> None:
    """Clean up instance profile and its associated role."""
    profile_name = config['iam']['instance_profile_name']
    role_name = config['iam']['instance_role_name']
    
    try:
        # First remove role from profile
        iam_client.remove_role_from_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name
        )
        print(f"Removed role from instance profile: {role_name}")
        
        # Then delete the profile
        iam_client.delete_instance_profile(InstanceProfileName=profile_name)
        print(f"Deleted instance profile: {profile_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise
    
    # Finally cleanup the role and its policies
    common.handle_iam_role(iam_client, role_name, config['iam']['instance_role_policies'], action='cleanup')

@common.aws_handler
def cleanup_s3_bucket(s3_client, config: Dict[str, Any]) -> None:
    """Clean up the S3 bucket used for application versions."""
    bucket_name = f"elasticbeanstalk-{config['aws']['region']}-{config['application']['name'].lower()}"
    
    try:
        # Delete all objects first
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects})
                print(f"Deleted {len(objects)} application versions from S3")
        
        # Then delete the bucket
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"Deleted S3 bucket: {bucket_name}")
    except ClientError as e:
        if e.response['Error']['Code'] not in ['NoSuchBucket', 'NoSuchKey']:
            raise

def cleanup_eb_config() -> None:
    """Remove the .elasticbeanstalk directory."""
    config_dir = Path(__file__).parent.parent.parent / '.elasticbeanstalk'
    if config_dir.exists():
        shutil.rmtree(config_dir)
        print("Removed .elasticbeanstalk configuration directory")

def wait_for_termination(eb_client, env_name: str) -> None:
    """Wait for environment to be fully terminated."""
    print(f"Waiting for environment {env_name} to be terminated...")
    last_event_time = None
    seen_events = set()
    
    while True:
        try:
            response = eb_client.describe_environments(
                EnvironmentNames=[env_name],
                IncludeDeleted=False
            )
            
            if not response['Environments']:
                break
            
            env = response['Environments'][0]
            status = env['Status']
            
            last_event_time = common.log_events(eb_client, env_name, last_event_time, seen_events)
            if status not in ['Terminating', 'Ready']:
                break
                
        except ClientError:
            break
            
        time.sleep(5)

def cleanup_application(config: Dict[str, Any]) -> None:
    """Clean up the Elastic Beanstalk environment and associated resources."""
    session = boto3.Session(region_name=config['aws']['region'])
    eb_client = session.client('elasticbeanstalk')
    iam_client = session.client('iam')
    s3_client = session.client('s3')
    
    env_name = config['application']['environment']
    
    # First terminate the environment if it exists
    try:
        response = eb_client.describe_environments(
            EnvironmentNames=[env_name],
            IncludeDeleted=False
        )
        if response['Environments']:
            print(f"Terminating environment: {env_name}")
            eb_client.terminate_environment(EnvironmentName=env_name)
            wait_for_termination(eb_client, env_name)
        else:
            print(f"Environment {env_name} does not exist or is already terminated")
    except ClientError:
        print(f"Environment {env_name} does not exist")
    
    # Check if we can clean up shared resources
    if not common.check_eb_resources(eb_client):
        print("No active environments found, proceeding with resource cleanup...")
        
        # Clean up instance profile and its role
        cleanup_instance_profile(iam_client, config)
        
        # Clean up service role
        common.handle_iam_role(
            iam_client,
            config['iam']['service_role_name'],
            config['iam']['service_role_policies'],
            action='cleanup'
        )
        
        # Clean up S3 bucket
        cleanup_s3_bucket(s3_client, config)
        
        try:
            # Clean up the application itself
            eb_client.delete_application(
                ApplicationName=config['application']['name'],
                TerminateEnvByForce=True
            )
            print(f"Deleted application: {config['application']['name']}")
        except ClientError:
            pass
    else:
        print("Other environments are still active. Skipping resource cleanup.")
    
    # Clean up local EB CLI configuration
    cleanup_eb_config()
    
    print("Cleanup complete!")