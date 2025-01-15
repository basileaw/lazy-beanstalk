"""
Handles cleanup of Elastic Beanstalk environment and associated AWS resources.
"""

import time
import shutil
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, Any, Set, Optional, List
import boto3
from botocore.exceptions import ClientError

class CleanupError(Exception):
    """Custom exception for cleanup errors."""
    pass

def aws_handler(func):
    """Handle AWS API calls and provide meaningful errors."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code not in ['NoSuchEntity', 'NoSuchBucket', 'NoSuchKey']:
                raise CleanupError(f"AWS {error_code}: {e.response['Error']['Message']}")
    return wrapper

def log_events(eb_client, env_name: str, last_event_time: Optional[datetime], seen_events: Set[str]) -> datetime:
    """Get and log new environment events."""
    kwargs = {'EnvironmentName': env_name, 'MaxRecords': 10}
    if last_event_time:
        kwargs['StartTime'] = last_event_time

    for event in reversed(eb_client.describe_events(**kwargs).get('Events', [])):
        event_key = f"{event['EventDate'].isoformat()}-{event['Message']}"
        if event_key not in seen_events:
            print(f"{event['EventDate']:%Y-%m-%d %H:%M:%S} {event['Severity']}: {event['Message']}")
            seen_events.add(event_key)
            last_event_time = event['EventDate']
    
    return last_event_time

def wait_for_environment_termination(eb_client, env_name: str) -> None:
    """Wait for environment to be terminated with detailed event logging."""
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
            
            last_event_time = log_events(eb_client, env_name, last_event_time, seen_events)
            if status not in ['Terminating', 'Ready']:
                break
                
        except ClientError:
            break
            
        time.sleep(5)

@aws_handler
def cleanup_role_policies(iam_client, role_name: str, policies_config: Dict) -> None:
    """Clean up policies attached to a role."""
    # Detach managed policies
    for arn in policies_config.get('managed_policies', []):
        try:
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            print(f"Detached managed policy: {arn}")
        except ClientError:
            pass

    # Find and delete custom policies
    account_id = boto3.client('sts').get_caller_identity()['Account']
    for policy_file in policies_config.get('custom_policies', []):
        policy_name = f"{role_name}-{policy_file.replace('.json', '')}"
        policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
        
        try:
            # First detach the policy
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
            print(f"Detached custom policy: {policy_name}")
            
            # Then delete the policy
            iam_client.delete_policy(PolicyArn=policy_arn)
            print(f"Deleted custom policy: {policy_name}")
        except ClientError:
            pass

@aws_handler
def cleanup_role(iam_client, role_name: str, policies_config: Dict) -> None:
    """Clean up an IAM role and its policies."""
    try:
        # First cleanup all policies
        cleanup_role_policies(iam_client, role_name, policies_config)
        
        # Then delete the role
        iam_client.delete_role(RoleName=role_name)
        print(f"Deleted role: {role_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise

@aws_handler
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
    
    # Finally cleanup the role
    cleanup_role(iam_client, role_name, config['iam']['instance_role_policies'])

@aws_handler
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

def check_resources_in_use(eb_client) -> bool:
    """Check if any environments exist that might be using our resources."""
    response = eb_client.describe_environments(IncludeDeleted=False)
    return len(response['Environments']) > 0

def cleanup_eb_config() -> None:
    """Remove the .elasticbeanstalk directory."""
    config_dir = Path(__file__).parent.parent.parent / '.elasticbeanstalk'
    if config_dir.exists():
        shutil.rmtree(config_dir)
        print("Removed .elasticbeanstalk configuration directory")

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
            wait_for_environment_termination(eb_client, env_name)
        else:
            print(f"Environment {env_name} does not exist or is already terminated")
    except ClientError:
        print(f"Environment {env_name} does not exist")
    
    # Check if we can clean up shared resources
    if not check_resources_in_use(eb_client):
        print("No active environments found, proceeding with resource cleanup...")
        
        # Clean up instance profile and its role
        cleanup_instance_profile(iam_client, config)
        
        # Clean up service role
        cleanup_role(
            iam_client,
            config['iam']['service_role_name'],
            config['iam']['service_role_policies']
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