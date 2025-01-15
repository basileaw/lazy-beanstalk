"""
Handles cleanup of Elastic Beanstalk environment and associated AWS resources.
"""

import os
import time
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Set
import boto3
from botocore.exceptions import ClientError

def get_environment_events(eb_client, env_name: str, start_time=None) -> list:
    """Get environment events since the start time."""
    kwargs = {
        'EnvironmentName': env_name,
        'MaxRecords': 10
    }
    if start_time:
        kwargs['StartTime'] = start_time
    
    response = eb_client.describe_events(**kwargs)
    return response.get('Events', [])

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
            
            events = get_environment_events(eb_client, env_name, last_event_time)
            for event in reversed(events):
                event_key = f"{event['EventDate'].isoformat()}-{event['Message']}"
                if event_key not in seen_events:
                    print(f"{event['EventDate'].strftime('%Y-%m-%d %H:%M:%S')} {event['Severity']}: {event['Message']}")
                    seen_events.add(event_key)
                    if last_event_time is None or event['EventDate'] > last_event_time:
                        last_event_time = event['EventDate']
            
            if status not in ['Terminating', 'Ready']:
                break
                
        except ClientError:
            break
            
        time.sleep(5)

def check_environment_exists(eb_client, env_name: str) -> bool:
    """Check if an Elastic Beanstalk environment exists."""
    try:
        response = eb_client.describe_environments(
            EnvironmentNames=[env_name],
            IncludeDeleted=False
        )
        return len(response['Environments']) > 0
    except ClientError:
        return False

def check_resources_in_use(eb_client) -> bool:
    """Check if any environments still exist that might be using our resources."""
    response = eb_client.describe_environments(IncludeDeleted=False)
    return len(response['Environments']) > 0

def is_policy_arn(policy: str) -> bool:
    """Check if the policy is an ARN or a local file path."""
    return policy.startswith('arn:')

def cleanup_service_role(iam_client, config: Dict[str, Any]) -> None:
    """Clean up the Elastic Beanstalk service role."""
    role_name = config['iam']['service_role_name']
    print(f"Cleaning up service role {role_name}...")
    
    try:
        # Get attached policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        
        # Detach policies
        for policy in config['iam']['service_role_policies']:
            try:
                if is_policy_arn(policy):
                    # Handle managed policy
                    iam_client.detach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy
                    )
                    print(f"Detached managed policy: {policy}")
                else:
                    # Handle custom policy - first find its name from attached policies
                    policy_name = Path(policy).stem  # Get filename without extension
                    for attached_policy in attached_policies['AttachedPolicies']:
                        if attached_policy['PolicyName'] == policy_name:
                            iam_client.detach_role_policy(
                                RoleName=role_name,
                                PolicyArn=attached_policy['PolicyArn']
                            )
                            print(f"Detached custom policy: {policy_name}")
                            
                            # Delete the custom policy
                            iam_client.delete_policy(
                                PolicyArn=attached_policy['PolicyArn']
                            )
                            print(f"Deleted custom policy: {policy_name}")
            except ClientError as e:
                print(f"Warning: Failed to detach policy {policy}: {e}")
        
        # Delete role
        iam_client.delete_role(RoleName=role_name)
        print(f"Deleted role: {role_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise

def cleanup_instance_profile(iam_client, config: Dict[str, Any]) -> None:
    """Clean up the EC2 instance profile and role."""
    profile_name = config['iam']['instance_profile_name']
    role_name = config['iam']['instance_role_name']
    
    print(f"Cleaning up instance profile {profile_name}...")
    
    try:
        # Remove role from instance profile
        try:
            iam_client.remove_role_from_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
            print(f"Removed role from instance profile: {role_name}")
        except ClientError:
            pass
        
        # Delete instance profile
        iam_client.delete_instance_profile(
            InstanceProfileName=profile_name
        )
        print(f"Deleted instance profile: {profile_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise
    
    print(f"Cleaning up instance role {role_name}...")
    try:
        # Get attached policies
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
        
        # Detach policies
        for policy in config['iam']['instance_role_policies']:
            try:
                if is_policy_arn(policy):
                    # Handle managed policy
                    iam_client.detach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy
                    )
                    print(f"Detached managed policy: {policy}")
                else:
                    # Handle custom policy
                    policy_name = Path(policy).stem
                    for attached_policy in attached_policies['AttachedPolicies']:
                        if attached_policy['PolicyName'] == policy_name:
                            iam_client.detach_role_policy(
                                RoleName=role_name,
                                PolicyArn=attached_policy['PolicyArn']
                            )
                            print(f"Detached custom policy: {policy_name}")
                            
                            # Delete the custom policy
                            iam_client.delete_policy(
                                PolicyArn=attached_policy['PolicyArn']
                            )
                            print(f"Deleted custom policy: {policy_name}")
            except ClientError as e:
                print(f"Warning: Failed to detach policy {policy}: {e}")
        
        # Delete instance role
        iam_client.delete_role(RoleName=role_name)
        print(f"Deleted role: {role_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise

def cleanup_s3_bucket(s3_client, config: Dict[str, Any]) -> None:
    """Clean up the S3 bucket used for application versions."""
    app_name = config['application']['name']
    bucket_name = f"elasticbeanstalk-{config['aws']['region']}-{app_name.lower()}"
    
    try:
        # First, delete all objects in the bucket
        print(f"Cleaning up S3 bucket: {bucket_name}")
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': objects}
                )
                print(f"Deleted {len(objects)} application versions from S3")
        
        # Then delete the bucket itself
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"Deleted S3 bucket: {bucket_name}")
    except ClientError as e:
        if e.response['Error']['Code'] not in ['NoSuchBucket', 'NoSuchKey']:
            raise

def cleanup_eb_config() -> None:
    """Remove the .elasticbeanstalk directory."""
    project_root = Path(__file__).parent.parent.parent
    eb_dir = project_root / '.elasticbeanstalk'
    if eb_dir.exists():
        shutil.rmtree(eb_dir)
        print("Removed .elasticbeanstalk configuration directory")

def cleanup_application(config: Dict[str, Any]) -> None:
    """
    Clean up the Elastic Beanstalk environment and associated resources.
    """
    session = boto3.Session(region_name=config['aws']['region'])
    iam_client = session.client('iam')
    eb_client = session.client('elasticbeanstalk')
    s3_client = session.client('s3')
    
    env_name = config['application']['environment']
    
    # Check and terminate environment if it exists
    if check_environment_exists(eb_client, env_name):
        print(f"Terminating environment: {env_name}")
        eb_client.terminate_environment(EnvironmentName=env_name)
        wait_for_environment_termination(eb_client, env_name)
    else:
        print(f"Environment {env_name} does not exist or is already terminated")
    
    # Check if we can clean up resources
    if not check_resources_in_use(eb_client):
        print("No active environments found, proceeding with resource cleanup...")
        cleanup_service_role(iam_client, config)
        cleanup_instance_profile(iam_client, config)
        cleanup_s3_bucket(s3_client, config)
    else:
        print("Other environments are still active. Skipping resource cleanup.")
    
    # Clean up local EB CLI configuration
    cleanup_eb_config()
    
    print("Cleanup complete!")