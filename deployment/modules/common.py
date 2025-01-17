"""Common utilities for Elastic Beanstalk deployment operations."""

import json
import time
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, Set, Optional, List, Callable
import boto3
from botocore.exceptions import ClientError

class DeploymentError(Exception):
    """Base exception for deployment operations."""
    pass

def aws_handler(func: Callable) -> Callable:
    """Decorator to handle AWS API errors."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            code = e.response['Error']['Code']
            if code not in ['NoSuchEntity', 'NoSuchBucket', 'NoSuchKey']:
                raise DeploymentError(f"AWS {code}: {e.response['Error']['Message']}")
    return wrapper

def load_policy(filename: str) -> Dict:
    """Load JSON policy file."""
    try:
        return json.loads((Path(__file__).parent.parent / 'policies' / filename).read_text())
    except Exception as e:
        raise DeploymentError(f"Failed to load {filename}: {e}")

def print_events(eb_client, env_name: str, after: Optional[datetime], seen: Set[str]) -> datetime:
    """Print and track new environment events."""
    kwargs = {'EnvironmentName': env_name, 'MaxRecords': 10}
    if after:
        kwargs['StartTime'] = after

    for event in reversed(eb_client.describe_events(**kwargs).get('Events', [])):
        key = f"{event['EventDate'].isoformat()}-{event['Message']}"
        if key not in seen:
            print(f"{event['EventDate']:%Y-%m-%d %H:%M:%S} {event['Severity']}: {event['Message']}")
            seen.add(key)
            after = event['EventDate']
    
    return after

def wait_for_env_status(eb_client, env_name: str, target: str) -> None:
    """Wait for environment to reach target status."""
    print(f"Waiting for environment to be {target}...")
    last_time, seen = None, set()
    
    while True:
        try:
            envs = eb_client.describe_environments(
                EnvironmentNames=[env_name],
                IncludeDeleted=False
            )['Environments']
            
            if not envs:
                if target == 'Terminated':
                    break
                raise DeploymentError(f"Environment {env_name} not found")
            
            status = envs[0]['Status']
            last_time = print_events(eb_client, env_name, last_time, seen)
            
            if status == target:
                break
            if status == 'Failed':
                raise DeploymentError(f"Environment failed to reach {target} status")
                
        except ClientError as e:
            if target == 'Terminated' and e.response['Error']['Code'] == 'ResourceNotFoundException':
                break
            raise
            
        time.sleep(5)

def check_env_exists(eb_client) -> bool:
    """Check if any environments exist."""
    return bool(eb_client.describe_environments(IncludeDeleted=False)['Environments'])

def get_env_settings(config: Dict) -> List[Dict[str, str]]:
    """Get environment settings from config."""
    return [
        {
            'Namespace': 'aws:autoscaling:launchconfiguration',
            'OptionName': 'IamInstanceProfile',
            'Value': config['iam']['instance_profile_name']
        },
        {
            'Namespace': 'aws:elasticbeanstalk:environment',
            'OptionName': 'ServiceRole',
            'Value': config['iam']['service_role_name']
        },
        {
            'Namespace': 'aws:autoscaling:launchconfiguration',
            'OptionName': 'InstanceType',
            'Value': config['instance']['type']
        },
        {
            'Namespace': 'aws:autoscaling:asg',
            'OptionName': 'MinSize',
            'Value': str(config['instance']['autoscaling']['min_instances'])
        },
        {
            'Namespace': 'aws:autoscaling:asg',
            'OptionName': 'MaxSize',
            'Value': str(config['instance']['autoscaling']['max_instances'])
        }
    ]

@aws_handler
def manage_iam_role(iam_client, role_name: str, policies: Dict, action: str = 'create') -> None:
    """Create or clean up IAM role and policies."""
    if action == 'create':
        try:
            iam_client.get_role(RoleName=role_name)
            return
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise

        # Create role
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(load_policy(policies['trust_policy']))
        )

        # Attach policies
        for arn in policies.get('managed_policies', []):
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=arn)

        # Handle custom policies
        account = boto3.client('sts').get_caller_identity()['Account']
        for policy_file in policies.get('custom_policies', []):
            name = f"{role_name}-{policy_file.replace('.json', '')}"
            arn = f"arn:aws:iam::{account}:policy/{name}"
            
            try:
                policy = iam_client.create_policy(
                    PolicyName=name,
                    PolicyDocument=json.dumps(load_policy(policy_file))
                )
                arn = policy['Policy']['Arn']
            except ClientError as e:
                if e.response['Error']['Code'] != 'EntityAlreadyExists':
                    raise
            
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=arn)

        iam_client.get_waiter('role_exists').wait(RoleName=role_name)

    elif action == 'cleanup':
        # Detach and clean up policies
        account = boto3.client('sts').get_caller_identity()['Account']
        
        for arn in policies.get('managed_policies', []):
            try:
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError:
                continue

        for policy_file in policies.get('custom_policies', []):
            try:
                name = f"{role_name}-{policy_file.replace('.json', '')}"
                arn = f"arn:aws:iam::{account}:policy/{name}"
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=arn)
                iam_client.delete_policy(PolicyArn=arn)
            except ClientError:
                continue

        try:
            iam_client.delete_role(RoleName=role_name)
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise