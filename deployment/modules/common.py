"""
Common utilities for Elastic Beanstalk deployment and cleanup operations.
"""

import json
import time
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, Any, Set, Optional, List, Callable
import boto3
from botocore.exceptions import ClientError

class DeploymentError(Exception):
    """Base exception for deployment operations."""
    pass

def aws_handler(func: Callable) -> Callable:
    """Handle AWS API calls and provide meaningful errors."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code not in ['NoSuchEntity', 'NoSuchBucket', 'NoSuchKey']:
                raise DeploymentError(f"AWS {error_code}: {e.response['Error']['Message']}")
    return wrapper

def load_policy_file(filename: str) -> Dict:
    """Load and parse a JSON policy file from the policies directory."""
    try:
        return json.loads((Path(__file__).parent.parent / 'policies' / filename).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise DeploymentError(f"Failed to load {filename}: {str(e)}")

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

def wait_for_environment(eb_client, env_name: str, target_status: str) -> None:
    """Wait for environment to reach target status."""
    print(f"Waiting for environment to be {target_status}...")
    last_event_time = None
    seen_events = set()
    
    while True:
        try:
            envs = eb_client.describe_environments(
                EnvironmentNames=[env_name],
                IncludeDeleted=False
            )['Environments']
            
            if not envs:
                raise DeploymentError(f"Environment {env_name} not found")
            
            status = envs[0]['Status']
            last_event_time = log_events(eb_client, env_name, last_event_time, seen_events)
            
            if status == target_status:
                break
            elif status == 'Failed':
                raise DeploymentError(f"Environment {env_name} failed to reach {target_status} status")
                
        except ClientError as e:
            if target_status == 'Terminated' and e.response['Error']['Code'] == 'ResourceNotFoundException':
                break
            raise
            
        time.sleep(5)

@aws_handler
def handle_iam_role(iam_client, role_name: str, policies_config: Dict, action: str = 'create') -> None:
    """Handle IAM role creation or cleanup."""
    if action == 'create':
        try:
            iam_client.get_role(RoleName=role_name)
            return
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise

        # Create role with trust policy
        iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(load_policy_file(policies_config['trust_policy']))
        )

        # Attach managed policies
        for arn in policies_config.get('managed_policies', []):
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=arn)

        # Create and attach custom policies
        account_id = boto3.client('sts').get_caller_identity()['Account']
        for policy_file in policies_config.get('custom_policies', []):
            policy_name = f"{role_name}-{policy_file.replace('.json', '')}"
            
            try:
                response = iam_client.create_policy(
                    PolicyName=policy_name,
                    PolicyDocument=json.dumps(load_policy_file(policy_file))
                )
                policy_arn = response['Policy']['Arn']
            except ClientError as e:
                if e.response['Error']['Code'] == 'EntityAlreadyExists':
                    policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
                else:
                    raise
            
            iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

        iam_client.get_waiter('role_exists').wait(RoleName=role_name)

    elif action == 'cleanup':
        # Detach and cleanup managed policies
        for arn in policies_config.get('managed_policies', []):
            try:
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=arn)
                print(f"Detached managed policy: {arn}")
            except ClientError:
                pass

        # Find, detach, and delete custom policies
        account_id = boto3.client('sts').get_caller_identity()['Account']
        for policy_file in policies_config.get('custom_policies', []):
            policy_name = f"{role_name}-{policy_file.replace('.json', '')}"
            policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
            
            try:
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                iam_client.delete_policy(PolicyArn=policy_arn)
                print(f"Cleaned up custom policy: {policy_name}")
            except ClientError:
                pass

        # Delete the role
        try:
            iam_client.delete_role(RoleName=role_name)
            print(f"Deleted role: {role_name}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise

def check_eb_resources(eb_client) -> bool:
    """Check if any environments exist that might be using our resources."""
    response = eb_client.describe_environments(IncludeDeleted=False)
    return len(response['Environments']) > 0

def get_environment_settings(config: Dict[str, Any]) -> List[Dict[str, str]]:
    """Get common environment settings for creation/updates."""
    settings = [
        {'Namespace': 'aws:autoscaling:launchconfiguration',
         'OptionName': 'IamInstanceProfile',
         'Value': config['iam']['instance_profile_name']},
        {'Namespace': 'aws:elasticbeanstalk:environment',
         'OptionName': 'ServiceRole',
         'Value': config['iam']['service_role_name']},
        {'Namespace': 'aws:autoscaling:launchconfiguration',
         'OptionName': 'InstanceType',
         'Value': config['instance']['type']},
        {'Namespace': 'aws:autoscaling:asg',
         'OptionName': 'MinSize',
         'Value': str(config['instance']['autoscaling']['min_instances'])},
        {'Namespace': 'aws:autoscaling:asg',
         'OptionName': 'MaxSize',
         'Value': str(config['instance']['autoscaling']['max_instances'])}
    ]
    return settings