# modules/common.py

"""Common utilities for Elastic Beanstalk deployment operations."""

import json
import time
import logging
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, Set, Optional, List, Callable, Tuple, Any
import boto3
from botocore.exceptions import ClientError

# Set up basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('deployment')

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
                error_message = f"AWS {code}: {e.response['Error']['Message']}"
                logger.error(error_message)
                raise DeploymentError(error_message)
    return wrapper

def load_policy(filename: str) -> Dict:
    """Load JSON policy file."""
    try:
        policy_path = Path(__file__).parent.parent / 'policies' / filename
        if not policy_path.exists():
            logger.error(f"Policy file not found: {policy_path}")
            raise DeploymentError(f"Policy file not found: {policy_path}")
            
        policy_content = policy_path.read_text()
        logger.debug(f"Loaded policy content from {filename}: {policy_content[:100]}...")
        policy = json.loads(policy_content)
        return policy
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in policy file {filename}: {e}")
        raise DeploymentError(f"Failed to parse JSON in {filename}: {e}")
    except Exception as e:
        logger.error(f"Failed to load {filename}: {e}")
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
            logger.info(f"Checking if role {role_name} exists")
            iam_client.get_role(RoleName=role_name)
            logger.info(f"Role {role_name} already exists, skipping creation")
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                raise

            logger.info(f"Creating role {role_name}")
            # Create role
            iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(load_policy(policies['trust_policy']))
            )
            logger.info(f"Role {role_name} created successfully")

        # Attach managed policies
        for arn in policies.get('managed_policies', []):
            logger.info(f"Attaching policy {arn} to role {role_name}")
            try:
                iam_client.attach_role_policy(RoleName=role_name, PolicyArn=arn)
                logger.info(f"Policy {arn} attached to role {role_name}")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    logger.error(f"Failed to attach policy {arn}: Policy not found")
                else:
                    raise

        # Handle custom policies
        account = boto3.client('sts').get_caller_identity()['Account']
        for policy_file in policies.get('custom_policies', []):
            name = f"{role_name}-{policy_file.replace('.json', '')}"
            policy_arn = f"arn:aws:iam::{account}:policy/{name}"
            
            # Load the policy document
            logger.info(f"Loading policy from {policy_file}")
            policy_doc = load_policy(policy_file)
            
            # Check if policy exists
            policy_exists = False
            try:
                response = iam_client.get_policy(PolicyArn=policy_arn)
                policy_exists = True
                logger.info(f"Policy {name} already exists with ARN: {policy_arn}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    logger.error(f"Error checking policy existence: {e}")
                    raise
                logger.info(f"Policy {name} does not exist, will create it")
            
            # Create policy if it doesn't exist
            if not policy_exists:
                try:
                    logger.info(f"Creating policy {name} from {policy_file}")
                    policy = iam_client.create_policy(
                        PolicyName=name,
                        PolicyDocument=json.dumps(policy_doc)
                    )
                    policy_arn = policy['Policy']['Arn']
                    logger.info(f"Created policy {name} with ARN: {policy_arn}")
                except ClientError as e:
                    if e.response['Error']['Code'] == 'EntityAlreadyExists':
                        logger.info(f"Policy {name} already exists, fetching ARN")
                        # If the policy exists but we couldn't fetch it earlier,
                        # try to list and find it
                        try:
                            policies_response = iam_client.list_policies(Scope='Local')
                            matching_policy = next(
                                (p for p in policies_response['Policies'] if p['PolicyName'] == name),
                                None
                            )
                            if matching_policy:
                                policy_arn = matching_policy['Arn']
                                logger.info(f"Found existing policy {name} with ARN: {policy_arn}")
                        except Exception as list_err:
                            logger.error(f"Error listing policies: {list_err}")
                    else:
                        logger.error(f"Failed to create policy {name}: {e}")
                        raise
            
            # Attach policy to role
            try:
                # Check if policy is already attached to avoid redundant operations
                attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                is_attached = any(p['PolicyArn'] == policy_arn for p in attached_policies['AttachedPolicies'])
                
                if not is_attached:
                    logger.info(f"Attaching policy {name} to role {role_name}")
                    iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                    logger.info(f"Attached policy {name} to role {role_name}")
                else:
                    logger.info(f"Policy {name} is already attached to role {role_name}")
            except ClientError as e:
                logger.error(f"Failed to attach policy {name} to role {role_name}: {e}")
                raise

        logger.info(f"Waiting for role {role_name} to be fully created and available")
        iam_client.get_waiter('role_exists').wait(RoleName=role_name)
        logger.info(f"Role {role_name} is ready")

    elif action == 'cleanup':
        logger.info(f"Cleaning up role {role_name}")
        # Detach and clean up policies
        account = boto3.client('sts').get_caller_identity()['Account']
        
        for arn in policies.get('managed_policies', []):
            try:
                logger.info(f"Detaching policy {arn} from role {role_name}")
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=arn)
                logger.info(f"Detached policy {arn} from role {role_name}")
            except ClientError as e:
                logger.warning(f"Error detaching policy {arn} from role {role_name}: {e}")
                continue

        for policy_file in policies.get('custom_policies', []):
            try:
                name = f"{role_name}-{policy_file.replace('.json', '')}"
                policy_arn = f"arn:aws:iam::{account}:policy/{name}"
                logger.info(f"Detaching and deleting policy {name}")
                iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
                logger.info(f"Detached policy {name} from role {role_name}")
                
                # Delete the policy
                iam_client.delete_policy(PolicyArn=policy_arn)
                logger.info(f"Deleted policy {name}")
            except ClientError as e:
                logger.warning(f"Error cleaning up policy {policy_file}: {e}")
                continue

        try:
            logger.info(f"Deleting role {role_name}")
            iam_client.delete_role(RoleName=role_name)
            logger.info(f"Deleted role {role_name}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'NoSuchEntity':
                logger.error(f"Error deleting role {role_name}: {e}")
                raise
            logger.info(f"Role {role_name} doesn't exist, skipping deletion")

# New HTTPS Management Functions

def get_resource_prefix(project_name: str) -> str:
    """Generate consistent prefix for resource tags."""
    return f"{project_name}:https"

@aws_handler
def get_https_status(elbv2_client, lb_arn: str, project_name: str) -> Tuple[bool, Optional[str]]:
    """
    Check if HTTPS is enabled and return status + certificate ARN.
    
    Args:
        elbv2_client: AWS elbv2 client
        lb_arn: Load balancer ARN
        project_name: Project name for tag prefix
    
    Returns:
        Tuple of (is_https_enabled, certificate_arn)
    """
    # Check load balancer tags
    tags = elbv2_client.describe_tags(
        ResourceArns=[lb_arn]
    )['TagDescriptions'][0]['Tags']
    
    prefix = get_resource_prefix(project_name)
    is_enabled = any(t['Key'] == f"{prefix}:enabled" and t['Value'].lower() == 'true' for t in tags)
    cert_arn = next((t['Value'] for t in tags if t['Key'] == f"{prefix}:certificate-arn"), None)
    
    return is_enabled, cert_arn

@aws_handler
def find_environment_load_balancer(eb_client, elbv2_client, env_name: str) -> Optional[str]:
    """
    Find the ALB ARN for an environment.
    
    Args:
        eb_client: AWS elastic beanstalk client
        elbv2_client: AWS elbv2 client
        env_name: Environment name
    
    Returns:
        Load balancer ARN if found, None otherwise
    """
    env = eb_client.describe_environments(
        EnvironmentNames=[env_name],
        IncludeDeleted=False
    )['Environments'][0]
    
    lbs = elbv2_client.describe_load_balancers()['LoadBalancers']
    for lb in lbs:
        if lb['Type'].lower() == 'application':
            tags = elbv2_client.describe_tags(
                ResourceArns=[lb['LoadBalancerArn']]
            )['TagDescriptions'][0]['Tags']
            
            if any(t['Key'] == 'elasticbeanstalk:environment-name' and 
                  t['Value'] == env_name for t in tags):
                return lb['LoadBalancerArn']
    
    return None

@aws_handler
def preserve_https_config(elbv2_client, lb_arn: str, project_name: str) -> Optional[Dict[str, Any]]:
    """
    Capture existing HTTPS configuration for preservation.
    
    Args:
        elbv2_client: AWS elbv2 client
        lb_arn: Load balancer ARN
        project_name: Project name for tag prefix
    
    Returns:
        Dict containing HTTPS configuration if enabled, None otherwise
    """
    is_enabled, cert_arn = get_https_status(elbv2_client, lb_arn, project_name)
    if not is_enabled:
        return None
        
    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
    https_listener = next((l for l in listeners if l['Port'] == 443), None)
    
    if not https_listener:
        return None
        
    return {
        'certificate_arn': cert_arn,
        'ssl_policy': https_listener['SslPolicy'],
        'default_actions': https_listener['DefaultActions']
    }

@aws_handler
def setup_https_listener(
    elbv2_client, 
    lb_arn: str, 
    cert_arn: str, 
    project_name: str,
    ssl_policy: str = 'ELBSecurityPolicy-2016-08'
) -> None:
    """
    Create or update HTTPS listener with proper configuration.
    
    Args:
        elbv2_client: AWS elbv2 client
        lb_arn: Load balancer ARN
        cert_arn: Certificate ARN
        project_name: Project name for tag prefix
        ssl_policy: SSL policy name
    """
    # Get HTTP listener for default actions
    listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
    http_listener = next((l for l in listeners if l['Port'] == 80), None)
    if not http_listener:
        raise DeploymentError("No HTTP listener found")
    
    # Check if HTTPS listener exists
    https_listener = next((l for l in listeners if l['Port'] == 443), None)
    
    if https_listener:
        # Update existing listener
        elbv2_client.modify_listener(
            ListenerArn=https_listener['ListenerArn'],
            Certificates=[{'CertificateArn': cert_arn}],
            SslPolicy=ssl_policy
        )
    else:
        # Create new listener
        elbv2_client.create_listener(
            LoadBalancerArn=lb_arn,
            Protocol='HTTPS',
            Port=443,
            Certificates=[{'CertificateArn': cert_arn}],
            SslPolicy=ssl_policy,
            DefaultActions=http_listener['DefaultActions']
        )
    
    # Update tags
    prefix = get_resource_prefix(project_name)
    elbv2_client.add_tags(
        ResourceArns=[lb_arn],
        Tags=[
            {'Key': f"{prefix}:enabled", 'Value': 'true'},
            {'Key': f"{prefix}:certificate-arn", 'Value': cert_arn}
        ]
    )

@aws_handler
def restore_https_config(elbv2_client, lb_arn: str, config: Dict[str, Any], project_name: str) -> None:
    """
    Restore HTTPS configuration after environment update.
    
    Args:
        elbv2_client: AWS elbv2 client
        lb_arn: Load balancer ARN
        config: HTTPS configuration dict from preserve_https_config
        project_name: Project name for tag prefix
    """
    if not config:
        return
        
    setup_https_listener(
        elbv2_client,
        lb_arn,
        config['certificate_arn'],
        project_name,
        config['ssl_policy']
    )