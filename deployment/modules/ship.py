"""
Handles deployment of Elastic Beanstalk application and associated AWS resources.
"""

import json
import os
import tempfile
import zipfile
import time
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Dict, Any, Set, Optional
import boto3
import yaml
from botocore.exceptions import ClientError

class DeployError(Exception):
    """Custom exception for deployment errors."""
    pass

def aws_handler(func):
    """Handle AWS API calls and provide meaningful errors."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code not in ['NoSuchEntity', 'NoSuchBucket']:
                raise DeployError(f"AWS {error_code}: {e.response['Error']['Message']}")
    return wrapper

def load_json_file(filename: str) -> Dict:
    """Load and parse a JSON file from the policies directory."""
    try:
        return json.loads((Path(__file__).parent.parent / 'policies' / filename).read_text())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        raise DeployError(f"Failed to load {filename}: {str(e)}")

def create_app_bundle() -> str:
    """Create a ZIP archive of application files based on .ebignore."""
    project_root = Path(__file__).parent.parent.parent
    include_patterns = {
        line[1:].strip() for line in (project_root / '.ebignore').read_text().splitlines()
        if line.strip() and not line.startswith('#') and line.startswith('!')
    }
    
    bundle_path = Path(tempfile.gettempdir()) / f'app_bundle_{datetime.now():%Y%m%d_%H%M%S}.zip'
    with zipfile.ZipFile(bundle_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for pattern in include_patterns:
            for path in project_root.glob(pattern.rstrip('/') + '/**/*' if pattern.endswith('/') else pattern):
                if path.is_file():
                    zipf.write(path, path.relative_to(project_root))
    return str(bundle_path)

@aws_handler
def setup_iam_role(iam_client, role_name: str, policies_config: Dict) -> None:
    """Create or update an IAM role with specified policies."""
    try:
        iam_client.get_role(RoleName=role_name)
        return
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            raise

    # Create role with trust policy from config
    iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(load_json_file(policies_config['trust_policy']))
    )

    # Attach managed policies
    for arn in policies_config.get('managed_policies', []):
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    # Create and attach custom policies
    account_id = boto3.client('sts').get_caller_identity()['Account']
    for policy_file in policies_config.get('custom_policies', []):
        policy_name = f"{role_name}-{policy_file.replace('.json', '')}"
        policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
        
        try:
            response = iam_client.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(load_json_file(policy_file))
            )
            policy_arn = response['Policy']['Arn']
        except ClientError as e:
            if e.response['Error']['Code'] != 'EntityAlreadyExists':
                raise
        
        iam_client.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    iam_client.get_waiter('role_exists').wait(RoleName=role_name)

@aws_handler
def ensure_instance_profile(iam_client, config: Dict[str, Any]) -> None:
    """Set up instance profile and its associated role."""
    profile_name = config['iam']['instance_profile_name']
    role_name = config['iam']['instance_role_name']
    
    # Set up the role first using policies from config
    setup_iam_role(iam_client, role_name, config['iam']['instance_role_policies'])
    
    # Create or update instance profile
    profile_exists = True
    try:
        profile = iam_client.get_instance_profile(InstanceProfileName=profile_name)
        # Check if role is attached
        roles = profile['InstanceProfile'].get('Roles', [])
        if not roles or roles[0]['RoleName'] != role_name:
            # Remove any existing roles
            for existing_role in roles:
                iam_client.remove_role_from_instance_profile(
                    InstanceProfileName=profile_name,
                    RoleName=existing_role['RoleName']
                )
            # Add our role
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            profile_exists = False
            iam_client.create_instance_profile(InstanceProfileName=profile_name)
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
        else:
            raise
    
    # Allow time for profile/role association to propagate
    if not profile_exists:
        time.sleep(10)

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

def wait_for_env(eb_client, env_name: str, target_status: str) -> None:
    """Wait for environment to reach target status."""
    print(f"Waiting for environment to be {target_status}...")
    last_event_time = None
    seen_events = set()
    
    while True:
        envs = eb_client.describe_environments(
            EnvironmentNames=[env_name],
            IncludeDeleted=False
        )['Environments']
        
        if not envs:
            raise DeployError(f"Environment {env_name} not found")
        
        last_event_time = log_events(eb_client, env_name, last_event_time, seen_events)
        if envs[0]['Status'] == target_status:
            break
        time.sleep(5)

def wait_for_version(eb_client, app_name: str, version: str) -> None:
    """Wait for application version to be processed."""
    print("Waiting for application version to be processed...")
    while True:
        versions = eb_client.describe_application_versions(
            ApplicationName=app_name,
            VersionLabels=[version]
        )['ApplicationVersions']
        
        if not versions:
            raise DeployError(f"Version {version} not found")
        
        status = versions[0]['Status']
        print(f"Version status: {status}")
        
        if status == 'PROCESSED':
            break
        elif status == 'FAILED':
            raise DeployError(f"Version {version} processing failed")
        time.sleep(5)

def create_or_update_env(eb_client, config: Dict[str, Any], version: str) -> None:
    """Create or update Elastic Beanstalk environment."""
    env_name = config['application']['environment']
    exists = bool(eb_client.describe_environments(
        EnvironmentNames=[env_name],
        IncludeDeleted=False
    )['Environments'])
    
    settings = [
        {'Namespace': 'aws:autoscaling:launchconfiguration',
         'OptionName': 'IamInstanceProfile',
         'Value': config['iam']['instance_profile_name']},
        {'Namespace': 'aws:elasticbeanstalk:environment',
         'OptionName': 'ServiceRole',
         'Value': config['iam']['service_role_name']},
        {'Namespace': 'aws:autoscaling:launchconfiguration',
         'OptionName': 'InstanceType',
         'Value': config['instance']['type']}
    ]
    
    if exists:
        eb_client.update_environment(
            EnvironmentName=env_name,
            VersionLabel=version,
            OptionSettings=settings
        )
    else:
        settings.append({
            'Namespace': 'aws:elasticbeanstalk:environment',
            'OptionName': 'LoadBalancerType',
            'Value': config['instance']['elb_type']
        })
        eb_client.create_environment(
            ApplicationName=config['application']['name'],
            EnvironmentName=env_name,
            VersionLabel=version,
            SolutionStackName=config['aws']['platform'],
            OptionSettings=settings
        )
    
    wait_for_env(eb_client, env_name, 'Ready')

def deploy_application(config: Dict[str, Any]) -> None:
    """Deploy the application to Elastic Beanstalk."""
    session = boto3.Session(region_name=config['aws']['region'])
    eb_client = session.client('elasticbeanstalk')
    iam_client = session.client('iam')
    s3_client = session.client('s3')
    
    # Create EB CLI config
    eb_dir = Path(__file__).parent.parent.parent / '.elasticbeanstalk'
    eb_dir.mkdir(exist_ok=True)
    (eb_dir / 'config.yml').write_text(yaml.safe_dump({
        'branch-defaults': {'default': {'environment': config['application']['environment']}},
        'global': {
            'application_name': config['application']['name'],
            'default_platform': config['aws']['platform'],
            'default_region': config['aws']['region'],
            'include_git_submodules': True,
            'instance_profile': None,
            'platform_name': None,
            'platform_version': None,
            'sc': 'git',
            'workspace_type': 'Application'
        }
    }))
    
    # Set up IAM resources
    setup_iam_role(
        iam_client,
        config['iam']['service_role_name'],
        config['iam']['service_role_policies']
    )
    ensure_instance_profile(iam_client, config)
    
    # Create/update application
    app_name = config['application']['name']
    if not eb_client.describe_applications(ApplicationNames=[app_name])['Applications']:
        eb_client.create_application(
            ApplicationName=app_name,
            Description=config.get('application', {}).get('description', 'Application created by deployment script')
        )
    
    # Create and upload application version
    version = f"v{datetime.now():%Y%m%d_%H%M%S}"
    bucket = f"elasticbeanstalk-{config['aws']['region']}-{app_name.lower()}"
    
    try:
        s3_client.head_bucket(Bucket=bucket)
    except ClientError:
        s3_client.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={'LocationConstraint': config['aws']['region']}
        )
    
    bundle = create_app_bundle()
    key = f"app-{version}.zip"
    
    with open(bundle, 'rb') as f:
        s3_client.upload_fileobj(f, bucket, key)
    os.remove(bundle)
    
    eb_client.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version,
        SourceBundle={'S3Bucket': bucket, 'S3Key': key},
        Process=True
    )
    
    wait_for_version(eb_client, app_name, version)
    create_or_update_env(eb_client, config, version)