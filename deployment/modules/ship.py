"""
Handles deployment of Elastic Beanstalk application and associated AWS resources.
"""

import os
import tempfile
import zipfile
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Set
import boto3
import yaml
from botocore.exceptions import ClientError

from . import common

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

@common.aws_handler
def ensure_instance_profile(iam_client, config: Dict[str, Any]) -> None:
    """Set up instance profile and its associated role."""
    profile_name = config['iam']['instance_profile_name']
    role_name = config['iam']['instance_role_name']
    
    # Set up the role first
    common.manage_iam_role(iam_client, role_name, config['iam']['instance_role_policies'])
    
    try:
        iam_client.get_instance_profile(InstanceProfileName=profile_name)
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
            iam_client.create_instance_profile(InstanceProfileName=profile_name)
            iam_client.add_role_to_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=role_name
            )
            time.sleep(10)  # Allow time for profile propagation
        else:
            raise

def wait_for_version(eb_client, app_name: str, version: str) -> None:
    """Wait for application version to be processed."""
    print("Waiting for application version to be processed...")
    while True:
        versions = eb_client.describe_application_versions(
            ApplicationName=app_name,
            VersionLabels=[version]
        )['ApplicationVersions']
        
        if not versions:
            raise common.DeploymentError(f"Version {version} not found")
        
        status = versions[0]['Status']
        print(f"Version status: {status}")
        
        if status == 'PROCESSED':
            break
        elif status == 'FAILED':
            raise common.DeploymentError(f"Version {version} processing failed")
        time.sleep(5)

def create_or_update_env(eb_client, config: Dict[str, Any], version: str) -> None:
    """Create or update Elastic Beanstalk environment."""
    env_name = config['application']['environment']
    exists = bool(eb_client.describe_environments(
        EnvironmentNames=[env_name],
        IncludeDeleted=False
    )['Environments'])
    
    settings = common.get_env_settings(config)
    
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
    
    common.wait_for_env_status(eb_client, env_name, 'Ready')

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
    common.manage_iam_role(
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