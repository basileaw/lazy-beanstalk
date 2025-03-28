# manage.py 
"""
Elastic Beanstalk deployment management script.
"""

from pathlib import Path
import sys
import click
import yaml
from typing import Dict, Optional

import boto3
from botocore.exceptions import ClientError

sys.path.append(str(Path(__file__).parent))
from modules.ship import deploy_application
from modules.scrap import cleanup_application
from modules.secure import pick_certificate, enable_https
from modules.common import DeploymentError

def get_project_name() -> str:
    """Retrieve the project name from the root folder."""
    return Path(__file__).parent.parent.name

def get_aws_region() -> str:
    """
    Get the AWS region from the configured profile.
    If region cannot be determined, returns the first available region.
    """
    try:
        session = boto3.Session()
        region = session.region_name
        
        if not region:
            # Try to get from configured profile
            profile = session.profile_name
            if profile:
                config = session.client('config')
                region = config.get_discovered_resource_counts(
                    resourceType='AWS::Config::ResourceCompliance',
                    limit=1
                ).get('region')
            
            # If still no region, get first available region
            if not region:
                available_regions = session.get_available_regions('elasticbeanstalk')
                if available_regions:
                    region = available_regions[0]
                    click.echo(f"No AWS region specified. Using first available region: {region}", err=True)
                else:
                    raise ValueError("No available regions found")
        
        return region
    except Exception as e:
        click.echo(f"Warning: Could not determine AWS region: {str(e)}. Check AWS configuration.", err=True)
        raise DeploymentError("Unable to determine AWS region. Please configure AWS CLI or specify region.")

def get_latest_docker_platform() -> str:
    """
    Get the latest Docker platform from Elastic Beanstalk.
    Returns the exact solution stack name needed for environment creation.
    """
    try:
        region = get_aws_region()
        session = boto3.Session(region_name=region)
        eb_client = session.client('elasticbeanstalk')
        
        # Get all available solution stacks directly
        click.echo("Retrieving available solution stacks...")
        solution_stacks = eb_client.list_available_solution_stacks()['SolutionStacks']
        click.echo(f"Found {len(solution_stacks)} solution stacks")
        
        # Filter for Docker stacks
        docker_stacks = [s for s in solution_stacks if 'Docker' in s]
        click.echo(f"Found {len(docker_stacks)} Docker solution stacks")
        
        if not docker_stacks:
            raise ValueError("No Docker solution stacks found in this region")
        
        # First try to find Amazon Linux 2023 Docker stacks
        al2023_stacks = [s for s in docker_stacks if 'Amazon Linux 2023' in s]
        
        if al2023_stacks:
            # Sort to get the latest version (sort alphabetically since version is in the name)
            latest_stack = sorted(al2023_stacks, reverse=True)[0]
            click.echo(f"Using latest Amazon Linux 2023 Docker stack: {latest_stack}")
            return latest_stack
        
        # If no AL2023 stacks, try Amazon Linux 2
        al2_stacks = [s for s in docker_stacks if 'Amazon Linux 2' in s and 'Amazon Linux 2023' not in s]
        
        if al2_stacks:
            latest_stack = sorted(al2_stacks, reverse=True)[0]
            click.echo(f"Using latest Amazon Linux 2 Docker stack: {latest_stack}")
            return latest_stack
        
        # If all else fails, use the latest Docker stack available
        latest_stack = sorted(docker_stacks, reverse=True)[0]
        click.echo(f"Using Docker stack: {latest_stack}")
        return latest_stack
        
    except Exception as e:
        click.echo(f"Error: Could not determine Docker platform: {str(e)}", err=True)
        raise DeploymentError(f"Unable to determine Docker platform: {str(e)}. Check AWS configuration.")

def load_config() -> Dict:
    """Load and validate configuration, replacing placeholders."""
    try:
        config = yaml.safe_load((Path(__file__).parent / "configurations" / "config.yml").read_text())
        project_name = get_project_name()
        aws_region = get_aws_region()
        docker_platform = get_latest_docker_platform()

        # Replace placeholders with actual values
        def replace_placeholders(obj):
            if isinstance(obj, str):
                return (obj.replace('${PROJECT_NAME}', project_name)
                          .replace('${AWS_REGION}', aws_region)
                          .replace('${LATEST_DOCKER_PLATFORM}', docker_platform))
            elif isinstance(obj, dict):
                return {k: replace_placeholders(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_placeholders(i) for i in obj]
            return obj

        config = replace_placeholders(config)
        
        # Log the resolved values
        click.echo(f"Using AWS Region: {aws_region}")
        click.echo(f"Using Platform: {docker_platform}")
        click.echo(f"Project Name: {project_name}")

        # Validate required fields
        required = {
            'aws': ['region', 'platform'],
            'application': ['name', 'environment'],
            'instance': ['type', 'elb_type', 'autoscaling'],
            'iam': ['service_role_name', 'instance_role_name', 'instance_profile_name']
        }
        
        for section, fields in required.items():
            if not all(field in config.get(section, {}) for field in fields):
                raise ValueError(f"Missing required fields in {section} section")
        return config
    except Exception as e:
        click.echo(f"Configuration error: {str(e)}", err=True)
        sys.exit(1)

@click.group()
def cli():
    """Elastic Beanstalk deployment management tool."""
    pass

@cli.command()
def ship():
    """Deploy the application."""
    try:
        deploy_application(load_config())
    except DeploymentError as e:
        click.echo(f"Deployment error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
def scrap():
    """Clean up all resources."""
    try:
        cleanup_application(load_config())
    except DeploymentError as e:
        click.echo(f"Cleanup error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
def secure():
    """Enable HTTPS (ACM + Route53) on your EB environment."""
    config = load_config()
    session = boto3.Session(region_name=config['aws']['region'])
    acm_client = session.client('acm')
    try:
        chosen_cert = pick_certificate(acm_client)
        enable_https(config, chosen_cert)
    except DeploymentError as e:
        click.echo(f"Security error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()