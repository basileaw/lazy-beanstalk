#!/usr/bin/env python3
"""
Elastic Beanstalk deployment management script.
Handles deployment and cleanup of EB environments with associated AWS resources.
"""

import os
import sys
from pathlib import Path
import click
import yaml
import boto3
from typing import Dict, Any

# Add the deployment directory to the Python path
DEPLOYMENT_DIR = Path(__file__).parent
sys.path.append(str(DEPLOYMENT_DIR))

from modules.ship import deploy_application
from modules.scrap import cleanup_application

def load_config() -> Dict[Any, Any]:
    """Load configuration from YAML file."""
    config_path = DEPLOYMENT_DIR / "configurations" / "config.yaml"
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        click.echo(f"Error: Configuration file not found at {config_path}", err=True)
        sys.exit(1)
    except yaml.YAMLError as e:
        click.echo(f"Error: Invalid YAML in configuration file: {e}", err=True)
        sys.exit(1)

def validate_config(config: Dict[Any, Any]) -> None:
    """Validate the loaded configuration."""
    required_sections = ['aws', 'application', 'instance', 'iam']
    required_fields = {
        'aws': ['region', 'platform'],
        'application': ['name', 'environment'],
        'instance': ['type', 'elb_type'],
        'iam': ['service_role_name', 'instance_role_name', 'instance_profile_name']
    }

    # Check for required sections
    for section in required_sections:
        if section not in config:
            click.echo(f"Error: Missing required section '{section}' in config", err=True)
            sys.exit(1)
        
        # Check for required fields in each section
        for field in required_fields[section]:
            if field not in config[section]:
                click.echo(f"Error: Missing required field '{field}' in '{section}' section", err=True)
                sys.exit(1)

@click.group()
def cli():
    """Elastic Beanstalk deployment management tool."""
    pass

@cli.command()
def ship():
    """Deploy the application to Elastic Beanstalk."""
    try:
        config = load_config()
        validate_config(config)
        deploy_application(config)
    except Exception as e:
        click.echo(f"Error during deployment: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
def scrap():
    """Clean up the Elastic Beanstalk environment and associated resources."""
    try:
        config = load_config()
        validate_config(config)
        cleanup_application(config)
    except Exception as e:
        click.echo(f"Error during cleanup: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()