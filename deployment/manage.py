#!/usr/bin/env python3
"""
Elastic Beanstalk deployment management script.
"""

from pathlib import Path
import sys
import click
import yaml
from typing import Dict

sys.path.append(str(Path(__file__).parent))
from modules.ship import deploy_application
from modules.scrap import cleanup_application
from modules.common import DeploymentError

def load_config() -> Dict:
    """Load and validate configuration."""
    try:
        config = yaml.safe_load((Path(__file__).parent / "configurations" / "config.yaml").read_text())
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

if __name__ == '__main__':
    cli()