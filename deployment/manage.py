# manage.py

"""
Elastic Beanstalk deployment management script.
"""

import sys
import click
from typing import Optional

from modules.configure import load_config, get_aws_clients, ConfigurationError
from modules.ship import deploy_application
from modules.scrap import cleanup_application
from modules.secure import pick_certificate, enable_https
from modules.shield import configure_oidc_auth, validate_oidc_config
from modules.common import DeploymentError

@click.group()
def cli():
    """Elastic Beanstalk deployment management tool."""
    pass

@cli.command()
def ship():
    """Deploy the application."""
    try:
        config = load_config()
        deploy_application(config)
    except (ConfigurationError, DeploymentError) as e:
        click.echo(f"Deployment error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
def scrap():
    """Clean up all resources."""
    try:
        config = load_config()
        cleanup_application(config)
    except (ConfigurationError, DeploymentError) as e:
        click.echo(f"Cleanup error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
def secure():
    """Enable HTTPS (ACM + Route53) on your EB environment."""
    try:
        config = load_config()
        aws_clients = get_aws_clients(config)
        acm_client = aws_clients['acm']
        chosen_cert = pick_certificate(acm_client)
        enable_https(config, chosen_cert)
    except (ConfigurationError, DeploymentError) as e:
        click.echo(f"Security error: {str(e)}", err=True)
        sys.exit(1)

@cli.command()
@click.option('--secret', '-s', help='OIDC client secret (can also use OIDC_CLIENT_SECRET env var)')
def shield(secret: Optional[str] = None):
    """Configure OIDC authentication for your EB environment."""
    try:
        config = load_config()
        
        # Validate OIDC configuration
        if not validate_oidc_config(config):
            sys.exit(1)
            
        configure_oidc_auth(config, client_secret=secret)
    except (ConfigurationError, DeploymentError) as e:
        click.echo(f"OIDC configuration error: {str(e)}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()