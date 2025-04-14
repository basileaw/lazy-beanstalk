# manage.py

"""
Elastic Beanstalk deployment management script.
"""

import sys
import click
from typing import Optional

from modules.configure import (
    ConfigurationManager, ClientManager, ProgressIndicator, logger,
    ConfigurationError
)
from modules.ship import deploy_application
from modules.scrap import cleanup_application
from modules.secure import pick_certificate, enable_https
from modules.shield import configure_oidc_auth, validate_oidc_config
from modules.common import DeploymentError

def init_environment():
    """Initialize the environment before running commands."""
    try:
        # Try to load config - this will initialize ClientManager with the correct region
        config = ConfigurationManager.load_config()
        return config
    except ConfigurationError as e:
        logger.error(f"Configuration error: {str(e)}")
        return None

@click.group()
def cli():
    """Elastic Beanstalk deployment management tool."""
    pass

@cli.command()
def ship():
    """Deploy the application."""
    try:
        logger.info("Starting deployment process")
        config = init_environment()
        if not config:
            sys.exit(1)
            
        deploy_application(config)
    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Deployment error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
def scrap():
    """Clean up all resources."""
    try:
        logger.info("Starting cleanup process")
        config = init_environment()
        if not config:
            sys.exit(1)
            
        cleanup_application(config)
    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Cleanup error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
def secure():
    """Enable HTTPS (ACM + Route53) on your EB environment."""
    try:
        logger.info("Starting HTTPS configuration process")
        config = init_environment()
        if not config:
            sys.exit(1)
        
        # Initialize ACM client through ClientManager
        acm_client = ClientManager.get_client('acm')
        
        # Choose certificate
        chosen_cert = pick_certificate(acm_client)
        if not chosen_cert:
            logger.error("No certificate selected")
            sys.exit(1)
            
        # Enable HTTPS
        enable_https(config, chosen_cert)
    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"HTTPS configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)

@cli.command()
@click.option('--secret', '-s', help='OIDC client secret (can also use OIDC_CLIENT_SECRET env var)')
def shield(secret: Optional[str] = None):
    """Configure OIDC authentication for your EB environment."""
    try:
        logger.info("Starting OIDC configuration process")
        config = init_environment()
        if not config:
            sys.exit(1)
        
        # Validate OIDC configuration
        if not validate_oidc_config(config):
            logger.error("OIDC configuration validation failed")
            sys.exit(1)
            
        configure_oidc_auth(config, client_secret=secret)
    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"OIDC configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    cli()