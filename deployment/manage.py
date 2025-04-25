# manage.py

"""
Elastic Beanstalk deployment management script.
"""

import sys
import argparse
from typing import Optional

from deployment.modules.setup import (
    ConfigurationManager,
    ClientManager,
    logger,
    ConfigurationError,
)
from modules.ship import deploy_application
from modules.scrap import cleanup_application
from modules.secure import pick_certificate, enable_https
from modules.shield import configure_oidc_auth, validate_oidc_config
from deployment.modules.support import DeploymentError


def init_environment(command=None):
    """
    Initialize the environment before running commands.
    Uses cached platform information when available to avoid redundant AWS API calls.

    Args:
        command: The command being executed, controls logging verbosity
    """
    try:
        # Only show verbose logging during the initial 'ship' command
        verbose_logging = command == "ship"

        # Check if EB config exists - this indicates a prior successful deployment
        eb_config_path = ConfigurationManager.get_eb_config_path()
        if eb_config_path:
            # If .elasticbeanstalk directory exists, check for cached solution stack
            cached_stack = ConfigurationManager.get_cached_solution_stack()
            if cached_stack:
                logger.debug(
                    f"Using cached solution stack from previous deployment: {cached_stack}"
                )

        # Load config - leverages caching for platform discovery
        config = ConfigurationManager.load_config(verbose_logging=verbose_logging)
        return config
    except ConfigurationError as e:
        logger.error(f"Configuration error: {str(e)}")
        return None


def ship_command(args):
    """Deploy the application."""
    try:
        logger.info("Starting deployment process")
        config = init_environment(command="ship")
        if not config:
            sys.exit(1)

        deploy_application(config)
    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Deployment error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


def scrap_command(args):
    """Clean up all resources."""
    try:
        logger.info("Starting cleanup process")
        config = init_environment(command="scrap")
        if not config:
            sys.exit(1)

        cleanup_application(config)
    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Cleanup error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


def secure_command(args):
    """Enable HTTPS (ACM + Route53) on your EB environment."""
    try:
        logger.info("Starting HTTPS configuration process")
        config = init_environment(command="secure")
        if not config:
            sys.exit(1)

        # Initialize ACM client through ClientManager
        acm_client = ClientManager.get_client("acm")

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


def shield_command(args):
    """Configure OIDC authentication for your EB environment."""
    try:
        logger.info("Starting OIDC configuration process")
        config = init_environment(command="shield")
        if not config:
            sys.exit(1)

        # Validate OIDC configuration
        if not validate_oidc_config(config):
            logger.error("OIDC configuration validation failed")
            sys.exit(1)

        configure_oidc_auth(config, client_secret=args.secret)
    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"OIDC configuration error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


def main():
    """Main entry point with argument parsing"""
    parser = argparse.ArgumentParser(
        description="Elastic Beanstalk deployment management tool."
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    subparsers.required = True

    # Ship command
    ship_parser = subparsers.add_parser("ship", help="Deploy the application.")
    ship_parser.set_defaults(func=ship_command)

    # Scrap command
    scrap_parser = subparsers.add_parser("scrap", help="Clean up all resources.")
    scrap_parser.set_defaults(func=scrap_command)

    # Secure command
    secure_parser = subparsers.add_parser(
        "secure", help="Enable HTTPS (ACM + Route53) on your EB environment."
    )
    secure_parser.set_defaults(func=secure_command)

    # Shield command
    shield_parser = subparsers.add_parser(
        "shield", help="Configure OIDC authentication for your EB environment."
    )
    shield_parser.add_argument(
        "--secret",
        "-s",
        help="OIDC client secret (can also use OIDC_CLIENT_SECRET env var)",
    )
    shield_parser.set_defaults(func=shield_command)

    # Parse arguments and execute the appropriate function
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
