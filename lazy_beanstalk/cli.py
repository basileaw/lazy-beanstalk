# cli.py

"""CLI interface for lazy-beanstalk using Click."""

import sys
import click
from pathlib import Path
from dotenv import load_dotenv

from . import ship, secure, shield, scrap
from .config import logger, ConfigurationError, DeploymentError, load_app_env_vars

# Load .env file from current directory if it exists
load_dotenv()


@click.group()
@click.version_option(version="2.0.0", prog_name="lazy-beanstalk")
def cli():
    """Lazy Beanstalk - Simple AWS Elastic Beanstalk deployment tool."""
    pass


@cli.command()
@click.option("--app-name", help="Application name (default: current directory name)")
@click.option("--environment-name", help="Environment name (default: {app_name}-env)")
@click.option("--region", help="AWS region (default: us-west-2)")
@click.option("--instance-type", help="EC2 instance type (default: t4g.nano)")
@click.option("--spot/--no-spot", default=None, help="Use spot instances")
@click.option("--min-instances", type=int, help="Minimum number of instances (default: 1)")
@click.option("--max-instances", type=int, help="Maximum number of instances (default: 1)")
@click.option("--policies-dir", help="Path to custom IAM policies directory")
@click.option("--dockerfile-path", help="Path to Dockerfile (default: ./Dockerfile)")
@click.option("--deployment-env", default=".env.lb", help="Deployment env file (excluded from EB, default: .env.lb)")
def ship_cmd(
    app_name,
    environment_name,
    region,
    instance_type,
    spot,
    min_instances,
    max_instances,
    policies_dir,
    dockerfile_path,
    deployment_env,
):
    """Deploy application to AWS Elastic Beanstalk."""
    try:
        # Auto-load app environment variables from .env* files
        # (excludes deployment vars from .env.lb or --deployment-env file)
        app_env_vars = load_app_env_vars(deployment_env)

        # Build kwargs from provided options
        kwargs = {}
        if app_name:
            kwargs["app_name"] = app_name
        if environment_name:
            kwargs["environment_name"] = environment_name
        if region:
            kwargs["region"] = region
        if instance_type:
            kwargs["instance_type"] = instance_type
        if spot is not None:
            kwargs["spot_instances"] = spot
        if min_instances:
            kwargs["min_instances"] = min_instances
        if max_instances:
            kwargs["max_instances"] = max_instances
        if policies_dir:
            kwargs["policies_dir"] = policies_dir
        if dockerfile_path:
            kwargs["dockerfile_path"] = dockerfile_path

        # Add auto-loaded env vars (if any)
        if app_env_vars:
            kwargs["env_vars"] = app_env_vars

        result = ship(**kwargs)

        click.echo(f"\n✓ Deployment successful!")
        click.echo(f"  Application: {result['app_name']}")
        click.echo(f"  Environment: {result['environment_name']}")
        click.echo(f"  URL: http://{result['environment_url']}")
        click.echo(f"  Version: {result['version']}")

    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option("--domain", help="Domain name for HTTPS")
@click.option(
    "--domain-mode",
    type=click.Choice(["sub", "root", "custom"]),
    help="Domain mode (default: sub)",
)
@click.option("--certificate-arn", help="ACM certificate ARN")
@click.option("--ttl", type=int, default=300, help="DNS record TTL (default: 300)")
def secure_cmd(domain, domain_mode, certificate_arn, ttl):
    """Enable HTTPS with ACM and Route 53."""
    try:
        kwargs = {}
        if domain:
            kwargs["domain"] = domain
        if domain_mode:
            kwargs["domain_mode"] = domain_mode
        if certificate_arn:
            kwargs["certificate_arn"] = certificate_arn
        if ttl:
            kwargs["ttl"] = ttl

        result = secure(**kwargs)

        click.echo(f"\n✓ HTTPS configuration successful!")
        click.echo(f"  Domains: {', '.join(['https://' + d for d in result['domains']])}")
        click.echo(f"  Certificate: {result['certificate_domain']}")

    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option("--client-id", help="OIDC client ID")
@click.option("--client-secret", help="OIDC client secret")
@click.option("--issuer", help="OIDC issuer URL")
@click.option("--auth-endpoint", help="Authorization endpoint URL")
@click.option("--token-endpoint", help="Token endpoint URL")
@click.option("--userinfo-endpoint", help="User info endpoint URL")
@click.option("--session-timeout", type=int, default=36000, help="Session timeout in seconds")
@click.option("--session-cookie-name", default="federate_id_token", help="Session cookie name")
@click.option("--scope", default="openid", help="OIDC scope")
def shield_cmd(
    client_id,
    client_secret,
    issuer,
    auth_endpoint,
    token_endpoint,
    userinfo_endpoint,
    session_timeout,
    session_cookie_name,
    scope,
):
    """Configure OIDC authentication on ALB."""
    try:
        kwargs = {}
        if client_id:
            kwargs["client_id"] = client_id
        if client_secret:
            kwargs["client_secret"] = client_secret
        if issuer:
            kwargs["issuer"] = issuer
        if auth_endpoint:
            kwargs["auth_endpoint"] = auth_endpoint
        if token_endpoint:
            kwargs["token_endpoint"] = token_endpoint
        if userinfo_endpoint:
            kwargs["userinfo_endpoint"] = userinfo_endpoint
        if session_timeout:
            kwargs["session_timeout"] = session_timeout
        if session_cookie_name:
            kwargs["session_cookie_name"] = session_cookie_name
        if scope:
            kwargs["scope"] = scope

        result = shield(**kwargs)

        click.echo(f"\n✓ OIDC authentication configured!")
        click.echo(f"  Domain: https://{result['domain']}")
        click.echo(f"  Issuer: {result['issuer']}")
        click.echo(f"  Client ID: {result['client_id']}")

    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


@cli.command()
@click.option("--app-name", help="Application name (default: from state file)")
@click.option("--force", is_flag=True, help="Skip confirmation prompts")
def scrap_cmd(app_name, force):
    """Remove all AWS resources created by lazy-beanstalk."""
    try:
        kwargs = {}
        if app_name:
            kwargs["app_name"] = app_name
        if force:
            kwargs["force"] = force

        result = scrap(**kwargs)

        if result["status"] == "completed":
            click.echo(f"\n✓ Cleanup successful!")
            click.echo(f"  Application: {result['app_name']}")
            click.echo(f"  Environment: {result['environment_name']}")
        elif result["status"] == "cancelled":
            click.echo("\nCleanup cancelled.")

    except (ConfigurationError, DeploymentError) as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
