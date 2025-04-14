# modules/shield.py

import os
import getpass
import re
from pathlib import Path
from typing import Dict, Optional, Tuple
import boto3
import click

from .common import DeploymentError, aws_handler

def ensure_env_in_gitignore():
    """Ensure .env is listed in .gitignore file."""
    project_root = Path(__file__).parent.parent.parent
    gitignore_path = project_root / '.gitignore'
    
    # Check if .gitignore exists
    if not gitignore_path.exists():
        click.echo("Creating .gitignore file with .env entry")
        with open(gitignore_path, 'w') as f:
            f.write(".env\n")
        return
    
    # Check if .env is already in .gitignore
    with open(gitignore_path, 'r') as f:
        content = f.read()
    
    if ".env" not in content.splitlines():
        click.echo("Adding .env to .gitignore")
        with open(gitignore_path, 'a') as f:
            # Add newline if needed
            if not content.endswith('\n'):
                f.write('\n')
            f.write(".env\n")

def prompt_for_missing_oidc_vars(config):
    """Prompt for missing OIDC variables and save them to .env file."""
    required_vars = [
        ('client_id', 'OIDC_CLIENT_ID', "Enter OIDC client ID"),
        ('client_secret', 'OIDC_CLIENT_SECRET', "Enter OIDC client secret"),
        ('issuer', 'OIDC_ISSUER', "Enter OIDC issuer URL"),
        ('endpoints.authorization', 'OIDC_AUTH_ENDPOINT', "Enter authorization endpoint URL"),
        ('endpoints.token', 'OIDC_TOKEN_ENDPOINT', "Enter token endpoint URL"),
        ('endpoints.userinfo', 'OIDC_USERINFO_ENDPOINT', "Enter userinfo endpoint URL")
    ]
    
    # Find which variables are missing
    missing = []
    for config_path, env_var, prompt_text in required_vars:
        if env_var not in os.environ or not os.environ[env_var]:
            missing.append((env_var, prompt_text))
    
    if not missing:
        return True  # All variables are present
        
    # Prompt for missing variables
    click.echo("\nSome required OIDC variables are missing. Please provide them:")
    new_vars = {}
    
    for env_var, prompt_text in missing:
        if env_var == 'OIDC_CLIENT_SECRET':
            value = getpass.getpass(f"{prompt_text}: ")
        else:
            value = click.prompt(prompt_text)
        
        new_vars[env_var] = value
        os.environ[env_var] = value  # Set for current session
    
    # Ask if user wants to save to .env
    if click.confirm("\nWould you like to save these values to .env file for future use?", default=True):
        # Ensure .env is in .gitignore first
        ensure_env_in_gitignore()
        
        project_root = Path(__file__).parent.parent.parent
        env_path = project_root / '.env'
        
        # Read existing .env if it exists
        existing_vars = {}
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        existing_vars[key.strip()] = value.strip()
        
        # Update with new values
        existing_vars.update(new_vars)
        
        # Write back to .env
        with open(env_path, 'w') as f:
            f.write("# OIDC Configuration - SENSITIVE INFORMATION\n\n")
            for key, value in existing_vars.items():
                f.write(f"{key}={value}\n")
        
        click.echo(f"Values saved to {env_path}")
    
    return True

def validate_oidc_config(config: Dict) -> bool:
    """
    Validate OIDC configuration and provide helpful error messages.
    If interactive mode is enabled, prompt for missing values.
    
    Args:
        config: The loaded configuration dictionary
        
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    if 'oidc' not in config:
        click.echo("ERROR: Missing 'oidc' section in configuration.", err=True)
        return False
    
    # Try to get missing variables through prompts
    if not prompt_for_missing_oidc_vars(config):
        return False
    
    # Final check after prompting
    required_vars = ['OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_ISSUER', 
                    'OIDC_AUTH_ENDPOINT', 'OIDC_TOKEN_ENDPOINT', 'OIDC_USERINFO_ENDPOINT']
    
    missing = [var for var in required_vars if var not in os.environ or not os.environ[var]]
    
    if missing:
        click.echo("ERROR: Still missing required OIDC environment variables:", err=True)
        for var in missing:
            click.echo(f"  - {var}", err=True)
        return False
    
    return True

@aws_handler
def get_domain_from_listener(elbv2_client, listener_arn: str) -> str:
    """Extract domain from the certificate attached to the HTTPS listener."""
    listener = elbv2_client.describe_listeners(ListenerArns=[listener_arn])['Listeners'][0]
    cert_arn = listener['Certificates'][0]['CertificateArn']
    acm_client = boto3.client('acm')
    cert = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
    project_name = Path(__file__).parent.parent.parent.name
    return cert['DomainName'].replace('*', project_name)

@aws_handler
def find_listener_arn(env_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Find HTTPS listener ARN for the environment's ALB."""
    eb = boto3.client('elasticbeanstalk')
    elbv2 = boto3.client('elbv2')
    
    envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)['Environments']
    if not envs:
        raise DeploymentError(f"Environment {env_name} not found")

    for lb in elbv2.describe_load_balancers()['LoadBalancers']:
        if lb['Type'].lower() != 'application':
            continue
        
        tags = elbv2.describe_tags(ResourceArns=[lb['LoadBalancerArn']])['TagDescriptions'][0]['Tags']
        if not any(t['Key'] == 'elasticbeanstalk:environment-name' and t['Value'] == env_name for t in tags):
            continue
        
        listeners = elbv2.describe_listeners(LoadBalancerArn=lb['LoadBalancerArn'])['Listeners']
        https_listener = next((l for l in listeners if l['Port'] == 443), None)
        if https_listener:
            return https_listener['ListenerArn'], lb['LoadBalancerArn']
        raise DeploymentError("HTTPS listener not found. Run 'secure' command first.")
    
    return None, None

@aws_handler
def find_target_group_arn(load_balancer_arn: str) -> str:
    """Get target group ARN for the load balancer."""
    elbv2 = boto3.client('elbv2')
    target_groups = elbv2.describe_target_groups(LoadBalancerArn=load_balancer_arn)['TargetGroups']
    if not target_groups:
        raise DeploymentError("No target groups found for load balancer")
    return target_groups[0]['TargetGroupArn']

def get_client_secret(secret: Optional[str] = None) -> str:
    """Get client secret from args, environment, or prompt user."""
    # Priority: 1. Command line arg, 2. Environment variable, 3. Interactive prompt
    if secret:
        return secret
    if secret := os.environ.get('OIDC_CLIENT_SECRET'):
        return secret
    return getpass.getpass("\nPlease enter your OIDC client secret: ")

@aws_handler
def configure_oidc_auth(config: Dict, client_secret: Optional[str] = None) -> None:
    """
    Configure OIDC authentication on ALB listener.
    
    Args:
        config: The loaded configuration dictionary
        client_secret: Optional client secret (will be prompted if not provided)
    """
    env_name = config['application']['environment']
    
    # Prioritize environment variables over config file values
    oidc_config = {
        'client_id': os.environ.get('OIDC_CLIENT_ID', config['oidc']['client_id']),
        'client_secret': client_secret or os.environ.get('OIDC_CLIENT_SECRET', ''),
        'issuer': os.environ.get('OIDC_ISSUER', config['oidc']['issuer']),
        'endpoints': {
            'authorization': os.environ.get('OIDC_AUTH_ENDPOINT', config['oidc']['endpoints']['authorization']),
            'token': os.environ.get('OIDC_TOKEN_ENDPOINT', config['oidc']['endpoints']['token']),
            'userinfo': os.environ.get('OIDC_USERINFO_ENDPOINT', config['oidc']['endpoints']['userinfo']),
        },
        'session': config['oidc']['session']  # Non-sensitive, use config values
    }
    
    click.echo(f"Configuring OIDC authentication for {env_name}...")
    
    # Get the client secret if not provided
    if not oidc_config['client_secret']:
        oidc_config['client_secret'] = get_client_secret()
    
    if not oidc_config['client_secret']:
        raise DeploymentError("OIDC client secret is required")
    
    # Find the HTTPS listener
    listener_arn, load_balancer_arn = find_listener_arn(env_name)
    if not listener_arn:
        raise DeploymentError("Could not find HTTPS listener")
    
    # Get domain from the certificate
    elbv2_client = boto3.client('elbv2')
    domain = get_domain_from_listener(elbv2_client, listener_arn)
    
    # Get target group ARN
    target_group_arn = find_target_group_arn(load_balancer_arn)
    
    # Clean existing rules
    click.echo("Removing existing listener rules...")
    for rule in elbv2_client.describe_rules(ListenerArn=listener_arn)['Rules']:
        if not rule.get('IsDefault', False):
            elbv2_client.delete_rule(RuleArn=rule['RuleArn'])
    
    # Configure authentication action
    click.echo("Configuring OIDC authentication...")
    auth_action = {
        'Type': 'authenticate-oidc',
        'AuthenticateOidcConfig': {
            'Issuer': oidc_config['issuer'],
            'AuthorizationEndpoint': oidc_config['endpoints']['authorization'],
            'TokenEndpoint': oidc_config['endpoints']['token'],
            'UserInfoEndpoint': oidc_config['endpoints']['userinfo'],
            'ClientId': oidc_config['client_id'],
            'ClientSecret': oidc_config['client_secret'],
            'SessionCookieName': oidc_config['session']['cookie_name'],
            'SessionTimeout': oidc_config['session']['timeout'],
            'Scope': oidc_config['session']['scope'],
            'OnUnauthenticatedRequest': 'authenticate'
        }
    }

    # Set default action to 503
    click.echo("Setting default listener action...")
    elbv2_client.modify_listener(
        ListenerArn=listener_arn,
        DefaultActions=[{
            'Type': 'fixed-response',
            'FixedResponseConfig': {
                'MessageBody': 'Unauthorized Access',
                'StatusCode': '503',
                'ContentType': 'text/plain'
            }
        }]
    )

    # Create authenticated access rule
    click.echo("Creating authentication rule...")
    elbv2_client.create_rule(
        ListenerArn=listener_arn,
        Priority=1,
        Conditions=[{'Field': 'path-pattern', 'Values': ['/*']}],
        Actions=[
            {**auth_action, 'Order': 1},
            {'Type': 'forward', 'TargetGroupArn': target_group_arn, 'Order': 2}
        ]
    )

    # Configure HTTP to HTTPS redirect
    click.echo("Configuring HTTP to HTTPS redirect...")
    http_listener = next(
        (l for l in elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)['Listeners']
         if l['Port'] == 80),
        None
    )
    if http_listener:
        elbv2_client.modify_listener(
            ListenerArn=http_listener['ListenerArn'],
            DefaultActions=[{
                'Type': 'redirect',
                'RedirectConfig': {
                    'Protocol': 'HTTPS',
                    'Port': '443',
                    'StatusCode': 'HTTP_301'
                }
            }]
        )
    
    click.echo(f"\nOIDC authentication successfully configured for {domain}")
    click.echo("Users will now be required to authenticate via your OIDC provider.")