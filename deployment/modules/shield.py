# modules/shield.py

import os
import getpass
from pathlib import Path
from typing import Dict, Optional, Tuple
import boto3
import click

from .common import DeploymentError, aws_handler

def validate_oidc_config(config: Dict) -> bool:
    """
    Validate OIDC configuration and provide helpful error messages.
    
    Args:
        config: The loaded configuration dictionary
        
    Returns:
        bool: True if configuration is valid, False otherwise
    """
    if 'oidc' not in config:
        click.echo("ERROR: Missing 'oidc' section in configuration.", err=True)
        return False
        
    required_vars = [
        ('client_id', 'OIDC_CLIENT_ID'),
        ('client_secret', 'OIDC_CLIENT_SECRET'),
        ('issuer', 'OIDC_ISSUER'),
        ('endpoints.authorization', 'OIDC_AUTH_ENDPOINT'),
        ('endpoints.token', 'OIDC_TOKEN_ENDPOINT'),
        ('endpoints.userinfo', 'OIDC_USERINFO_ENDPOINT')
    ]
    
    missing = []
    for config_path, env_var in required_vars:
        parts = config_path.split('.')
        value = config['oidc']
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                value = None
                break
        
        if not value:
            missing.append(env_var)
    
    if missing:
        click.echo("ERROR: Missing required OIDC environment variables:", err=True)
        for var in missing:
            click.echo(f"  - {var}", err=True)
        click.echo("\nPlease set these environment variables and try again.", err=True)
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
    oidc_config = config['oidc']
    
    click.echo(f"Configuring OIDC authentication for {env_name}...")
    
    # Get the client secret if not provided
    client_secret = client_secret or get_client_secret()
    if not client_secret:
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
            'ClientSecret': client_secret,
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