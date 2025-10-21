# shield.py

"""Configure OIDC authentication for Elastic Beanstalk environment."""

import os
import getpass
from typing import Dict, Optional, Tuple

from .config import (
    ClientManager,
    StateManager,
    logger,
    DeploymentError,
    ConfigurationError,
    get_oidc_env_var,
    get_env_var,
)
from . import support


def validate_oidc_params(
    client_id: Optional[str],
    client_secret: Optional[str],
    issuer: Optional[str],
    auth_endpoint: Optional[str],
    token_endpoint: Optional[str],
    userinfo_endpoint: Optional[str],
) -> None:
    """
    Validate that all required OIDC parameters are provided.

    Args:
        All OIDC configuration parameters

    Raises:
        ConfigurationError if any required parameter is missing
    """
    required_params = {
        "client_id": client_id,
        "client_secret": client_secret,
        "issuer": issuer,
        "auth_endpoint": auth_endpoint,
        "token_endpoint": token_endpoint,
        "userinfo_endpoint": userinfo_endpoint,
    }

    missing = [name for name, value in required_params.items() if not value]

    if missing:
        logger.error("Missing required OIDC configuration parameters:")
        for param in missing:
            logger.error(f"  - {param}")

        logger.info("\nPlease provide these parameters when calling shield().")
        logger.info("Example:")
        logger.info("  shield(")
        for param in missing:
            logger.info(f"    {param}='your-value-here',")
        logger.info("  )")

        raise ConfigurationError(f"Missing required OIDC parameters: {', '.join(missing)}")


@support.aws_handler
def get_domain_from_listener(listener_arn: str, app_name: str) -> str:
    """Extract domain from the certificate attached to the HTTPS listener."""
    elbv2_client = ClientManager.get_client("elbv2")
    listener = elbv2_client.describe_listeners(ListenerArns=[listener_arn])[
        "Listeners"
    ][0]
    cert_arn = listener["Certificates"][0]["CertificateArn"]

    acm_client = ClientManager.get_client("acm")
    cert = acm_client.describe_certificate(CertificateArn=cert_arn)["Certificate"]
    return cert["DomainName"].replace("*", app_name)


@support.aws_handler
def find_listener_arn(env_name: str) -> Tuple[Optional[str], Optional[str]]:
    """Find HTTPS listener ARN for the environment's ALB."""
    eb_client = ClientManager.get_client("elasticbeanstalk")
    elbv2_client = ClientManager.get_client("elbv2")

    logger.info("Finding HTTPS listener")

    # Check if environment exists
    envs = eb_client.describe_environments(
        EnvironmentNames=[env_name], IncludeDeleted=False
    )["Environments"]
    if not envs:
        raise DeploymentError(f"Environment {env_name} not found")

    # Find the load balancer for the environment
    lbs = elbv2_client.describe_load_balancers()["LoadBalancers"]
    env_lb = None

    for lb in lbs:
        if lb["Type"].lower() != "application":
            continue

        tags = elbv2_client.describe_tags(ResourceArns=[lb["LoadBalancerArn"]])[
            "TagDescriptions"
        ][0]["Tags"]
        if any(
            t["Key"] == "elasticbeanstalk:environment-name" and t["Value"] == env_name
            for t in tags
        ):
            env_lb = lb
            break

    if not env_lb:
        raise DeploymentError(f"No load balancer found for environment {env_name}")

    # Find the HTTPS listener
    listeners = elbv2_client.describe_listeners(
        LoadBalancerArn=env_lb["LoadBalancerArn"]
    )["Listeners"]
    https_listener = next((l for l in listeners if l["Port"] == 443), None)

    if not https_listener:
        raise DeploymentError("HTTPS listener not found. Run 'secure' command first.")

    return https_listener["ListenerArn"], env_lb["LoadBalancerArn"]


@support.aws_handler
def find_target_group_arn(load_balancer_arn: str) -> str:
    """Get target group ARN for the load balancer."""
    elbv2_client = ClientManager.get_client("elbv2")
    logger.info("Finding target group")

    target_groups = elbv2_client.describe_target_groups(
        LoadBalancerArn=load_balancer_arn
    )["TargetGroups"]
    if not target_groups:
        raise DeploymentError("No target groups found for load balancer")

    return target_groups[0]["TargetGroupArn"]


def shield(
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    issuer: Optional[str] = None,
    auth_endpoint: Optional[str] = None,
    token_endpoint: Optional[str] = None,
    userinfo_endpoint: Optional[str] = None,
    session_timeout: int = 36000,
    session_cookie_name: str = "federate_id_token",
    scope: str = "openid",
) -> Dict[str, str]:
    """
    Configure OIDC authentication for your Elastic Beanstalk environment.

    Args:
        client_id: OIDC client ID (required)
        client_secret: OIDC client secret (required)
        issuer: OIDC issuer URL (required)
        auth_endpoint: Authorization endpoint URL (required)
        token_endpoint: Token endpoint URL (required)
        userinfo_endpoint: User info endpoint URL (required)
        session_timeout: Session timeout in seconds (default: 36000)
        session_cookie_name: Session cookie name (default: "federate_id_token")
        scope: OIDC scope (default: "openid")

    Returns:
        Dict with OIDC configuration details
    """
    # Load full EB config
    eb_config = StateManager.load_eb_config()
    if not eb_config:
        raise DeploymentError(
            "No deployment configuration found. Please run 'ship' command first."
        )

    # Get app_name from EB CLI global section
    global_config = eb_config.get("global", {})
    app_name = global_config.get("application_name")

    # Get env_name from branch-defaults
    branch_defaults = eb_config.get("branch-defaults", {})
    main_branch = branch_defaults.get("main", {})
    env_name = main_branch.get("environment")

    # Get region from global section
    region = global_config.get("default_region")

    if not app_name or not env_name:
        raise DeploymentError("Invalid configuration: missing app_name or environment_name")

    # Initialize AWS clients
    ClientManager.initialize(region)

    # Read OIDC parameters from environment if not provided as arguments
    # Provider credentials (with OIDC_* fallback)
    if not client_id:
        client_id = get_oidc_env_var("CLIENT_ID")
    if not client_secret:
        client_secret = get_oidc_env_var("CLIENT_SECRET")
    if not issuer:
        issuer = get_oidc_env_var("ISSUER")
    if not auth_endpoint:
        auth_endpoint = get_oidc_env_var("AUTH_ENDPOINT")
    if not token_endpoint:
        token_endpoint = get_oidc_env_var("TOKEN_ENDPOINT")
    if not userinfo_endpoint:
        userinfo_endpoint = get_oidc_env_var("USERINFO_ENDPOINT")

    # ALB configuration (only LB_ prefix, no fallback)
    if session_timeout == 36000:  # Only override if default
        env_timeout = get_env_var("OIDC_SESSION_TIMEOUT")
        if env_timeout:
            session_timeout = int(env_timeout)
    if session_cookie_name == "federate_id_token":  # Only override if default
        env_cookie = get_env_var("OIDC_SESSION_COOKIE_NAME")
        if env_cookie:
            session_cookie_name = env_cookie
    if scope == "openid":  # Only override if default
        env_scope = get_env_var("OIDC_SCOPE")
        if env_scope:
            scope = env_scope

    # Prompt for client secret if still not provided (for interactive use)
    if not client_secret:
        client_secret = getpass.getpass("\nPlease enter your OIDC client secret: ")

    # Validate all required parameters are present
    validate_oidc_params(
        client_id, client_secret, issuer, auth_endpoint, token_endpoint, userinfo_endpoint
    )

    logger.info(f"Configuring OIDC authentication for {env_name}")

    # Find the HTTPS listener
    listener_arn, load_balancer_arn = find_listener_arn(env_name)
    if not listener_arn:
        raise DeploymentError("Could not find HTTPS listener")

    # Get domain from the certificate
    domain = get_domain_from_listener(listener_arn, app_name)

    # Get target group ARN
    target_group_arn = find_target_group_arn(load_balancer_arn)

    # Clean existing rules
    elbv2_client = ClientManager.get_client("elbv2")
    logger.info("Removing existing listener rules")

    rules_removed = 0
    for rule in elbv2_client.describe_rules(ListenerArn=listener_arn)["Rules"]:
        if not rule.get("IsDefault", False):
            elbv2_client.delete_rule(RuleArn=rule["RuleArn"])
            rules_removed += 1

    if rules_removed > 0:
        logger.info(f"Removed {rules_removed} rules")
    else:
        logger.info(f"No rules to remove")

    # Configure authentication action
    logger.info("Configuring OIDC authentication")

    auth_action = {
        "Type": "authenticate-oidc",
        "AuthenticateOidcConfig": {
            "Issuer": issuer,
            "AuthorizationEndpoint": auth_endpoint,
            "TokenEndpoint": token_endpoint,
            "UserInfoEndpoint": userinfo_endpoint,
            "ClientId": client_id,
            "ClientSecret": client_secret,
            "SessionCookieName": session_cookie_name,
            "SessionTimeout": session_timeout,
            "Scope": scope,
            "OnUnauthenticatedRequest": "authenticate",
        },
    }

    # Set default action to 503
    logger.info("Setting default listener action to deny unauthorized access")
    elbv2_client.modify_listener(
        ListenerArn=listener_arn,
        DefaultActions=[
            {
                "Type": "fixed-response",
                "FixedResponseConfig": {
                    "MessageBody": "Unauthorized Access",
                    "StatusCode": "503",
                    "ContentType": "text/plain",
                },
            }
        ],
    )

    # Create authenticated access rule
    logger.info("Creating authentication rule")
    elbv2_client.create_rule(
        ListenerArn=listener_arn,
        Priority=1,
        Conditions=[{"Field": "path-pattern", "Values": ["/*"]}],
        Actions=[
            {**auth_action, "Order": 1},
            {"Type": "forward", "TargetGroupArn": target_group_arn, "Order": 2},
        ],
    )

    # Configure HTTP to HTTPS redirect
    logger.info("Configuring HTTP to HTTPS redirect")
    http_listener = next(
        (
            l
            for l in elbv2_client.describe_listeners(LoadBalancerArn=load_balancer_arn)[
                "Listeners"
            ]
            if l["Port"] == 80
        ),
        None,
    )
    if http_listener:
        elbv2_client.modify_listener(
            ListenerArn=http_listener["ListenerArn"],
            DefaultActions=[
                {
                    "Type": "redirect",
                    "RedirectConfig": {
                        "Protocol": "HTTPS",
                        "Port": "443",
                        "StatusCode": "HTTP_301",
                    },
                }
            ],
        )
    else:
        logger.info("HTTP listener not found")

    logger.info(f"OIDC authentication successfully configured for https://{domain}")

    return {
        "domain": domain,
        "issuer": issuer,
        "client_id": client_id,
    }
