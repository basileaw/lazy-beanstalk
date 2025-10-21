# Lazy Beanstalk

A simple pip-installable tool for deploying Python applications to AWS Elastic Beanstalk. Perfect for solo developers and Python beginners who want to quickly ship their projects without spending days figuring out cloud deployment.

## Features

- **Zero-config deployment** with smart defaults (us-west-2, t4g.nano, etc.)
- **Environment variable support** via `.env` file with hybrid naming (LB_* with standard fallbacks)
- **Auto-OIDC** - `secure` command detects OIDC env vars and configures authentication automatically
- **Both CLI and Python API** for maximum flexibility
- **One-command operations** for deployment, HTTPS, OIDC auth, and cleanup
- **Automatic change detection** for environment updates
- **Compatible with EB CLI** - works alongside standard Elastic Beanstalk tools

## Prerequisites

- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Python 3.12 or newer
- A Dockerfile for your application
- An existing Python web application (or a new one) that you'd like to deploy

## Installation

Install directly from GitHub using pip:

```bash
pip install git+https://github.com/bazeindustries/lazy-beanstalk.git
```

Or with pipx for isolated installation:

```bash
pipx install git+https://github.com/bazeindustries/lazy-beanstalk.git
```

Or with Poetry in your project:

```bash
poetry add git+https://github.com/bazeindustries/lazy-beanstalk.git
```

## Quick Start

### CLI Usage

Deploy your application with a single command:

```bash
lb ship
```

That's it! Lazy Beanstalk will:
- Use your current directory name as the app name
- Create an environment named `{app-name}-env`
- Deploy to `us-west-2` using `t4g.nano` instances
- Package and upload your application using the Dockerfile in your project root
- Create all necessary IAM roles and S3 buckets
- Output your application URL when complete

Enable HTTPS (auto-configures OIDC if env vars present):

```bash
lb secure
```

Or add OIDC separately:

```bash
lb shield
```

Clean up all resources:

```bash
lb scrap
```

### Python API Usage

For programmatic control, import and use the Python API:

```python
from lazy_beanstalk import ship, secure, shield, scrap

# Deploy with custom configuration
result = ship(
    app_name="my-app",
    region="us-east-1",
    instance_type="t3.small",
    spot_instances=True,
    min_instances=2,
    max_instances=4,
    env_vars={
        "DATABASE_URL": "postgres://...",
        "API_KEY": "secret"
    },
    tags={
        "Environment": "production",
        "Team": "platform"
    }
)

print(f"Deployed to: {result['environment_url']}")

# Enable HTTPS
https_result = secure(
    domain="api.example.com",
    domain_mode="sub"
)

# Add authentication
auth_result = shield(
    client_id="oauth-client-id",
    client_secret="oauth-secret",
    issuer="https://auth.example.com",
    auth_endpoint="https://auth.example.com/authorize",
    token_endpoint="https://auth.example.com/token",
    userinfo_endpoint="https://auth.example.com/userinfo"
)

# Clean up
cleanup_result = scrap(force=True)
```

## Configuration

### Smart Defaults

Lazy Beanstalk uses sensible defaults for quick deployments:

- **Region**: `us-west-2`
- **Instance Type**: `t4g.nano` (ARM-based, cost-effective)
- **Autoscaling**: Min 1, Max 1 instance
- **Spot Instances**: Disabled
- **Load Balancer**: Application Load Balancer
- **Platform**: Latest Amazon Linux 2023 Docker platform
- **Tags**: `Environment=development`, `ManagedBy=lazy-beanstalk`

### Configuration Hierarchy

Configuration is merged from multiple sources (lowest to highest priority):

1. **Hardcoded defaults** (see above)
2. **Environment variables** (`.env` file, auto-loaded)
3. **State file** (`.elasticbeanstalk/config.yml`)
4. **API parameters** or **CLI flags**

### Environment Variables

**Deployment Configuration** (via `.env` file):

```bash
# .env file (auto-loaded)
AWS_REGION=us-west-2
LB_INSTANCE_TYPE=t4g.small
LB_SPOT_INSTANCES=true
LB_MIN_INSTANCES=2
LB_MAX_INSTANCES=4

# HTTPS
LB_CERTIFICATE_ARN=arn:aws:acm:...
LB_DOMAIN_MODE=custom
LB_CUSTOM_SUBDOMAINS=api,admin,app

# OIDC (auto-configures when running 'lb secure')
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-secret
OIDC_ISSUER=https://your-idp.com
OIDC_AUTH_ENDPOINT=https://your-idp.com/oauth2/authorize
OIDC_TOKEN_ENDPOINT=https://your-idp.com/oauth2/token
OIDC_USERINFO_ENDPOINT=https://your-idp.com/oauth2/userInfo
```

**Application Environment Variables** (passed to your app):

```python
ship(
    env_vars={
        "DATABASE_URL": os.getenv("DATABASE_URL"),
        "API_KEY": os.getenv("API_KEY")
    }
)
```

### State File

Lazy Beanstalk stores state in `.elasticbeanstalk/config.yml` (EB CLI compatible) to:
- Track deployment configuration and detect changes
- Enable `eb logs`, `eb ssh`, and other EB CLI commands
- Store environment metadata

### IAM Policies

Lazy Beanstalk automatically creates IAM roles with AWS managed policies:

**Service Role**:
- `AWSElasticBeanstalkService`
- `AWSElasticBeanstalkEnhancedHealth`

**Instance Role**:
- `AWSElasticBeanstalkWebTier`
- `AWSElasticBeanstalkMulticontainerDocker`
- `AWSElasticBeanstalkWorkerTier`

Add custom policies by creating a directory with JSON policy files:

```python
ship(policies_dir="./my-policies")
```

Policy files in `./my-policies/*.json` will be:
- Created as customer-managed IAM policies
- Attached to the EC2 instance role
- Synchronized on each deployment (1:1 local-to-cloud sync)
- Versioned in AWS (up to 5 versions maintained)
- Removed from AWS if deleted locally

### HTTPS Configuration

Enable HTTPS using AWS Certificate Manager. If OIDC env vars are present, OIDC is auto-configured too:

```bash
# Via .env file (recommended)
# Add LB_CERTIFICATE_ARN, LB_DOMAIN_MODE, OIDC_* vars to .env
lb secure

# Or via CLI flags
lb secure --certificate-arn arn:aws:acm:... --domain-mode custom
```

**Domain Modes**:
- `sub`: Creates `{app-name}.example.com`
- `root`: Creates `example.com`
- `custom`: Creates multiple subdomains from `LB_CUSTOM_SUBDOMAINS=api,admin,app`

### OIDC Authentication

**Auto-configuration** (via `lb secure`):
```bash
# Add OIDC vars to .env, then:
lb secure  # Auto-configures OIDC if env vars present
```

**Standalone** (if not using auto-config):
```bash
# Via .env with OIDC_* vars
lb shield

# Or via CLI
lb shield --client-id <id> --client-secret <secret> --issuer <url> \
  --auth-endpoint <url> --token-endpoint <url> --userinfo-endpoint <url>
```

## CLI Reference

### `lb ship`

Deploy your application to AWS Elastic Beanstalk.

**Options**:
- `--app-name` - Application name (default: current directory name)
- `--environment-name` - Environment name (default: {app-name}-env)
- `--region` - AWS region (default: us-west-2)
- `--instance-type` - EC2 instance type (default: t4g.nano)
- `--spot/--no-spot` - Use spot instances (default: no-spot)
- `--min-instances` - Min autoscaling instances (default: 1)
- `--max-instances` - Max autoscaling instances (default: 1)
- `--policies-dir` - Path to custom IAM policies directory
- `--dockerfile-path` - Path to Dockerfile (default: ./Dockerfile)

**Example**:
```bash
lb ship --region us-east-1 --instance-type t3.small --spot --min-instances 2 --max-instances 4
```

### `lb secure`

Enable HTTPS with ACM and Route 53. Auto-configures OIDC if env vars present.

**Options**:
- `--certificate-arn` - ACM certificate ARN (or use LB_CERTIFICATE_ARN env var)
- `--domain-mode` - Domain mode: sub, root, or custom (or use LB_DOMAIN_MODE env var)
- `--custom-subdomains` - Comma-separated subdomains for custom mode (or use LB_CUSTOM_SUBDOMAINS)
- `--ttl` - DNS record TTL (default: 300)

**Example**:
```bash
# Recommended: use .env file
lb secure

# Or via CLI
lb secure --certificate-arn arn:aws:acm:... --domain-mode custom --custom-subdomains api,admin
```

### `lb shield`

Configure OIDC authentication on the load balancer. Reads from env vars by default.

**Options**:
All parameters optional if corresponding env vars are set (OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, etc.):
- `--client-id`, `--client-secret`, `--issuer`
- `--auth-endpoint`, `--token-endpoint`, `--userinfo-endpoint`
- `--session-timeout` - Session timeout in seconds (default: 36000)
- `--scope` - OIDC scope (default: openid)

**Example**:
```bash
# Recommended: use .env file with OIDC_* vars
lb shield

# Or use CLI
lb shield --client-id abc123 --client-secret xyz789 --issuer https://auth.example.com \
  --auth-endpoint https://auth.example.com/authorize \
  --token-endpoint https://auth.example.com/token \
  --userinfo-endpoint https://auth.example.com/userinfo
```

### `lb scrap`

Remove all AWS resources created by lazy-beanstalk.

**Options**:
- `--app-name` - Application name (default: from state file)
- `--force` - Skip confirmation prompts

**Example**:
```bash
lb scrap --force
```

## Python API Reference

### `ship(**kwargs)`

Deploy application to AWS Elastic Beanstalk.

**Parameters**:
- `app_name` (str): Application name
- `environment_name` (str): Environment name
- `region` (str): AWS region
- `instance_type` (str): EC2 instance type
- `spot_instances` (bool): Use spot instances
- `min_instances` (int): Min autoscaling instances
- `max_instances` (int): Max autoscaling instances
- `policies_dir` (str): Path to custom IAM policies directory
- `env_vars` (dict): Environment variables for application
- `tags` (dict): AWS resource tags
- `dockerfile_path` (str): Path to Dockerfile
- `aws_profile` (str): AWS profile name

**Returns**: Dict with deployment details (environment URL, app name, version, region)

### `secure(**kwargs)`

Enable HTTPS on your Elastic Beanstalk environment. Auto-configures OIDC if env vars present.

**Parameters**:
- `certificate_arn` (str): ACM certificate ARN
- `domain_mode` (str): Domain mode (sub, root, custom)
- `custom_subdomains` (list): List of subdomains for custom mode
- `include_root` (bool): Include root domain in custom mode
- `ttl` (int): DNS record TTL

**Returns**: Dict with HTTPS configuration details (and OIDC if auto-configured)

### `shield(**kwargs)`

Configure OIDC authentication.

**Parameters**:
- `client_id` (str): OIDC client ID
- `client_secret` (str): OIDC client secret
- `issuer` (str): OIDC issuer URL
- `auth_endpoint` (str): Authorization endpoint URL
- `token_endpoint` (str): Token endpoint URL
- `userinfo_endpoint` (str): User info endpoint URL
- `session_timeout` (int): Session timeout in seconds
- `session_cookie_name` (str): Session cookie name
- `scope` (str): OIDC scope

**Returns**: Dict with OIDC configuration details

### `scrap(**kwargs)`

Remove all AWS resources.

**Parameters**:
- `app_name` (str): Application name
- `force` (bool): Skip confirmation prompts

**Returns**: Dict with cleanup status

## Important Considerations

- **Cost Management**: Application Load Balancers (required for HTTPS/OIDC) cost ~$16/month minimum
- **Spot Instances**: Can reduce costs by up to 90% but may be interrupted
- **State File**: `.elasticbeanstalk/` directory tracked by lazy-beanstalk, compatible with EB CLI
- **Dockerfile Required**: You must provide your own Dockerfile for complete runtime control
- **Intended Use**: Designed for prototypes, demos, and small personal tools

## Compatibility with EB CLI

Lazy Beanstalk creates `.elasticbeanstalk/config.yml`, making it compatible with standard EB CLI commands:

```bash
eb status
eb logs
eb ssh
eb config
eb printenv
```

## Examples

### Minimal Deployment (Zero Config)

```bash
# Just needs a Dockerfile
lb ship
```

### Full Setup with HTTPS + OIDC

```bash
# .env file:
# AWS_REGION=us-east-1
# LB_INSTANCE_TYPE=t3.small
# LB_MIN_INSTANCES=2
# LB_MAX_INSTANCES=10
# LB_CERTIFICATE_ARN=arn:aws:acm:...
# OIDC_CLIENT_ID=...
# OIDC_CLIENT_SECRET=...
# OIDC_ISSUER=...
# OIDC_AUTH_ENDPOINT=...
# OIDC_TOKEN_ENDPOINT=...
# OIDC_USERINFO_ENDPOINT=...

lb ship && lb secure  # Auto-configures OIDC from env vars
```

### Cost-Optimized Development

```bash
lb ship --spot --instance-type t4g.nano --region us-west-2
```

### Complete Teardown

```bash
lb scrap --force
```

## Troubleshooting

### Deployment fails with "Dockerfile not found"

Ensure you have a `Dockerfile` in your project root. Lazy Beanstalk requires you to provide your own Dockerfile.

### Changes not applying to environment

Check the logs - Lazy Beanstalk detects and logs configuration changes. Some changes (like platform or load balancer type) require recreating the environment.

### HTTPS setup fails

Ensure:
- Your ACM certificate is issued and validated
- The certificate domain matches your `--domain` parameter
- Your Route 53 hosted zone exists for the domain

### OIDC authentication not working

Verify all required parameters are provided:
- `client_id`, `client_secret`, `issuer`
- `auth_endpoint`, `token_endpoint`, `userinfo_endpoint`

Check environment variables or pass them explicitly.

## Acknowledgements

Lazy Beanstalk was built with plenty of LLM assistance, particularly from [Anthropic](https://github.com/anthropics), [Mistral](https://github.com/mistralai) and [Continue.dev](https://github.com/continuedev/continue).
