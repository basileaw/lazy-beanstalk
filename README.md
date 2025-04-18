# Lazy Beanstalk

Lazy Beanstalk is a Python deployment package for AWS Elastic Beanstalk that lets you deploy your Python web applications with minimal effort. Perfect for solo developers and Python beginners who want to quickly share their projects without spending days figuring out cloud deployment.

## How It Works

Lazy Beanstalk provides a simple template for deploying Python applications on AWS Elastic Beanstalk. It handles the complex configuration, infrastructure setup, and deployment process for you. Just install it into your project, run a single command, and your application is live with a public URL.

### Compatibility with EB CLI

Lazy Beanstalk works alongside the standard Elastic Beanstalk CLI. If you're familiar with `eb` commands, you can continue using them after initial deployment. Lazy Beanstalk creates the proper configuration files that make it compatible with standard EB operations.

### Prerequisites

- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Docker Desktop installed locally 
- Python 3.12 or newer
- An existing Python web application (or a new one) that you'd like to deploy ;) 

## Installation

Install Lazy Beanstalk directly into your project with a single command 

```bash
curl -sSL https://raw.githubusercontent.com/anotherbazeinthewall/lazy-beanstalk/main/installer.sh | bash
```

This adds a `deployment` directory, Dockerfile, .dockerignore, .ebignore and Makefile (that you're free to customize at your discretion)

## Usage

The Makefile defines a series of tasks for testing, shipping, securing and tearing down your application. 
```bash
make serve
```
Runs your application locally for development testing. The command executes `app/main.py` directly on your local machine, providing a development server with hot-reloading and logging output to your terminal.
```bash
make spin
```
Runs your application in a Docker container for a production-like test. This builds a Docker image using your project's Dockerfile, auto-detects Python dependencies, mounts AWS credentials, and exposes your application on port 8000.
```bash
make ship
```
Deploys your application to AWS Elastic Beanstalk. The process creates necessary IAM roles, packages and uploads your code to S3, and creates or updates your Elastic Beanstalk environment. Deployment typically takes 5-10 minutes and outputs your application's URL upon completion.
```bash
make secure
```
Enables HTTPS for your deployed application. The command configures your load balancer with an HTTPS listener using your AWS Certificate Manager certificates, sets up appropriate security groups, and creates DNS records if your domain matches the certificate.
```bash
make shield
```
Adds OIDC authentication to your application. This configures your load balancer to handle authentication, securing all paths behind a login requirement. Users will be redirected to your identity provider for authentication before accessing your application.
```bash
make scrap
```
Removes all AWS resources created by Lazy Beanstalk. The command terminates your environment, deletes IAM roles and S3 buckets, removes HTTPS and OIDC configurations, and cleans up local files. This process takes 5-15 minutes and prevents ongoing AWS charges.

## Configuration

Lazy Beanstalk allows for batteries-included deployment, but there are a few ways to customize at your discretion. 

### Config.yml

The `config.yml` file controls all deployment settings. Key variables are automatically filled in:

- `${PROJECT_NAME}`: Your project directory name
- `${AWS_REGION}`: Your AWS region
- `${LATEST_DOCKER_PLATFORM}`: The latest Elastic Beanstalk Docker platform

### IAM

Lazy Beanstalk automatically creates and manages IAM roles for your application. Custom policies can be added to the `deployment/policies` directory as JSON files.

### OIDC Authentication

To use OIDC authentication (with the `shield` command), you'll need to set these environment variables or be ready to enter them when prompted:

- `OIDC_CLIENT_ID`: Your OIDC client ID
- `OIDC_CLIENT_SECRET`: Your OIDC client secret
- `OIDC_ISSUER`: Your OIDC provider issuer URL
- `OIDC_AUTH_ENDPOINT`: Authorization endpoint URL
- `OIDC_TOKEN_ENDPOINT`: Token endpoint URL
- `OIDC_USERINFO_ENDPOINT`: User info endpoint URL

These can be stored in a `.env` file (which is automatically added to `.gitignore`).

## A Few Considerations

- Lazy Beanstalk is designed for prototypes and small tools and is not suitable for production-grade applications.
- Implementing HTTPS/OIDC via an Application Load Balancer can get pricey. 
- Be cautious with IAM permissions - only add what you need.
- Never commit `.env` files to version control.

## Acknowledgements

Lazy Beanstalk was built with plenty of LLM assistance, particularly from [Anthropic](https://github.com/anthropics), [Mistral](https://github.com/mistralai) and [Continue.dev](https://github.com/continuedev/continue).