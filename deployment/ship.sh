#!/bin/bash
set -e # Exit on error
export PYTHONWARNINGS="ignore"

# Function to check if a role exists
check_role_exists() {
    local role_name=$1
    aws iam get-role --role-name "$role_name" &>/dev/null
    return $?
}

# Function to check if an instance profile exists
check_instance_profile_exists() {
    local profile_name=$1
    aws iam get-instance-profile --instance-profile-name "$profile_name" &>/dev/null
    return $?
}

# Function to check if environment exists
check_env_exists() {
    local env_name=$1
    eb status "$env_name" &>/dev/null
    return $?
}

# Function for clean error output
error() {
    echo "ERROR: $1" >&2
    exit 1
}

# Load configuration
if ! command -v yq &>/dev/null; then
    error "yq is required but not installed. Please install yq to parse YAML configuration."
fi

# Read configuration values using yq
CONFIG_FILE="deployment/configurations/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    error "Configuration file $CONFIG_FILE not found"
fi

# Read values from config
AWS_REGION=$(yq '.aws.region' "$CONFIG_FILE")
APP_NAME=$(yq '.application.name' "$CONFIG_FILE")
ENV_NAME=$(yq '.application.environment' "$CONFIG_FILE")
INSTANCE_TYPE=$(yq '.instance.type' "$CONFIG_FILE")
ELB_TYPE=$(yq '.instance.elb_type' "$CONFIG_FILE")
SERVICE_ROLE_NAME=$(yq '.iam.service_role_name' "$CONFIG_FILE")
INSTANCE_ROLE_NAME=$(yq '.iam.instance_role_name' "$CONFIG_FILE")
INSTANCE_PROFILE_NAME=$(yq '.iam.instance_profile_name' "$CONFIG_FILE")

echo "1. Setting up IAM roles..."

# Create EB service role if it doesn't exist
if ! check_role_exists "$SERVICE_ROLE_NAME"; then
    echo "Creating Elastic Beanstalk service role..."
    aws iam create-role \
        --role-name "$SERVICE_ROLE_NAME" \
        --assume-role-policy-document file://deployment/policies/trust-policy.json || error "Failed to create EB service role"

    # Attach service role policies
    while IFS= read -r policy_arn; do
        aws iam attach-role-policy \
            --role-name "$SERVICE_ROLE_NAME" \
            --policy-arn "$policy_arn" || error "Failed to attach policy $policy_arn to service role"
    done < <(yq '.iam.service_role_policies[]' "$CONFIG_FILE")
    
    echo "Waiting for service role to propagate..."
    sleep 10
fi

# Create EC2 instance role if it doesn't exist
if ! check_role_exists "$INSTANCE_ROLE_NAME"; then
    echo "Creating EC2 instance role..."
    aws iam create-role \
        --role-name "$INSTANCE_ROLE_NAME" \
        --assume-role-policy-document file://deployment/policies/ec2-trust-policy.json || error "Failed to create EC2 instance role"

    # Attach instance role policies
    while IFS= read -r policy_arn; do
        aws iam attach-role-policy \
            --role-name "$INSTANCE_ROLE_NAME" \
            --policy-arn "$policy_arn" || error "Failed to attach policy $policy_arn to instance role"
    done < <(yq '.iam.instance_role_policies[]' "$CONFIG_FILE")
fi

# Create instance profile if it doesn't exist
if ! check_instance_profile_exists "$INSTANCE_PROFILE_NAME"; then
    echo "Creating EC2 instance profile..."
    aws iam create-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" || error "Failed to create instance profile"
    
    # Add role to instance profile
    aws iam add-role-to-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" \
        --role-name "$INSTANCE_ROLE_NAME" || error "Failed to add role to instance profile"
    
    echo "Waiting for instance profile to propagate..."
    sleep 10
fi

echo "2. Initializing Elastic Beanstalk application..."
eb init \
    --platform "Docker" \
    --region "$AWS_REGION" \
    "$APP_NAME" || error "Failed to initialize Elastic Beanstalk application"

echo "3. Checking environment status..."
if check_env_exists "$ENV_NAME"; then
    echo "Environment exists, deploying updates..."
    eb deploy "$ENV_NAME" || error "Failed to deploy to existing environment"
else
    echo "Creating new environment..."
    eb create "$ENV_NAME" \
        --elb-type "$ELB_TYPE" \
        --instance-type "$INSTANCE_TYPE" \
        --service-role "$SERVICE_ROLE_NAME" \
        --instance_profile "$INSTANCE_PROFILE_NAME" || error "Failed to create environment"
fi

echo "Deployment complete!"