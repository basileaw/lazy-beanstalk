#!/bin/bash
set -e # Exit on error
export PYTHONWARNINGS="ignore"
export AWS_PAGER="cat"

# Load configuration
if ! command -v yq &>/dev/null; then
    echo "ERROR: yq is required but not installed. Please install yq to parse YAML configuration." >&2
    exit 1
fi

# Read configuration values
CONFIG_FILE="deployment/configurations/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Configuration file $CONFIG_FILE not found" >&2
    exit 1
fi

# Read values from config
ENV_NAME=$(yq '.application.environment' "$CONFIG_FILE")
SERVICE_ROLE_NAME=$(yq '.iam.service_role_name' "$CONFIG_FILE")
INSTANCE_ROLE_NAME=$(yq '.iam.instance_role_name' "$CONFIG_FILE")
INSTANCE_PROFILE_NAME=$(yq '.iam.instance_profile_name' "$CONFIG_FILE")

echo "Checking environment status..."
ENV_CHECK=$(aws elasticbeanstalk describe-environments \
    --environment-names "$ENV_NAME" \
    --query "length(Environments[])" \
    --output text 2>/dev/null || echo "0")

if [ "$ENV_CHECK" = "0" ]; then
    echo "Environment '$ENV_NAME' does not exist or is already terminated."
else
    echo "Terminating environment..."
    aws elasticbeanstalk terminate-environment --environment-name "$ENV_NAME"
    echo "Waiting for environment termination..."
    while aws elasticbeanstalk describe-environments --environment-names "$ENV_NAME" --query "Environments[0].Status" --output text 2>/dev/null | grep -q -E "Terminating|Ready"; do
        echo -n "."
        sleep 10
    done
    echo "Environment terminated."
fi

# Check if the service role exists and if it's not being used by other environments
echo "Checking service role usage..."
ROLE_IN_USE=$(aws elasticbeanstalk describe-environments \
    --query "length(Environments[])" \
    --output text)

if [ "$ROLE_IN_USE" = "0" ]; then
    echo "Cleaning up IAM resources..."
    
    # Detach and delete service role
    echo "Cleaning up service role..."
    while IFS= read -r policy_arn; do
        aws iam detach-role-policy \
            --role-name "$SERVICE_ROLE_NAME" \
            --policy-arn "$policy_arn" 2>/dev/null || true
    done < <(yq '.iam.service_role_policies[]' "$CONFIG_FILE")
    aws iam delete-role --role-name "$SERVICE_ROLE_NAME" 2>/dev/null || true
    
    # Remove role from instance profile and delete it
    echo "Cleaning up instance profile..."
    aws iam remove-role-from-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" \
        --role-name "$INSTANCE_ROLE_NAME" 2>/dev/null || true
    aws iam delete-instance-profile \
        --instance-profile-name "$INSTANCE_PROFILE_NAME" 2>/dev/null || true
    
    # Detach and delete instance role
    echo "Cleaning up instance role..."
    while IFS= read -r policy_arn; do
        aws iam detach-role-policy \
            --role-name "$INSTANCE_ROLE_NAME" \
            --policy-arn "$policy_arn" 2>/dev/null || true
    done < <(yq '.iam.instance_role_policies[]' "$CONFIG_FILE")
    aws iam delete-role --role-name "$INSTANCE_ROLE_NAME" 2>/dev/null || true
    
    echo "IAM resources cleaned up."
else
    echo "Resources still in use by other environments. Skipping IAM resource deletion."
fi

echo "Cleaning up previous configuration..."
rm -rf .elasticbeanstalk/

echo "Done!"