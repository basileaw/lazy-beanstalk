#!/bin/bash
set -e # Exit on error
export PYTHONWARNINGS="ignore"

# Function to check if environment exists
check_env_exists() {
    eb status lazy-beanstalk-env &>/dev/null
    return $?
}

# Function for clean error output
error() {
    echo "ERROR: $1" >&2
    exit 1
}

echo "1. Initializing Elastic Beanstalk application..."
eb init \
    --platform "Docker" \
    --region us-west-2 \
    lazy-beanstalk || error "Failed to initialize Elastic Beanstalk application"

echo "2. Checking environment status..."
if check_env_exists; then
    echo "Environment exists, deploying updates..."
    eb deploy lazy-beanstalk-env || error "Failed to deploy to existing environment"
else
    echo "Creating new environment..."
    eb create lazy-beanstalk-env \
        --elb-type application \
        --instance-type t3.micro || error "Failed to create environment"
fi

# echo "3. Configuring security group..."
# INSTANCE_ID=$(aws elasticbeanstalk describe-environment-resources \
#     --environment-name lazy-beanstalk-env \
#     --query 'EnvironmentResources.Instances[0].Id' \
#     --output text) || error "Failed to get instance ID"

# if [ "$INSTANCE_ID" == "None" ] || [ -z "$INSTANCE_ID" ]; then
#     error "No instance found for environment"
# fi

# SG_ID=$(aws ec2 describe-instances \
#     --instance-ids ${INSTANCE_ID} \
#     --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
#     --output text) || error "Failed to get security group ID"

# if [ "$SG_ID" == "None" ] || [ -z "$SG_ID" ]; then
#     error "No security group found for instance"
# fi

# echo "4. Adding/updating security group rule for ttyd..."
# aws ec2 describe-security-groups \
#     --group-ids ${SG_ID} \
#     --query 'SecurityGroups[0].IpPermissions[?FromPort==`7681`]' \
#     --output text | grep -q . && \
#     aws ec2 revoke-security-group-ingress \
#         --group-id ${SG_ID} \
#     --protocol tcp \
#     --port 7681 \
#         --cidr 0.0.0.0/0 \
#         || true
#     aws ec2 authorize-security-group-ingress \
#         --group-id ${SG_ID} \
#         --protocol tcp \
#         --port 7681 \
#         --cidr 0.0.0.0/0 \
#     || error "Failed to configure security group rule"

echo "Deployment complete!"