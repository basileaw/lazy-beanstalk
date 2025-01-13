#!/bin/bash
set -e # Exit on error
export PYTHONWARNINGS="ignore"

# Function to check if environment exists
check_env_exists() {
    eb status lazy-beanstalk-env &>/dev/null
    return $?
}

# Function to check if role exists
check_role_exists() {
    aws iam get-role --role-name lazy-beanstalk-eb-role &>/dev/null
    return $?
}

# Function for clean error output
error() {
    echo "ERROR: $1" >&2
    exit 1
}

echo "1. Creating IAM role if it doesn't exist..."
if ! check_role_exists; then
    # Create trust policy JSON file
    cat > trust-policy.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Principal": {
                "Service": "elasticbeanstalk.amazonaws.com"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "elasticbeanstalk"
                }
            }
        }
    ]
}
EOF

    # Create the role
    aws iam create-role \
        --role-name lazy-beanstalk-eb-role \
        --assume-role-policy-document file://trust-policy.json || error "Failed to create IAM role"

    # Attach necessary policies
    aws iam attach-role-policy \
        --role-name lazy-beanstalk-eb-role \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService || error "Failed to attach service policy"

    aws iam attach-role-policy \
        --role-name lazy-beanstalk-eb-role \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth || error "Failed to attach enhanced health policy"

    # Clean up the temporary file
    rm trust-policy.json
    
    # Wait for role to propagate
    echo "Waiting for role to propagate..."
    sleep 10
fi

echo "2. Initializing Elastic Beanstalk application..."
eb init \
    --platform "Docker" \
    # --region us-west-2 \
    lazy-beanstalk || error "Failed to initialize Elastic Beanstalk application"

echo "3. Checking environment status..."
if check_env_exists; then
    echo "Environment exists, deploying updates..."
    eb deploy lazy-beanstalk-env || error "Failed to deploy to existing environment"
else
    echo "Creating new environment..."
    eb create lazy-beanstalk-env \
        --elb-type application \
        --instance-type t3.micro \
        --service-role lazy-beanstalk-eb-role || error "Failed to create environment"
fi

# echo "Configuring security group..."
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

# echo "Adding/updating security group rule for ttyd..."
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