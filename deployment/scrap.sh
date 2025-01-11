#!/bin/bash
set -e # Exit on error
export PYTHONWARNINGS="ignore"
export AWS_PAGER="cat"

echo "Checking environment status..."
ENV_CHECK=$(aws elasticbeanstalk describe-environments \
    --environment-names simple-ship-env \
    --query "length(Environments[])" \
    --output text 2>/dev/null || echo "0")

if [ "$ENV_CHECK" = "0" ]; then
    echo "Environment 'simple-ship-env' does not exist or is already terminated."
else
    # If we get here, the environment exists and needs to be terminated
    echo "Terminating environment..."
    aws elasticbeanstalk terminate-environment --environment-name simple-ship-env

    echo "Waiting for environment termination..."
    while aws elasticbeanstalk describe-environments --environment-names simple-ship-env --query "Environments[0].Status" --output text 2>/dev/null | grep -q -E "Terminating|Ready"; do
        echo -n "."
        sleep 10
    done
fi

# Check if the service role exists and if it's not being used by other environments
echo "Checking service role usage..."
ROLE_IN_USE=$(aws elasticbeanstalk describe-environments \
    --query "length(Environments[])" \
    --output text)

if [ "$ROLE_IN_USE" = "0" ]; then
    echo "Attempting to delete service role..."
    # First detach the policies
    aws iam detach-role-policy \
        --role-name aws-elasticbeanstalk-service-role \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth 2>/dev/null || true
    aws iam detach-role-policy \
        --role-name aws-elasticbeanstalk-service-role \
        --policy-arn arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkService 2>/dev/null || true
    
    # Then delete the role
    aws iam delete-role --role-name aws-elasticbeanstalk-service-role 2>/dev/null || true
    echo "Service role deleted or was already removed."
else
    echo "Service role still in use by other environments. Skipping role deletion."
fi

echo "Cleaning up previous configuration..."
rm -rf .elasticbeanstalk/
echo " Done!"