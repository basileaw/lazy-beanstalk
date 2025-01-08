#!/bin/bash
set -e # Exit on error
export PYTHONWARNINGS="ignore"

echo "1. Cleaning up previous configuration..."
rm -rf .elasticbeanstalk/

echo "2. Checking environment status..."
ENV_STATUS=$(aws elasticbeanstalk describe-environments \
    --environment-names simple-ship-env \
    --query 'Environments[0].Status' \
    --output text 2>/dev/null || echo "DOES_NOT_EXIST")

if [ "$ENV_STATUS" != "DOES_NOT_EXIST" ] && [ "$ENV_STATUS" != "Terminated" ]; then
    echo "Terminating environment..."
    aws elasticbeanstalk terminate-environment --environment-name simple-ship-env
    echo "Waiting for environment termination..."
    while aws elasticbeanstalk describe-environments --environment-names simple-ship-env --query 'Environments[0].Status' --output text 2>/dev/null | grep -q -E 'Terminating|Ready'; do
        echo -n "."
        sleep 10
    done
    echo " Done!"
fi

echo "3. Initializing Elastic Beanstalk application..."
eb init \
    --platform docker \
    --region us-west-2 \
    simple-ship

echo "4. Creating new environment..."
eb create simple-ship-env --single --verbose

echo "5. Configuring security group..."
INSTANCE_ID=$(aws elasticbeanstalk describe-environment-resources --environment-name simple-ship-env --query 'EnvironmentResources.Instances[0].Id' --output text)
SG_ID=$(aws ec2 describe-instances --instance-ids $INSTANCE_ID --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)
aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 7681 \
    --cidr 0.0.0.0/0

echo "6. Deploying application..."
eb deploy --verbose

echo "Setup complete!"