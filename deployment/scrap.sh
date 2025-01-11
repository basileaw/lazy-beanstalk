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
    exit 0
fi

# If we get here, the environment exists and needs to be terminated
echo "Terminating environment..."
aws elasticbeanstalk terminate-environment --environment-name simple-ship-env

echo "Waiting for environment termination..."
while aws elasticbeanstalk describe-environments --environment-names simple-ship-env --query "Environments[0].Status" --output text 2>/dev/null | grep -q -E "Terminating|Ready"; do
    echo -n "."
    sleep 10
done

echo "Cleaning up previous configuration..."
rm -rf .elasticbeanstalk/
echo " Done!"