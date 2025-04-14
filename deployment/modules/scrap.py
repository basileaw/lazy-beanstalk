# scrap.py

"""Clean up Elastic Beanstalk environment and associated resources."""

import shutil
from typing import Dict
from botocore.exceptions import ClientError

from . import common
from .configure import (
    ConfigurationManager, ClientManager, ProgressIndicator, logger
)

def cleanup_local_config() -> None:
    """Remove local EB CLI configuration."""
    config_dir = ConfigurationManager.get_project_root() / '.elasticbeanstalk'
    if config_dir.exists():
        ProgressIndicator.start("Removing .elasticbeanstalk configuration directory")
        shutil.rmtree(config_dir)
        logger.info("Removed .elasticbeanstalk configuration directory")

@common.aws_handler
def cleanup_oidc(env_name: str) -> None:
    """Clean up OIDC authentication rules from ALB listener."""
    eb_client = ClientManager.get_client('elasticbeanstalk')
    elbv2_client = ClientManager.get_client('elbv2')
    
    # Find load balancer first
    ProgressIndicator.start("Checking for OIDC authentication rules")
    lb_arn = common.find_environment_load_balancer(env_name)
    if not lb_arn:
        ProgressIndicator.complete("load balancer not found")
        return

    # Find HTTPS listener
    try:
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
        https_listener = next((l for l in listeners if l['Port'] == 443), None)
        
        if not https_listener:
            ProgressIndicator.complete("no HTTPS listener")
            logger.info("No HTTPS listener found, skipping OIDC cleanup")
            return
        
        # Check for OIDC rules
        rules = elbv2_client.describe_rules(ListenerArn=https_listener['ListenerArn'])['Rules']
        oidc_rules = [r for r in rules if not r.get('IsDefault', False) and 
                      any(a.get('Type') == 'authenticate-oidc' for a in r.get('Actions', []))]
        
        if not oidc_rules:
            ProgressIndicator.complete("no rules found")
            logger.info("No OIDC authentication rules found")
            return
        
        ProgressIndicator.complete(f"Found {len(oidc_rules)} rules")
        
        # Delete OIDC rules
        ProgressIndicator.start("Removing OIDC authentication rules")
        for rule in oidc_rules:
            logger.info(f"Removing rule: {rule['RuleArn']}")
            elbv2_client.delete_rule(RuleArn=rule['RuleArn'])
        
        # Restore default action to forward traffic
        # Get target group
        ProgressIndicator.start("Restoring default HTTPS listener action")
        target_groups = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn)['TargetGroups']
        if target_groups:
            target_group_arn = target_groups[0]['TargetGroupArn']
            elbv2_client.modify_listener(
                ListenerArn=https_listener['ListenerArn'],
                DefaultActions=[{
                    'Type': 'forward',
                    'TargetGroupArn': target_group_arn
                }]
            )
            ProgressIndicator.complete("restored")
            logger.info("OIDC authentication rules removed successfully")
        else:
            logger.warning("Could not restore default action: no target groups found")
        
    except ClientError as e:
        if e.response['Error']['Code'] not in ['LoadBalancerNotFound', 'ListenerNotFound']:
            ProgressIndicator.complete("error")
            raise
        ProgressIndicator.complete("resource not found")

@common.aws_handler
def cleanup_https(env_name: str, project_name: str) -> None:
    """Clean up HTTPS listener and DNS record if they exist."""
    eb_client = ClientManager.get_client('elasticbeanstalk')
    elbv2_client = ClientManager.get_client('elbv2')
    r53_client = ClientManager.get_client('route53')
    
    # Find load balancer first
    ProgressIndicator.start("Checking HTTPS configuration")
    lb_arn = common.find_environment_load_balancer(env_name)
    if not lb_arn:
        ProgressIndicator.complete("load balancer not found")
        return

    # Check if HTTPS is enabled
    is_https_enabled, cert_arn = common.get_https_status(lb_arn, project_name)
    if not is_https_enabled:
        ProgressIndicator.complete("not enabled")
        return
    logger.info("Found HTTPS configuration, cleaning up")
    
    # Clean up HTTPS listener
    try:
        ProgressIndicator.start("Removing HTTPS listener")
        listeners = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)['Listeners']
        https_listener = next((l for l in listeners if l['Port'] == 443), None)
        if https_listener:
            elbv2_client.delete_listener(ListenerArn=https_listener['ListenerArn'])
            logger.info("Removed HTTPS listener")
        else:
            ProgressIndicator.complete("not found")
    except ClientError as e:
        if e.response['Error']['Code'] not in ['LoadBalancerNotFound', 'ListenerNotFound']:
            ProgressIndicator.complete("error")
            raise
        ProgressIndicator.complete("resource not found")

    # Clean up DNS record
    try:
        if cert_arn:  # Only proceed if we have a certificate ARN
            # Get the domain from the certificate
            ProgressIndicator.start("Cleaning up DNS record")
            acm_client = ClientManager.get_client('acm')
            cert = acm_client.describe_certificate(CertificateArn=cert_arn)['Certificate']
            domain = cert['DomainName'].replace('*', project_name)
            
            # Get the load balancer DNS name
            lb = elbv2_client.describe_load_balancers(LoadBalancerArns=[lb_arn])['LoadBalancers'][0]
            lb_dns = lb['DNSName']
            
            zones = r53_client.list_hosted_zones()['HostedZones']
            zone = next((z for z in zones if domain.endswith(z['Name'].rstrip('.'))), None)
            
            if zone:
                records = r53_client.list_resource_record_sets(
                    HostedZoneId=zone['Id'],
                    StartRecordName=domain,
                    StartRecordType='CNAME',
                    MaxItems='1'
                )['ResourceRecordSets']
                
                record = next((r for r in records if r['Name'] == f"{domain}."), None)
                if record and record['ResourceRecords'][0]['Value'] == lb_dns:
                    logger.info(f"Removing DNS record for {domain}")
                    r53_client.change_resource_record_sets(
                        HostedZoneId=zone['Id'],
                        ChangeBatch={
                            'Changes': [{
                                'Action': 'DELETE',
                                'ResourceRecordSet': record
                            }]
                        }
                    )
                else:
                    ProgressIndicator.complete("no matching record")
            else:
                ProgressIndicator.complete("no matching hosted zone")
    except ClientError as e:
        if e.response['Error']['Code'] not in ['LoadBalancerNotFound', 'NoSuchHostedZone']:
            ProgressIndicator.complete("error")
            raise
        ProgressIndicator.complete("resource not found")

@common.aws_handler
def cleanup_instance_profile(config: Dict) -> None:
    """Clean up instance profile and role."""
    iam_client = ClientManager.get_client('iam')
    profile_name = config['iam']['instance_profile_name']
    role_name = config['iam']['instance_role_name']

    try:
        ProgressIndicator.start(f"Cleaning up instance profile {profile_name}")
        
        # Remove role from profile
        iam_client.remove_role_from_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name
        )
        logger.info(f"Removed role from instance profile: {role_name}")

        # Delete profile
        iam_client.delete_instance_profile(InstanceProfileName=profile_name)
        logger.info(f"Deleted instance profile: {profile_name}")
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            ProgressIndicator.complete("error")
            raise
        ProgressIndicator.complete("not found")

    # Clean up the role
    common.manage_iam_role(
        role_name,
        config['iam']['instance_role_policies'],
        action='cleanup'
    )

@common.aws_handler
def cleanup_s3_bucket(config: Dict) -> None:
    """Clean up the application version S3 bucket."""
    s3_client = ClientManager.get_client('s3')
    bucket = f"elasticbeanstalk-{config['aws']['region']}-{config['application']['name'].lower()}"
    
    ProgressIndicator.start(f"Cleaning up S3 bucket {bucket}")
    
    try:
        # Delete all objects
        object_count = 0
        paginator = s3_client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket):
            if 'Contents' in page:
                objects = [{'Key': obj['Key']} for obj in page['Contents']]
                s3_client.delete_objects(Bucket=bucket, Delete={'Objects': objects})
                object_count += len(objects)
                # Show progress for large buckets
                if object_count > 0 and object_count % 100 == 0:
                    ProgressIndicator.step()

        # Delete bucket
        s3_client.delete_bucket(Bucket=bucket)
        logger.info(f"Removed {object_count} objects")
        logger.info(f"Deleted S3 bucket: {bucket}")
    except ClientError as e:
        if e.response['Error']['Code'] not in ['NoSuchBucket', 'NoSuchKey']:
            ProgressIndicator.complete("error")
            raise
        ProgressIndicator.complete("not found")

def cleanup_application(config: Dict) -> None:
    """Clean up all Elastic Beanstalk resources."""
    project_name = ConfigurationManager.get_project_name()
    env_name = config['application']['environment']
    
    logger.info("Starting cleanup process")
    
    # Clean up OIDC rules first (before we remove the HTTPS listener)
    cleanup_oidc(env_name)
    
    # Clean up HTTPS resources next
    cleanup_https(env_name, project_name)

    # Terminate environment if it exists
    try:
        eb_client = ClientManager.get_client('elasticbeanstalk')
        ProgressIndicator.start(f"Checking if environment {env_name} exists")
        
        env_exists = bool(eb_client.describe_environments(
            EnvironmentNames=[env_name],
            IncludeDeleted=False
        )['Environments'])

        if env_exists:
            logger.info(f"Terminating environment: {env_name}")
            eb_client.terminate_environment(EnvironmentName=env_name)
            common.wait_for_env_status(env_name, 'Terminated')
        else:
            ProgressIndicator.complete("not found")
    except ClientError:
        ProgressIndicator.complete("error checking")

    # Check if there are any other environments before cleaning up shared resources
    ProgressIndicator.start("Checking for other active environments")
    no_other_envs = not common.check_env_exists()
    
    if no_other_envs:
        logger.info("No active environments found, cleaning up shared resources")
        
        # Clean up IAM resources
        cleanup_instance_profile(config)
        common.manage_iam_role(
            config['iam']['service_role_name'],
            config['iam']['service_role_policies'],
            action='cleanup'
        )
        
        # Clean up S3 bucket
        cleanup_s3_bucket(config)

        # Delete application
        ProgressIndicator.start(f"Deleting application {config['application']['name']}")
        try:
            eb_client = ClientManager.get_client('elasticbeanstalk')
            eb_client.delete_application(
                ApplicationName=config['application']['name'],
                TerminateEnvByForce=True
            )
            ProgressIndicator.complete("deleted")
            logger.info(f"Deleted application: {config['application']['name']}")
        except ClientError:
            ProgressIndicator.complete("error or not found")
    else:
        logger.info("Other environments still active. Skipping resource cleanup.")

    # Remove local configuration
    cleanup_local_config()
    
    logger.info("Cleanup complete!")