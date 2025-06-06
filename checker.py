import boto3
import json
import os
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load environment variables from the .env file for local development
load_dotenv()

# --- Load AWS Resource Identifiers from Environment Variables ---
# These IDs scope the scan to the specific test environment resources.
VPC_ID = os.getenv("AWS_VPC_ID")
PUBLIC_SUBNET_ID = os.getenv("AWS_PUBLIC_SUBNET_ID")
PRIVATE_SUBNET_ID = os.getenv("AWS_PRIVATE_SUBNET_ID")
ROUTE_TABLE_ID = os.getenv("AWS_ROUTE_TABLE_ID")
IGW_ID = os.getenv("AWS_IGW_ID")
PERMISSIVE_ACL_ID = os.getenv("AWS_PERMISSIVE_ACL_ID")

# Initialize boto3 clients for AWS services
s3_client = boto3.client('s3', region_name='eu-north-1')
ec2_client = boto3.client('ec2', region_name='eu-north-1')
iam_client = boto3.client('iam')


# --- S3 Compliance Checks ---
def check_s3_compliance():
    issues = []
    buckets = s3_client.list_buckets().get('Buckets', [])
    for bucket in buckets:
        bucket_name = bucket['Name']
        bucket_issue = {"Bucket": bucket_name, "Issues": []}
        
        # Check Public Access Block configuration
        try:
            pab = s3_client.get_public_access_block(Bucket=bucket_name)
            config = pab.get('PublicAccessBlockConfiguration', {})
            if not (config.get('BlockPublicAcls', True) and 
                    config.get('IgnorePublicAcls', True) and 
                    config.get('BlockPublicPolicy', True) and 
                    config.get('RestrictPublicBuckets', True)):
                bucket_issue["Issues"].append({
                    "Issue": "Public access is allowed due to misconfigured Public Access Block settings.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                bucket_issue["Issues"].append({
                    "Issue": "No Public Access Block configuration found.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                })
            else:
                raise

        # Check the bucket policy for public access
        try:
            policy = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy['Policy'])
            for statement in policy_doc.get("Statement", []):
                principal = statement.get("Principal")
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    bucket_issue["Issues"].append({
                        "Issue": "Bucket policy allows public access.",
                        "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                    })
                    break
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                # No policy exists, which is secure in this context.
                pass
            else:
                raise

        # Check if server-side encryption is enabled
        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                bucket_issue["Issues"].append({
                    "Issue": "Bucket encryption is not enabled.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                })

        # Check if server access logging is enabled
        try:
            logging = s3_client.get_bucket_logging(Bucket=bucket_name)
            if not logging.get("LoggingEnabled"):
                bucket_issue["Issues"].append({
                    "Issue": "Bucket logging is not enabled.",
                    "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)"
                })
        except Exception as e:
            bucket_issue["Issues"].append({
                "Issue": "Error checking bucket logging: " + str(e),
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)"
            })

        if bucket_issue["Issues"]:
            issues.append(bucket_issue)
    return issues


# --- EC2 Security Group Checks ---
def check_ec2_security_groups():
    issues = []
    # Filter security groups to only those within our specific test VPC
    sg_response = ec2_client.describe_security_groups(
        Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}]
    )
    for sg in sg_response.get('SecurityGroups', []):
        sg_id = sg['GroupId']
        sg_issue = {"SecurityGroup": sg_id, "Issues": []}
        for rule in sg.get('IpPermissions', []):
            protocol = rule.get('IpProtocol')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp')
                if cidr == '0.0.0.0/0':
                    if protocol == "tcp" and from_port is not None and to_port is not None:
                        if from_port <= 22 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "SSH (port 22) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                            })
                        if from_port <= 3389 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "RDP (port 3389) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                            })
                        if from_port <= 80 <= to_port:
                            sg_issue["Issues"].append({
                                "Issue": "HTTP (port 80) publicly accessible",
                                "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                            })
                    elif protocol == "icmp":
                        sg_issue["Issues"].append({
                            "Issue": "ICMP (Ping) publicly accessible",
                            "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                        })
                    else:
                        sg_issue["Issues"].append({
                            "Issue": "Wide-open rule (0.0.0.0/0) detected.",
                            "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                        })
        if sg_issue["Issues"]:
            issues.append(sg_issue)
    return issues


# --- IAM Compliance Checks ---
def policy_allows_wildcards(policy_doc):
    """
    Checks if a given IAM policy document contains wildcard "*" 
    in its Action or Resource fields.
    """
    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions or "*" in resources:
            return True
    return False

def check_user_activity(user):
    """
    Checks if an IAM user has used their password or access keys recently.
    Returns True if the user appears to be inactive.
    """
    # Assume the user is inactive until activity is found
    inactive = True

    # Check for console login activity
    if 'PasswordLastUsed' in user:
        inactive = False

    # Check for access key activity
    user_name = user['UserName']
    access_keys = iam_client.list_access_keys(UserName=user_name).get('AccessKeyMetadata', [])
    for key in access_keys:
        key_id = key['AccessKeyId']
        try:
            last_used_info = iam_client.get_access_key_last_used(AccessKeyId=key_id)
            if last_used_info.get('AccessKeyLastUsed', {}).get('LastUsedDate'):
                inactive = False
                break
        except ClientError:
            # If an error occurs (e.g., key never used), assume no activity for this key
            continue

    return inactive

def check_iam_policies():
    issues = []
    # Check IAM Roles for overly permissive policies
    roles = iam_client.list_roles().get('Roles', [])
    for role in roles:
        role_name = role['RoleName']
        role_issue = {"Role": role_name, "Issues": []}
        
        # Check inline policies attached to the role
        inline_policies = iam_client.list_role_policies(RoleName=role_name).get('PolicyNames', [])
        for policy_name in inline_policies:
            policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
            if policy_allows_wildcards(policy):
                role_issue["Issues"].append({
                    "Issue": f"Inline policy '{policy_name}' grants wildcard permissions.",
                    "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)"
                })
        
        # This is a simplified check for attached managed policies.
        # A full implementation would inspect the policy document of each managed policy.
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', [])
        for attached_policy in attached_policies:
            role_issue["Issues"].append({
                "Issue": f"Review attached policy '{attached_policy['PolicyName']}' for wildcard permissions.",
                "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)"
            })
            
        if role_issue["Issues"]:
            issues.append(role_issue)
    
    # Check IAM Users for MFA status and inactivity
    users = iam_client.list_users().get('Users', [])
    for user in users:
        user_name = user['UserName']
        user_issue = {"User": user_name, "Issues": []}
        
        mfa_devices = iam_client.list_mfa_devices(UserName=user_name).get('MFADevices', [])
        if not mfa_devices:
            user_issue["Issues"].append({
                "Issue": "User does not have MFA enabled.",
                "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)"
            })
        
        # Check if the user account has been inactive
        if check_user_activity(user):
            user_issue["Issues"].append({
                "Issue": "User account appears to be inactive (no console or API usage).",
                "DORA_Mapping": "Article 5 (ICT Risk Management & Third-Party Oversight)"
            })
            
        if user_issue["Issues"]:
            issues.append(user_issue)
    
    return issues


# --- VPC Configuration Checks ---
def check_vpc_configurations():
    issues = []
    # Filter Route Tables to our specific test VPC
    route_tables = ec2_client.describe_route_tables(
        Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}]
    ).get('RouteTables', [])
    for rt in route_tables:
        rt_id = rt['RouteTableId']
        rt_issue = {"RouteTable": rt_id, "Issues": []}
        for route in rt.get('Routes', []):
            if route.get('DestinationCidrBlock') == "0.0.0.0/0" and 'GatewayId' in route:
                gateway = route['GatewayId']
                if gateway.startswith("igw-"):
                    rt_issue["Issues"].append({
                        "Issue": "Default route to an Internet Gateway detected; verify if intended for public subnets.",
                        "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                    })
        if rt_issue["Issues"]:
            issues.append(rt_issue)

    # Filter Network ACLs to our test VPC and the specific permissive ACL
    acls = ec2_client.describe_network_acls(
        Filters=[
            {'Name': 'vpc-id', 'Values': [VPC_ID]},
            {'Name': 'network-acl-id', 'Values': [PERMISSIVE_ACL_ID]}
        ]
    ).get('NetworkAcls', [])
    for acl in acls:
        acl_id = acl['NetworkAclId']
        acl_issue = {"NetworkACL": acl_id, "Issues": []}
        for entry in acl.get('Entries', []):
            if entry.get('RuleAction') == 'allow' and entry.get('CidrBlock') == "0.0.0.0/0":
                acl_issue["Issues"].append({
                    "Issue": "Overly permissive rule allowing all traffic from 0.0.0.0/0 detected.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                })
        if acl_issue["Issues"]:
            issues.append(acl_issue)
    
    # Filter Subnets to our specific test VPC
    subnets = ec2_client.describe_subnets(
        Filters=[{'Name': 'vpc-id', 'Values': [VPC_ID]}]
    ).get('Subnets', [])
    for subnet in subnets:
        subnet_id = subnet['SubnetId']
        # Check if the subnet automatically assigns public IPs to instances
        if subnet.get('MapPublicIpOnLaunch', False):
            issues.append({
                "Subnet": subnet_id,
                "Issues": [{
                    "Issue": "Subnet is configured to automatically assign public IPs, which may indicate unintended public exposure.",
                    "DORA_Mapping": "Article 9 (Secure Cloud Configurations)"
                }]
            })
    
    # Check if VPC Flow Logs are enabled for our test VPC
    flow_logs = ec2_client.describe_flow_logs().get('FlowLogs', [])
    vpc_flow_log_ids = {log['ResourceId'] for log in flow_logs}
    if VPC_ID not in vpc_flow_log_ids:
        issues.append({
            "VPC": VPC_ID,
            "Issues": [{
                "Issue": "VPC Flow Logs are not enabled, which may hinder network traffic monitoring.",
                "DORA_Mapping": "Article 10 (Incident Reporting & Security Governance)"
            }]
        })
    
    return issues

def main():
    results = {
        "S3_Compliance_Issues": check_s3_compliance(),
        "EC2_SG_Issues": check_ec2_security_groups(),
        "IAM_Issues": check_iam_policies(),
        "VPC_Issues": check_vpc_configurations()
    }
    # Print results as JSON for consumption by other scripts (in our case the streamlit.py)
    print(json.dumps(results, indent=4))

if __name__ == '__main__':
    main()