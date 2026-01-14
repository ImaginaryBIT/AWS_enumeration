"""
AWS Cloud Assessment Agent
==========================

Single-file, safe-by-default AWS enumeration agent that recursively enumerates
identities (users/roles) and builds a privilege graph by discovering principals
that the current principal can assume or otherwise impersonate.

Author: ChatGPT (for an authorized penetration tester)
License: Use only with explicit authorization

Features:
- Read-only by default (dry-run). Any state-changing action must be explicitly enabled.
- Enumerates: caller identity, IAM policies (user/role/group), role trust policies,
  common resource policies (S3, Lambda, SNS, SQS), instance profiles.
- Detects principals that can be assumed (via policies & trust policies).
- Attempts AssumeRole (if permitted) to recurse as the new principal (only if not dry-run).
- Builds a JSON graph and a DOT file for visualization.
- Enumerates: caller identity, IAM policies (user/role/group), role trust policies,
- Rate-limited, with max recursion depth and allow/deny lists.

Usage:
    python aws_cloud_assessment_agent.py --profile default --output out --max-depth 3

CONFIGURATION / SAFE-BY-DEFAULT
- --dry-run (default): never call sts:AssumeRole or modify resources.
- --allow-assume: required to actually call AssumeRole; otherwise assumptions are simulated.
- --max-depth: stop recursion at this depth (default 3).

NOTE: This script aims to be a starting point. Extend carefully.

"""

from __future__ import annotations
import argparse
import boto3
import botocore
from botocore.parsers import ResponseParserError
import json
import os
import time
import threading
import logging
from datetime import datetime
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import deque

# --------- Basic logging setup ---------
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger('cloud-agent')

# --------- Helper utilities ---------

def safe_sleep(seconds: float):
    # Centralized sleep for rate limiting/backoff
    time.sleep(seconds)


def mkdir_p(path: str):
    os.makedirs(path, exist_ok=True)


# --------- AWS helpers ---------
class AWSClientFactory:
    def __init__(self, profile: Optional[str], region: Optional[str]):
        session_kwargs = {}
        if profile:
            session_kwargs['profile_name'] = profile
        self.session = boto3.Session(**session_kwargs)
        self.region = region

    def client(self, service: str):
        return self.session.client(service, region_name=self.region)

    def resource(self, service: str):
        return self.session.resource(service, region_name=self.region)


# --------- Data structures for graph ---------
class PrivGraph:
    def __init__(self):
        # nodes: map from node_id -> metadata
        self.nodes: Dict[str, Dict[str, Any]] = {}
        # edges: list of (from, to, relation, metadata)
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, nid: str, meta: Dict[str, Any]):
        if nid not in self.nodes:
            self.nodes[nid] = meta
        else:
            # merge metadata
            self.nodes[nid].update(meta)

    def add_edge(self, src: str, dst: str, relation: str, meta: Optional[Dict[str, Any]] = None):
        self.edges.append({
            'src': src,
            'dst': dst,
            'relation': relation,
            'meta': meta or {}
        })

    def to_dict(self) -> Dict[str, Any]:
        return {'nodes': self.nodes, 'edges': self.edges}

    def export_json(self, path: str):
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    def export_dot(self, path: str):
        # Very small DOT exporter
        lines = ['digraph G {']
        
        # Relation mapping for better readability in the graph
        relation_labels = {
            'trusted-by': 'can assume to',
            's3-policy-principal': 'allows access to',
            'lambda-policy-principal': 'allows access to'
        }
        
        for nid, meta in self.nodes.items():
            label = meta.get('label', nid)
            lines.append(f'  "{nid}" [label="{label}"];')
        for e in self.edges:
            rel = e.get('relation', 'trusted-by')
            label = relation_labels.get(rel, rel)
            lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{label}"];')
        lines.append('}')
        with open(path, 'w') as f:
            f.write('\n'.join(lines))


# --------- Enumerator core ---------
class Enumerator:
    def __init__(self, client_factory: AWSClientFactory, dry_run: bool = True, allow_assume: bool = False,
                 max_depth: int = 3, rate_limit: float = 0.2, deny_list: Optional[List[str]] = None,
                 allow_list: Optional[List[str]] = None, include_aws_policies: bool = False):
        self.cf = client_factory
        self.dry_run = dry_run
        self.allow_assume = allow_assume
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self.deny_list = deny_list or []
        self.allow_list = allow_list or []
        self.include_aws_policies = include_aws_policies

        self.iam = self.cf.client('iam')
        self.sts = self.cf.client('sts')
        self.s3 = self.cf.client('s3')
        self.lambda_client = self.cf.client('lambda')
        self.sqs = self.cf.client('sqs')
        self.sns = self.cf.client('sns')
        self.kms = self.cf.client('kms')
        self.secretsmanager = self.cf.client('secretsmanager')
        self.ecr = self.cf.client('ecr')
        self.glacier = self.cf.client('glacier')
        self.apigateway = self.cf.client('apigateway')
        self.efs = self.cf.client('efs')
        self.ec2 = self.cf.client('ec2')
        self.organizations = self.cf.client('organizations')
        self.rds = self.cf.client('rds')
        self.ecs = self.cf.client('ecs')
        self.elasticbeanstalk = self.cf.client('elasticbeanstalk')
        self.lightsail = self.cf.client('lightsail')
        self.elb = self.cf.client('elb')
        self.elbv2 = self.cf.client('elbv2')

        self.graph = PrivGraph()
        # discovered principals to avoid loops
        self.discovered: Set[str] = set()

    # ---------- low level helpers ----------
    def _is_principal_in_policy(self, identity_arn: str, policy: Dict[str, Any]) -> bool:
        """
        Check if an identity_arn is explicitly or implicitly trusted in an IAM policy Statement block.
        Properly handles string vs list for Principals and wildcards.
        """
        if not policy:
            return False
            
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
            
        account_id = self._arn_account(identity_arn)
        account_arn = f"arn:aws:iam::{account_id}:root"
        
        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue
                
            principals = stmt.get('Principal', {})
            if not principals:
                continue
                
            # If Principal is "*", it usually means anyone in the account 
            # (or even public if no condition, but in trust policies it's often account-scoped)
            if principals == "*":
                return True
                
            aws_principals = principals.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
                
            for p in aws_principals:
                if p == "*" or p == identity_arn or p == account_id or p == account_arn:
                    return True
                    
        return False

    def get_caller_identity(self, creds: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Return sts:GetCallerIdentity result using provided creds or default client."""
        client = self.sts
        try:
            res = client.get_caller_identity()
            logger.info(f"Current identity: {res['Arn']}")
            return res
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to get caller identity: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error getting caller identity: {e}")
            return {}

    def list_roles(self) -> List[Dict[str, Any]]:
        roles = []
        try:
            paginator = self.iam.get_paginator('list_roles')
            for page in paginator.paginate():
                roles.extend(page.get('Roles', []))
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to list roles: {e}")
        return roles

    def list_users(self) -> List[Dict[str, Any]]:
        users = []
        try:
            paginator = self.iam.get_paginator('list_users')
            for page in paginator.paginate():
                users.extend(page.get('Users', []))
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to list users: {e}")
        return users

    def list_groups(self) -> List[Dict[str, Any]]:
        groups = []
        try:
            paginator = self.iam.get_paginator('list_groups')
            for page in paginator.paginate():
                groups.extend(page.get('Groups', []))
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to list groups: {e}")
        return groups

    def list_attached_user_policies(self, user_name: str) -> List[Dict[str, Any]]:
        out = []
        try:
            paginator = self.iam.get_paginator('list_attached_user_policies')
            for page in paginator.paginate(UserName=user_name):
                out.extend(page.get('AttachedPolicies', []))
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_attached_user_policies failed for {user_name}: {e}")
        except ResponseParserError as e:
            logger.warning(f"AWS API returned invalid response for list_attached_user_policies({user_name}): {e}")
        except Exception as e:
            logger.warning(f"Unexpected error in list_attached_user_policies({user_name}): {e}")
        return out

    def list_inline_policies_for_user(self, user_name: str) -> Dict[str, Any]:
        policies = {}
        try:
            res = self.iam.list_user_policies(UserName=user_name)
            for name in res.get('PolicyNames', []):
                doc = self.iam.get_user_policy(UserName=user_name, PolicyName=name)['PolicyDocument']
                policies[name] = doc
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_inline_policies_for_user failed for {user_name}: {e}")
        except ResponseParserError as e:
            logger.warning(f"AWS API returned invalid response for list_inline_policies_for_user({user_name}): {e}")
        except Exception as e:
            logger.warning(f"Unexpected error in list_inline_policies_for_user({user_name}): {e}")
        return policies

    def list_groups_for_user(self, user_name: str) -> List[Dict[str, Any]]:
        groups = []
        try:
            paginator = self.iam.get_paginator('list_groups_for_user')
            for page in paginator.paginate(UserName=user_name):
                groups.extend(page.get('Groups', []))
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_groups_for_user failed for {user_name}: {e}")
        return groups

    def list_attached_group_policies(self, group_name: str) -> List[Dict[str, Any]]:
        out = []
        try:
            paginator = self.iam.get_paginator('list_attached_group_policies')
            for page in paginator.paginate(GroupName=group_name):
                out.extend(page.get('AttachedPolicies', []))
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_attached_group_policies failed for {group_name}: {e}")
        return out

    def list_inline_policies_for_group(self, group_name: str) -> Dict[str, Any]:
        policies = {}
        try:
            res = self.iam.list_group_policies(GroupName=group_name)
            for name in res.get('PolicyNames', []):
                doc = self.iam.get_group_policy(GroupName=group_name, PolicyName=name)['PolicyDocument']
                policies[name] = doc
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_inline_policies_for_group failed for {group_name}: {e}")
        return policies

    def get_policy_version(self, policy_arn: str, version_id: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            return res['PolicyVersion']['Document']
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_policy_version failed for {policy_arn}: {e}")
            return None
        except ResponseParserError as e:
            logger.warning(f"AWS API returned invalid response for {policy_arn}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Unexpected error getting policy version for {policy_arn}: {e}")
            return None

    def list_policy_versions(self, policy_arn: str) -> List[Dict[str, Any]]:
        """List all available versions for a policy."""
        try:
            res = self.iam.list_policy_versions(PolicyArn=policy_arn)
            return res.get('Versions', [])
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_policy_versions failed for {policy_arn}: {e}")
            return []

    def get_role_policy_document(self, role_name: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.iam.get_role(RoleName=role_name)
            return res['Role']['AssumeRolePolicyDocument']
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_role_policy_document failed for {role_name}: {e}")
            return None

    def list_attached_role_policies(self, role_name: str) -> List[Dict[str, Any]]:
        out = []
        try:
            paginator = self.iam.get_paginator('list_attached_role_policies')
            for page in paginator.paginate(RoleName=role_name):
                out.extend(page.get('AttachedPolicies', []))
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_attached_role_policies failed for {role_name}: {e}")
        except ResponseParserError as e:
            logger.warning(f"AWS API returned invalid response for list_attached_role_policies({role_name}): {e}")
        except Exception as e:
            logger.warning(f"Unexpected error in list_attached_role_policies({role_name}): {e}")
        return out

    def list_inline_policies_for_role(self, role_name: str) -> Dict[str, Any]:
        policies = {}
        try:
            res = self.iam.list_role_policies(RoleName=role_name)
            for name in res.get('PolicyNames', []):
                doc = self.iam.get_role_policy(RoleName=role_name, PolicyName=name)['PolicyDocument']
                policies[name] = doc
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_inline_policies_for_role failed for {role_name}: {e}")
        except ResponseParserError as e:
            logger.warning(f"AWS API returned invalid response for list_inline_policies_for_role({role_name}): {e}")
        except Exception as e:
            logger.warning(f"Unexpected error in list_inline_policies_for_role({role_name}): {e}")
        return policies

    # ---------- resource-based policies enumeration ----------
    def get_s3_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.s3.get_bucket_policy(Bucket=bucket)
            return json.loads(res['Policy'])
        except botocore.exceptions.ClientError as e:
            # Bucket may not have a policy or access denied
            return None

    def list_buckets(self) -> List[str]:
        try:
            res = self.s3.list_buckets()
            return [b['Name'] for b in res.get('Buckets', [])]
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_buckets failed: {e}")
            return []

    def get_lambda_policy(self, function_name: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.lambda_client.get_policy(FunctionName=function_name)
            return json.loads(res['Policy'])
        except botocore.exceptions.ClientError:
            return None

    def list_lambda_functions(self) -> List[str]:
        try:
            funcs = []
            paginator = self.lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for f in page.get('Functions', []):
                    funcs.append(f['FunctionName'])
            return funcs
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_lambda_functions failed: {e}")
            return []

    # ---------- Additional resource-based policies enumeration ----------
    
    # KMS Key Policies
    def list_kms_keys(self) -> List[str]:
        try:
            keys = []
            paginator = self.kms.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page.get('Keys', []):
                    keys.append(key['KeyId'])
            return keys
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_kms_keys failed: {e}")
            return []
    
    def get_kms_key_policy(self, key_id: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.kms.get_key_policy(KeyId=key_id, PolicyName='default')
            return json.loads(res['Policy'])
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_kms_key_policy failed for {key_id}: {e}")
            return None
    
    # SQS Queue Policies
    def list_sqs_queues(self) -> List[str]:
        try:
            res = self.sqs.list_queues()
            return res.get('QueueUrls', [])
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_sqs_queues failed: {e}")
            return []
    
    def get_sqs_queue_policy(self, queue_url: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['Policy'])
            policy_str = res.get('Attributes', {}).get('Policy')
            if policy_str:
                return json.loads(policy_str)
            return None
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_sqs_queue_policy failed for {queue_url}: {e}")
            return None
    
    # SNS Topic Policies
    def list_sns_topics(self) -> List[str]:
        try:
            topics = []
            paginator = self.sns.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page.get('Topics', []):
                    topics.append(topic['TopicArn'])
            return topics
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_sns_topics failed: {e}")
            return []
    
    def get_sns_topic_policy(self, topic_arn: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.sns.get_topic_attributes(TopicArn=topic_arn)
            policy_str = res.get('Attributes', {}).get('Policy')
            if policy_str:
                return json.loads(policy_str)
            return None
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_sns_topic_policy failed for {topic_arn}: {e}")
            return None
    
    # Secrets Manager Secret Policies
    def list_secrets(self) -> List[str]:
        try:
            secrets = []
            paginator = self.secretsmanager.get_paginator('list_secrets')
            for page in paginator.paginate():
                for secret in page.get('SecretList', []):
                    secrets.append(secret['ARN'])
            return secrets
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_secrets failed: {e}")
            return []
    
    def get_secret_policy(self, secret_arn: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.secretsmanager.get_resource_policy(SecretId=secret_arn)
            policy_str = res.get('ResourcePolicy')
            if policy_str:
                return json.loads(policy_str)
            return None
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_secret_policy failed for {secret_arn}: {e}")
            return None
    
    # ECR Repository Policies
    def list_ecr_repositories(self) -> List[str]:
        try:
            repos = []
            paginator = self.ecr.get_paginator('describe_repositories')
            for page in paginator.paginate():
                for repo in page.get('repositories', []):
                    repos.append(repo['repositoryName'])
            return repos
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_ecr_repositories failed: {e}")
            return []
    
    def get_ecr_repository_policy(self, repository_name: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.ecr.get_repository_policy(repositoryName=repository_name)
            policy_str = res.get('policyText')
            if policy_str:
                return json.loads(policy_str)
            return None
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_ecr_repository_policy failed for {repository_name}: {e}")
            return None
    
    # Glacier Vault Policies
    def list_glacier_vaults(self) -> List[str]:
        try:
            res = self.glacier.list_vaults()
            return [v['VaultName'] for v in res.get('VaultList', [])]
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_glacier_vaults failed: {e}")
            return []
    
    def get_glacier_vault_policy(self, vault_name: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.glacier.get_vault_access_policy(vaultName=vault_name)
            policy_str = res.get('policy', {}).get('Policy')
            if policy_str:
                return json.loads(policy_str)
            return None
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_glacier_vault_policy failed for {vault_name}: {e}")
            return None
    
    # API Gateway Resource Policies
    def list_api_gateways(self) -> List[Dict[str, str]]:
        try:
            apis = []
            paginator = self.apigateway.get_paginator('get_rest_apis')
            for page in paginator.paginate():
                for api in page.get('items', []):
                    apis.append({'id': api['id'], 'name': api.get('name', 'Unknown')})
            return apis
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_api_gateways failed: {e}")
            return []
    
    def get_api_gateway_policy(self, api_id: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.apigateway.get_rest_api(restApiId=api_id)
            policy_str = res.get('policy')
            if policy_str:
                return json.loads(policy_str)
            return None
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_api_gateway_policy failed for {api_id}: {e}")
            return None
    
    # EFS File System Policies
    def list_efs_file_systems(self) -> List[str]:
        try:
            res = self.efs.describe_file_systems()
            return [fs['FileSystemId'] for fs in res.get('FileSystems', [])]
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_efs_file_systems failed: {e}")
            return []
    
    def get_efs_file_system_policy(self, file_system_id: str) -> Optional[Dict[str, Any]]:
        try:
            res = self.efs.describe_file_system_policy(FileSystemId=file_system_id)
            policy_str = res.get('Policy')
            if policy_str:
                return json.loads(policy_str)
            return None
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_efs_file_system_policy failed for {file_system_id}: {e}")
            return None
    # ---------- Compute & Infrastructure Context ----------

    def list_instance_profiles(self) -> List[Dict[str, Any]]:
        profiles = []
        try:
            paginator = self.iam.get_paginator('list_instance_profiles')
            for page in paginator.paginate():
                profiles.extend(page.get('InstanceProfiles', []))
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_instance_profiles failed: {e}")
        return profiles

    def list_instances(self) -> List[Dict[str, Any]]:
        instances = []
        try:
            paginator = self.ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for reservation in page.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        instances.append(instance)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_instances failed: {e}")
        return instances

    def list_network_interfaces(self) -> List[Dict[str, Any]]:
        """List all network interfaces in the region."""
        interfaces = []
        try:
            paginator = self.ec2.get_paginator('describe_network_interfaces')
            for page in paginator.paginate():
                for interface in page.get('NetworkInterfaces', []):
                    interfaces.append(interface)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_network_interfaces failed: {e}")
        return interfaces

    def get_lambda_event_source_mappings(self, function_name: str) -> List[Dict[str, Any]]:
        mappings = []
        try:
            paginator = self.lambda_client.get_paginator('list_event_source_mappings')
            for page in paginator.paginate(FunctionName=function_name):
                mappings.extend(page.get('EventSourceMappings', []))
        except botocore.exceptions.ClientError as e:
            logger.debug(f"get_lambda_event_source_mappings failed for {function_name}: {e}")
        return mappings

    # ---------- Organizations & SCPs ----------

    def get_organization_info(self) -> Optional[Dict[str, Any]]:
        try:
            res = self.organizations.describe_organization()
            return res.get('Organization')
        except botocore.exceptions.ClientError as e:
            logger.debug(f"describe_organization failed: {e}")
            return None

    def list_applied_scps(self) -> List[Dict[str, Any]]:
        scps = []
        try:
            # First, we need to know the account ID to list policies for it
            res = self.sts.get_caller_identity()
            account_id = res['Account']
            
            # List policies attached to this account
            paginator = self.organizations.get_paginator('list_policies_for_target')
            # Filter for Service Control Policies
            for page in paginator.paginate(TargetId=account_id, Filter='SERVICE_CONTROL_POLICY'):
                for policy_summary in page.get('Policies', []):
                    # Get the full policy content
                    policy_id = policy_summary['Id']
                    policy_detail = self.organizations.describe_policy(PolicyId=policy_id)
                    scps.append(policy_detail.get('Policy', {}))
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_applied_scps failed: {e}")
        return scps


    # ---------- principal discovery heuristics ----------
    def principals_from_policy_statement(self, stmt: Dict[str, Any]) -> List[str]:
        principals = []
        p = stmt.get('Principal')
        if not p:
            return principals
        if isinstance(p, str):
            principals.append(p)
        elif isinstance(p, dict):
            for k, v in p.items():
                if isinstance(v, str):
                    principals.append(v)
                elif isinstance(v, list):
                    principals.extend(v)
        return principals

    def find_principals_in_s3_policies(self) -> List[Tuple[str, str]]:
        # returns list of (bucket, principal)
        out = []
        buckets = self.list_buckets()
        for b in buckets:
            pol = self.get_s3_bucket_policy(b)
            if not pol:
                continue
            for stmt in pol.get('Statement', []):
                for principal in self.principals_from_policy_statement(stmt):
                    out.append((b, principal))
        return out

    def find_principals_in_lambda(self) -> List[Tuple[str, str]]:
        out = []
        funcs = self.list_lambda_functions()
        for f in funcs:
            pol = self.get_lambda_policy(f)
            if not pol:
                continue
            for stmt in pol.get('Statement', []):
                for principal in self.principals_from_policy_statement(stmt):
                    out.append((f, principal))
        return out

    # ---------- AssumeRole handling ----------
    def can_simulate_assume(self, src_arn: str, target_role_arn: str) -> bool:
        # Conservative simulation: add match if we see sts:AssumeRole in documented policies
        # Real evaluation requires policy simulation; here we use best-effort scanning.
        # We'll inspect attached policies of the src principal when possible.
        return True  # we'll rely on AWS error when actually calling AssumeRole if allowed

    def attempt_assume_role(self, role_arn: str, session_name: str = 'assess-session') -> Optional[Dict[str, Any]]:
        if self.dry_run:
            logger.info(f"Dry-run: skipping actual AssumeRole to {role_arn}")
            return None
        if not self.allow_assume:
            logger.info(f"AssumeRole disabled by flags; skipping AssumeRole to {role_arn}")
            return None
        try:
            res = self.sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            creds = res['Credentials']
            logger.info(f"Assumed {role_arn} for session {session_name}")
            # Return temporary credentials (accessKeyId, secretAccessKey, sessionToken)
            return {
                'AccessKeyId': creds['AccessKeyId'],
                'SecretAccessKey': creds['SecretAccessKey'],
                'SessionToken': creds['SessionToken']
            }
        except botocore.exceptions.ClientError as e:
            logger.info(f"AssumeRole to {role_arn} failed or denied: {e.response.get('Error', {}).get('Message')}")
            return None

    # ---------- Core recursive traversal ----------
    def discover_from_identity(self, identity_arn: str, depth: int = 0, source: Optional[str] = None):
        if not identity_arn:
            logger.debug("No identity ARN provided for discovery.")
            return
        if depth > self.max_depth:
            logger.debug(f"Max depth reached for {identity_arn}")
            return
        if identity_arn in self.discovered:
            logger.debug(f"Already discovered {identity_arn}")
            return
        # deny-list/allow-list checks
        for deny in self.deny_list:
            if deny in identity_arn:
                logger.info(f"Skipping {identity_arn} due to deny-list rule")
                return
        if self.allow_list and not any(a in identity_arn for a in self.allow_list):
            logger.debug(f"Skipping {identity_arn} due to allow-list (no matches)")
            return

        logger.info(f"Discovering from identity: {identity_arn} (depth {depth})")
        self.discovered.add(identity_arn)

        # Add node
        self.graph.add_node(identity_arn, {'label': identity_arn, 'discovered_depth': depth})

        # Enumerate roles list and trust policies to find roles that trust this identity
        roles = self.list_roles()
        for r in roles:
            role_name = r['RoleName']
            role_arn = r['Arn']
            trust = r.get('AssumeRolePolicyDocument') or self.get_role_policy_document(role_name)
            if not trust:
                continue
            if self._is_principal_in_policy(identity_arn, trust):
                # potential path: identity -> can be trusted by role
                self.graph.add_edge(identity_arn, role_arn, 'trusted-by')
                logger.info(f"Potential trust path (inbound): {identity_arn} -> {role_arn}")
                # attempt to assume
                creds = self.attempt_assume_role(role_arn, session_name=f'assess-{int(time.time())}')
                if creds:
                    # create new client factory with temporary credentials and re-enumerate
                    tmp_cf = self._client_factory_from_temp_creds(creds)
                    sub_enum = Enumerator(tmp_cf, dry_run=self.dry_run, allow_assume=self.allow_assume,
                                          max_depth=self.max_depth, rate_limit=self.rate_limit,
                                          deny_list=self.deny_list, allow_list=self.allow_list)
                    # small sleep to avoid immediate throttling
                    safe_sleep(self.rate_limit)
                    try:
                        cid = sub_enum.get_caller_identity()
                        sub_identity_arn = cid.get('Arn')
                        # merge subgraph results
                        sub_enum.discover_from_identity(sub_identity_arn, depth=depth+1, source=identity_arn)
                        # Merge subgraph into main graph
                        self._merge_subgraph(sub_enum)
                    except Exception as e:
                        logger.debug(f"Sub-enum failed: {e}")
                else:
                    # Add role node even if assume failed (discovery)
                    self.graph.add_node(role_arn, {'label': role_arn})

        # Outbound AssumeRole discovery: What roles can this identity assume?
        my_policies = self.get_policies_for_identity(identity_arn)
        assumable_target_roles = self.get_assumable_roles_from_policies(my_policies)
        for target_role_arn in assumable_target_roles:
            if target_role_arn == '*':
                # We record '*' as a potential risk but hard to graph specific target
                self.graph.add_edge(identity_arn, "*", 'can-assume-all')
                logger.warning(f"Identity {identity_arn} has administrative AssumeRole (*) permissions!")
                continue
                
            # Add edge
            self.graph.add_edge(identity_arn, target_role_arn, 'can-assume')
            logger.info(f"Outbound path: {identity_arn} -> {target_role_arn} (via policy)")
            
            # If we didn't already discover this via trust policies, try to assume it now
            if target_role_arn not in self.discovered and self.allow_assume:
                creds = self.attempt_assume_role(target_role_arn, session_name=f'assess-out-{int(time.time())}')
                if creds:
                    tmp_cf = self._client_factory_from_temp_creds(creds)
                    sub_enum = Enumerator(tmp_cf, dry_run=self.dry_run, allow_assume=self.allow_assume,
                                          max_depth=self.max_depth, rate_limit=self.rate_limit,
                                          deny_list=self.deny_list, allow_list=self.allow_list)
                    safe_sleep(self.rate_limit)
                    try:
                        cid = sub_enum.get_caller_identity()
                        sub_identity_arn = cid.get('Arn')
                        sub_enum.discover_from_identity(sub_identity_arn, depth=depth+1, source=identity_arn)
                        self._merge_subgraph(sub_enum)
                    except Exception as e:
                        logger.debug(f"Sub-enum fail for outbound path {target_role_arn}: {e}")
                else:
                    # Add role node even if assume failed (discovery)
                    self.graph.add_node(target_role_arn, {'label': target_role_arn})

            # rate limit between role checks
            safe_sleep(self.rate_limit)

        # PassRole discovery: What roles can this identity pass to services?
        passable_target_roles = self.get_passable_roles_from_policies(my_policies)
        for target_role_arn in passable_target_roles:
            if target_role_arn == '*':
                self.graph.add_edge(identity_arn, "*", 'can-pass-all-roles')
                logger.warning(f"Identity {identity_arn} has administrative PassRole (*) permissions!")
                continue
            
            self.graph.add_edge(identity_arn, target_role_arn, 'can-pass-this-role-to-another-service')
            logger.info(f"PassRole path: {identity_arn} -> {target_role_arn} (via policy)")

        # resource-based policies: S3
        for bucket, principal in self.find_principals_in_s3_policies():
            # If this principal equals identity_arn or account root, treat as an edge
            self.graph.add_node(f's3://{bucket}', {'label': f's3://{bucket}'})
            self.graph.add_edge(f's3://{bucket}', principal, 's3-policy-principal')

        # Lambda resource policies
        for func, principal in self.find_principals_in_lambda():
            self.graph.add_node(f'lambda:{func}', {'label': f'lambda:{func}'})
            self.graph.add_edge(f'lambda:{func}', principal, 'lambda-policy-principal')

        safe_sleep(self.rate_limit)

    def _merge_subgraph(self, sub: 'Enumerator'):
        for nid, meta in sub.graph.nodes.items():
            self.graph.add_node(nid, meta)
        for e in sub.graph.edges:
            self.graph.add_edge(e['src'], e['dst'], e['relation'], e.get('meta'))

    def _client_factory_from_temp_creds(self, creds: Dict[str, str]) -> AWSClientFactory:
        # Create a new boto3 session using temporary creds
        session = boto3.Session(
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
        cf = AWSClientFactory(profile=None, region=self.cf.region)
        cf.session = session
        return cf

    def get_assumable_roles_from_policies(self, policy_docs: List[Dict[str, Any]]) -> List[str]:
        """Simple heuristic to find Role ARNs in policies that allow sts:AssumeRole."""
        assumable_roles = set()
        for doc in policy_docs:
            statements = doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                effect = stmt.get('Effect')
                action = stmt.get('Action', [])
                if isinstance(action, str):
                    action = [action]
                
                # Check if sts:AssumeRole (or typo iam:AssumeRole) is allowed
                can_assume = False
                if effect == 'Allow':
                    for a in action:
                        if a in ['sts:AssumeRole', 'sts:Assume*', 'iam:AssumeRole', 'iam:Assume*', 'sts:*', 'iam:*', '*']:
                            can_assume = True
                            break
                
                if can_assume:
                    res = stmt.get('Resource', [])
                    if isinstance(res, str):
                        res = [res]
                    for r in res:
                        if ':role/' in r or r == '*':
                            assumable_roles.add(r)
        return list(assumable_roles)

    def get_passable_roles_from_policies(self, policy_docs: List[Dict[str, Any]]) -> List[str]:
        """Simple heuristic to find Role ARNs in policies that allow iam:PassRole."""
        passable_roles = set()
        for doc in policy_docs:
            statements = doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]
            for stmt in statements:
                effect = stmt.get('Effect')
                action = stmt.get('Action', [])
                if isinstance(action, str):
                    action = [action]
                
                # Check if iam:PassRole (or iam:*) is allowed
                can_pass = False
                if effect == 'Allow':
                    for a in action:
                        if a in ['iam:PassRole', 'iam:*', 'iam:Pass*', '*']:
                            can_pass = True
                            break
                
                if can_pass:
                    res = stmt.get('Resource', [])
                    if isinstance(res, str):
                        res = [res]
                    for r in res:
                        if ':role/' in r or r == '*':
                            passable_roles.add(r)
        return list(passable_roles)

    def _arn_account(self, arn: str) -> str:
        # Return account id portion of ARN if possible
        # arn:partition:service:region:account-id:resource
        parts = arn.split(':')
        if len(parts) >= 5:
            return parts[4]
        return ''

    # ---------- Exporters and finalization ----------
    def get_policies_for_identity(self, identity_arn: str) -> List[Dict[str, Any]]:
        """Fetch all attached and inline policy documents for an identity ARN."""
        policy_docs = []
        if ":role/" in identity_arn:
            role_name = identity_arn.split("/")[-1]
            # Attached
            for p in self.list_attached_role_policies(role_name):
                p_arn = p['PolicyArn']
                try:
                    p_info = self.iam.get_policy(PolicyArn=p_arn)
                    p_ver = p_info['Policy']['DefaultVersionId']
                    doc = self.get_policy_version(p_arn, p_ver)
                    if doc: policy_docs.append(doc)
                    safe_sleep(self.rate_limit)
                except: pass
            # Inline
            for doc in self.list_inline_policies_for_role(role_name).values():
                policy_docs.append(doc)
        elif ":user/" in identity_arn:
            user_name = identity_arn.split("/")[-1]
            # Attached
            for p in self.list_attached_user_policies(user_name):
                p_arn = p['PolicyArn']
                try:
                    p_info = self.iam.get_policy(PolicyArn=p_arn)
                    p_ver = p_info['Policy']['DefaultVersionId']
                    doc = self.get_policy_version(p_arn, p_ver)
                    if doc: policy_docs.append(doc)
                    safe_sleep(self.rate_limit)
                except: pass
            # Inline
            for doc in self.list_inline_policies_for_user(user_name).values():
                policy_docs.append(doc)
            # Groups (Users inherit group policies)
            for group in self.list_groups_for_user(user_name):
                group_name = group['GroupName']
                for gp in self.list_attached_group_policies(group_name):
                    gp_arn = gp['PolicyArn']
                    try:
                        gp_info = self.iam.get_policy(PolicyArn=gp_arn)
                        gp_ver = gp_info['Policy']['DefaultVersionId']
                        doc = self.get_policy_version(gp_arn, gp_ver)
                        if doc: policy_docs.append(doc)
                        safe_sleep(self.rate_limit)
                    except: pass
                for doc in self.list_inline_policies_for_group(group_name).values():
                    policy_docs.append(doc)
        elif ":assumed-role/" in identity_arn:
            # arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
            parts = identity_arn.split("/")
            if len(parts) >= 2:
                role_name = parts[1]
                # Recurse with the actual role ARN to get its policies
                account_id = self._arn_account(identity_arn)
                role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
                return self.get_policies_for_identity(role_arn)
        
        return [d for d in policy_docs if d]

    def export_iam_data(self, outdir: str):
        """Export comprehensive IAM data for analysis."""
        logger.info("Exporting IAM data...")
        
        # Export users
        users = self.list_users()
        users_path = os.path.join(outdir, 'iam_users.json')
        with open(users_path, 'w') as f:
            json.dump(users, f, indent=2, default=str)
        logger.info(f"Exported {len(users)} users to {users_path}")
        
        # Export roles with their policies (including full policy documents)
        roles = self.list_roles()
        roles_detailed = []
        for role in roles:
            try:
                role_name = role['RoleName']
                attached_policies = self.list_attached_role_policies(role_name)
                
                # Fetch full policy documents for attached policies
                attached_policies_with_docs = []
                for policy in attached_policies:
                    policy_arn = policy['PolicyArn']
                    policy_data = {'PolicyName': policy['PolicyName'], 'PolicyArn': policy_arn}
                    # Get the policy document
                    try:
                        policy_info = self.iam.get_policy(PolicyArn=policy_arn)
                        default_version = policy_info['Policy']['DefaultVersionId']
                        policy_doc = self.get_policy_version(policy_arn, default_version)
                        policy_data['PolicyDocument'] = policy_doc
                        safe_sleep(self.rate_limit)
                    except botocore.exceptions.ClientError as e:
                        logger.debug(f"Failed to get policy document for {policy_arn}: {e}")
                        policy_data['PolicyDocument'] = None
                    attached_policies_with_docs.append(policy_data)
                
                role_data = {
                    'RoleInfo': role,
                    'AttachedPolicies': attached_policies_with_docs,
                    'InlinePolicies': self.list_inline_policies_for_role(role_name),
                    'AssumeRolePolicyDocument': role.get('AssumeRolePolicyDocument')
                }
                roles_detailed.append(role_data)
                safe_sleep(self.rate_limit)
            except Exception as e:
                logger.error(f"Failed to process role {role.get('RoleName')}: {e}")
                continue
        
        roles_path = os.path.join(outdir, 'iam_roles.json')
        with open(roles_path, 'w') as f:
            json.dump(roles_detailed, f, indent=2, default=str)
        logger.info(f"Exported {len(roles_detailed)} roles to {roles_path}")

        # Export all global groups
        groups = self.list_groups()
        groups_detailed_global = []
        for group in groups:
            try:
                group_name = group['GroupName']
                attached_policies = self.list_attached_group_policies(group_name)
                
                # Fetch full policy documents for attached policies
                attached_policies_with_docs = []
                for policy in attached_policies:
                    policy_arn = policy['PolicyArn']
                    policy_data = {'PolicyName': policy['PolicyName'], 'PolicyArn': policy_arn}
                    try:
                        policy_info = self.iam.get_policy(PolicyArn=policy_arn)
                        default_version = policy_info['Policy']['DefaultVersionId']
                        policy_doc = self.get_policy_version(policy_arn, default_version)
                        policy_data['PolicyDocument'] = policy_doc
                        safe_sleep(self.rate_limit)
                    except botocore.exceptions.ClientError:
                        policy_data['PolicyDocument'] = None
                    attached_policies_with_docs.append(policy_data)
                
                group_data = {
                    'GroupInfo': group,
                    'AttachedPolicies': attached_policies_with_docs,
                    'InlinePolicies': self.list_inline_policies_for_group(group_name)
                }
                groups_detailed_global.append(group_data)
                safe_sleep(self.rate_limit)
            except Exception as e:
                logger.error(f"Failed to process group {group.get('GroupName')}: {e}")
                continue
        
        groups_path = os.path.join(outdir, 'iam_groups.json')
        with open(groups_path, 'w') as f:
            json.dump(groups_detailed_global, f, indent=2, default=str)
        logger.info(f"Exported {len(groups_detailed_global)} groups to {groups_path}")
        
        # Export user policies (including full policy documents)
        users_detailed = []
        for user in users:
            try:
                user_name = user['UserName']
                attached_policies = self.list_attached_user_policies(user_name)
                
                # Fetch full policy documents for attached policies
                attached_policies_with_docs = []
                for policy in attached_policies:
                    policy_arn = policy['PolicyArn']
                    policy_data = {'PolicyName': policy['PolicyName'], 'PolicyArn': policy_arn}
                    # Get the policy document
                    try:
                        policy_info = self.iam.get_policy(PolicyArn=policy_arn)
                        default_version = policy_info['Policy']['DefaultVersionId']
                        policy_doc = self.get_policy_version(policy_arn, default_version)
                        policy_data['PolicyDocument'] = policy_doc
                        safe_sleep(self.rate_limit)
                    except botocore.exceptions.ClientError as e:
                        logger.debug(f"Failed to get policy document for {policy_arn}: {e}")
                        policy_data['PolicyDocument'] = None
                    attached_policies_with_docs.append(policy_data)
                
                user_groups = self.list_groups_for_user(user_name)
                groups_detailed = []
                for group in user_groups:
                    group_name = group['GroupName']
                    group_attached = self.list_attached_group_policies(group_name)
                    
                    group_attached_with_docs = []
                    for p in group_attached:
                        p_arn = p['PolicyArn']
                        p_data = {'PolicyName': p['PolicyName'], 'PolicyArn': p_arn}
                        try:
                            p_info = self.iam.get_policy(PolicyArn=p_arn)
                            p_ver = p_info['Policy']['DefaultVersionId']
                            p_data['PolicyDocument'] = self.get_policy_version(p_arn, p_ver)
                        except botocore.exceptions.ClientError:
                            p_data['PolicyDocument'] = None
                        group_attached_with_docs.append(p_data)
                    
                    groups_detailed.append({
                        'GroupName': group_name,
                        'GroupId': group['GroupId'],
                        'Arn': group['Arn'],
                        'AttachedPolicies': group_attached_with_docs,
                        'InlinePolicies': self.list_inline_policies_for_group(group_name)
                    })

                user_inline = self.list_inline_policies_for_user(user_name)
                
                # Combine all policies to find potential role assumption
                all_policy_docs = []
                for p in attached_policies_with_docs:
                    if p.get('PolicyDocument'): all_policy_docs.append(p['PolicyDocument'])
                for doc in user_inline.values():
                    all_policy_docs.append(doc)
                for g in groups_detailed:
                    for p in g['AttachedPolicies']:
                        if p.get('PolicyDocument'): all_policy_docs.append(p['PolicyDocument'])
                    for doc in g['InlinePolicies'].values():
                        all_policy_docs.append(doc)
                        
                user_data = {
                    'UserInfo': user,
                    'Groups': groups_detailed,
                    'AttachedPolicies': attached_policies_with_docs,
                    'InlinePolicies': user_inline,
                    'PotentialAssumableRoles': self.get_assumable_roles_from_policies(all_policy_docs)
                }
                users_detailed.append(user_data)
                safe_sleep(self.rate_limit)
            except Exception as e:
                logger.error(f"Failed to process user {user.get('UserName')}: {e}")
                continue
        
        users_detailed_path = os.path.join(outdir, 'iam_users_detailed.json')
        with open(users_detailed_path, 'w') as f:
            json.dump(users_detailed, f, indent=2, default=str)
        logger.info(f"Exported detailed user data to {users_detailed_path}")
        
        # Export managed policies (customer-managed by default, or all if --include-aws-policies is set)
        policies = []
        scope = 'All' if self.include_aws_policies else 'Local'
        scope_desc = 'all managed' if self.include_aws_policies else 'customer-managed'
        
        try:
            paginator = self.iam.get_paginator('list_policies')
            logger.info(f"Exporting {scope_desc} policies (Scope={scope})...")
            for page in paginator.paginate(Scope=scope):
                for policy in page.get('Policies', []):
                    policy_arn = policy['Arn']
                    default_version = policy['DefaultVersionId']
                    
                    policy_data = {
                        'PolicyInfo': policy,
                        'PolicyDocument': self.get_policy_version(policy_arn, default_version),
                        'Versions': []
                    }
                    
                    # Only fetch all versions for customer-managed policies to save time/API calls
                    if not policy_arn.startswith('arn:aws:iam::aws:'):
                        versions = self.list_policy_versions(policy_arn)
                        for v in versions:
                            v_id = v['VersionId']
                            v_doc = self.get_policy_version(policy_arn, v_id)
                            policy_data['Versions'].append({
                                'VersionId': v_id,
                                'IsDefaultVersion': v['IsDefaultVersion'],
                                'CreateDate': v['CreateDate'],
                                'PolicyDocument': v_doc
                            })
                            safe_sleep(self.rate_limit)
                    
                    policies.append(policy_data)
                    safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"list_policies failed: {e}")
        
        policies_path = os.path.join(outdir, 'iam_policies.json')
        with open(policies_path, 'w') as f:
            json.dump(policies, f, indent=2, default=str)
        logger.info(f"Exported {len(policies)} {scope_desc} policies to {policies_path}")


    def export_resource_policies(self, outdir: str):
        """Export resource-based policies from various AWS services."""
        logger.info("Exporting resource-based policies...")
        
        resource_policies = {
            'S3Buckets': [],
            'LambdaFunctions': [],
            'KMSKeys': [],
            'SQSQueues': [],
            'SNSTopics': [],
            'Secrets': [],
            'ECRRepositories': [],
            'GlacierVaults': [],
            'APIGateways': [],
            'EFSFileSystems': []
        }
        
        # S3 Bucket Policies
        buckets = self.list_buckets()
        for bucket in buckets:
            policy = self.get_s3_bucket_policy(bucket)
            if policy:
                resource_policies['S3Buckets'].append({
                    'ResourceName': bucket,
                    'ResourceType': 'S3Bucket',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['S3Buckets'])} S3 bucket policies")
        
        # Lambda Function Policies
        functions = self.list_lambda_functions()
        for func in functions:
            policy = self.get_lambda_policy(func)
            if policy:
                resource_policies['LambdaFunctions'].append({
                    'ResourceName': func,
                    'ResourceType': 'LambdaFunction',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['LambdaFunctions'])} Lambda function policies")
        
        # KMS Key Policies
        keys = self.list_kms_keys()
        for key in keys:
            policy = self.get_kms_key_policy(key)
            if policy:
                resource_policies['KMSKeys'].append({
                    'ResourceName': key,
                    'ResourceType': 'KMSKey',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['KMSKeys'])} KMS key policies")
        
        # SQS Queue Policies
        queues = self.list_sqs_queues()
        for queue in queues:
            policy = self.get_sqs_queue_policy(queue)
            if policy:
                resource_policies['SQSQueues'].append({
                    'ResourceName': queue,
                    'ResourceType': 'SQSQueue',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['SQSQueues'])} SQS queue policies")
        
        # SNS Topic Policies
        topics = self.list_sns_topics()
        for topic in topics:
            policy = self.get_sns_topic_policy(topic)
            if policy:
                resource_policies['SNSTopics'].append({
                    'ResourceName': topic,
                    'ResourceType': 'SNSTopic',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['SNSTopics'])} SNS topic policies")
        
        # Secrets Manager Secret Policies
        secrets = self.list_secrets()
        for secret in secrets:
            policy = self.get_secret_policy(secret)
            if policy:
                resource_policies['Secrets'].append({
                    'ResourceName': secret,
                    'ResourceType': 'Secret',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['Secrets'])} Secrets Manager policies")
        
        # ECR Repository Policies
        repos = self.list_ecr_repositories()
        for repo in repos:
            policy = self.get_ecr_repository_policy(repo)
            if policy:
                resource_policies['ECRRepositories'].append({
                    'ResourceName': repo,
                    'ResourceType': 'ECRRepository',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['ECRRepositories'])} ECR repository policies")
        
        # Glacier Vault Policies
        vaults = self.list_glacier_vaults()
        for vault in vaults:
            policy = self.get_glacier_vault_policy(vault)
            if policy:
                resource_policies['GlacierVaults'].append({
                    'ResourceName': vault,
                    'ResourceType': 'GlacierVault',
                    'Policy': policy
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(resource_policies['GlacierVaults'])} Glacier vault policies")
        
        # API Gateway Resource Policies


        # Write to file
        resource_policies_path = os.path.join(outdir, 'resource_policies.json')
        with open(resource_policies_path, 'w') as f:
            json.dump(resource_policies, f, indent=2, default=str)
        
        # Calculate total
        total_policies = sum(len(v) for v in resource_policies.values())
        logger.info(f"Exported {total_policies} total resource policies to {resource_policies_path}")


    def export_infrastructure_context(self, outdir: str):
        """Export compute and infrastructure context for path analysis."""
        logger.info("Exporting infrastructure context...")
        
        infra_data = {
            'EC2Instances': [],
            'LambdaTriggers': [],
            'NetworkInterfaces': []
        }
        
        # Network Interfaces (ENIs)
        interfaces = self.list_network_interfaces()
        for eni in interfaces:
            infra_data['NetworkInterfaces'].append({
                'NetworkInterfaceId': eni.get('NetworkInterfaceId'),
                'SubnetId': eni.get('SubnetId'),
                'VpcId': eni.get('VpcId'),
                'AvailabilityZone': eni.get('AvailabilityZone'),
                'Description': eni.get('Description'),
                'InterfaceType': eni.get('InterfaceType'),
                'Status': eni.get('Status'),
                'MacAddress': eni.get('MacAddress'),
                'PrivateIpAddress': eni.get('PrivateIpAddress'),
                'PrivateIpAddresses': eni.get('PrivateIpAddresses', []),
                'Association': eni.get('Association'), # Includes PublicIp
                'Groups': eni.get('Groups', []),       # Security Groups
                'Attachment': eni.get('Attachment')
            })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(infra_data['NetworkInterfaces'])} Network Interfaces with context")
        
        # EC2 Instances and profiles
        instances = self.list_instances()
        for instance in instances:
            name = ''
            for tag in instance.get('Tags', []):
                if tag['Key'] == 'Name':
                    name = tag['Value']
                    break
            
            infra_data['EC2Instances'].append({
                'InstanceId': instance['InstanceId'],
                'Name': name,
                'State': instance['State']['Name'],
                'PublicIpAddress': instance.get('PublicIpAddress'),
                'PrivateIpAddress': instance.get('PrivateIpAddress'),
                'IamInstanceProfile': instance.get('IamInstanceProfile'),
                'VpcId': instance.get('VpcId'),
                'SubnetId': instance.get('SubnetId'),
                'SecurityGroups': instance.get('SecurityGroups', [])
            })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(infra_data['EC2Instances'])} EC2 instances with context")
        
        # Lambda Triggers
        functions = self.list_lambda_functions()
        for func in functions:
            mappings = self.get_lambda_event_source_mappings(func)
            if mappings:
                infra_data['LambdaTriggers'].append({
                    'FunctionName': func,
                    'EventSourceMappings': mappings
                })
            safe_sleep(self.rate_limit)
        logger.info(f"Exported {len(infra_data['LambdaTriggers'])} Lambda functions with trigger mappings")
        
        # Write to file
        infra_path = os.path.join(outdir, 'infrastructure_context.json')
        with open(infra_path, 'w') as f:
            json.dump(infra_data, f, indent=2, default=str)
        logger.info(f"Infrastructure context exported to {infra_path}")

    def export_organization_context(self, outdir: str):
        """Export AWS Organizations and SCP information."""
        logger.info("Exporting organization context...")
        
        org_data = {
            'Organization': self.get_organization_info(),
            'AppliedSCPs': self.list_applied_scps()
        }
        
        # Write to file
        org_path = os.path.join(outdir, 'organization_context.json')
        with open(org_path, 'w') as f:
            json.dump(org_data, f, indent=2, default=str)
        
        if org_data['Organization']:
            logger.info(f"Exported organization info and {len(org_data['AppliedSCPs'])} SCPs to {org_path}")
        else:
            logger.info(f"Account does not appear to be part of an organization or insufficient permissions. Results in {org_path}")

    # ---------- Exposure Audit Logic ----------
    def _is_policy_publicly_exposed(self, policy: Dict[str, Any]) -> bool:
        """Check if a policy explicitly or implicitly allows public access."""
        if not policy:
            return False
            
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
            
        for stmt in statements:
            if stmt.get('Effect') != 'Allow':
                continue
                
            principals = stmt.get('Principal', {})
            if principals == "*":
                # Check for conditions that might restrict "public" to the account
                condition = stmt.get('Condition', {})
                if not condition:
                    return True
                # Very basic check: if there's no OrgID or SourceAccount condition, flag it
                if not any(k in str(condition) for k in ['aws:PrincipalOrgID', 'aws:SourceAccount', 'aws:SourceOwner']):
                    return True
                    
            aws_principals = principals.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
                
            for p in aws_principals:
                if p == "*":
                    condition = stmt.get('Condition', {})
                    if not condition or not any(k in str(condition) for k in ['aws:PrincipalOrgID', 'aws:SourceAccount', 'aws:SourceOwner']):
                        return True
                    
        return False

    def audit_s3_exposure(self) -> List[Dict[str, Any]]:
        exposed = []
        try:
            buckets = self.list_buckets()
            for bucket in buckets:
                policy = self.get_s3_bucket_policy(bucket)
                # Check Public Access Block
                pab = {}
                try:
                    res = self.s3.get_public_access_block(Bucket=bucket)
                    pab = res.get('PublicAccessBlockConfiguration', {})
                except botocore.exceptions.ClientError:
                    pass
                
                is_public = self._is_policy_publicly_exposed(policy)
                # If PAB is missing or false, it's more risky
                if is_public or not pab.get('BlockPublicPolicy', True):
                    exposed.append({
                        'BucketName': bucket,
                        'IsPubliclyExposed': is_public,
                        'PublicAccessBlock': pab
                    })
                safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"audit_s3_exposure failed: {e}")
        return exposed

    def audit_ec2_exposure(self) -> List[Dict[str, Any]]:
        exposed = []
        try:
            instances = self.list_instances()
            for inst in instances:
                public_ip = inst.get('PublicIpAddress')
                if not public_ip:
                    continue
                
                # Check Security Groups for 0.0.0.0/0
                open_ports = []
                for sg_ref in inst.get('SecurityGroups', []):
                    sg_id = sg_ref['GroupId']
                    try:
                        res = self.ec2.describe_security_groups(GroupIds=[sg_id])
                        for sg in res['SecurityGroups']:
                            for perm in sg.get('IpPermissions', []):
                                for range_obj in perm.get('IpRanges', []):
                                    if range_obj.get('CidrIp') == '0.0.0.0/0':
                                        port = perm.get('FromPort', 'all')
                                        open_ports.append({
                                            'GroupId': sg_id,
                                            'GroupName': sg.get('GroupName'),
                                            'Port': port,
                                            'Protocol': perm.get('IpProtocol')
                                        })
                    except botocore.exceptions.ClientError:
                        continue
                
                if open_ports:
                    exposed.append({
                        'InstanceId': inst['InstanceId'],
                        'Name': inst.get('Name'),
                        'PublicIp': public_ip,
                        'OpenPorts': open_ports
                    })
                safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"audit_ec2_exposure failed: {e}")
        return exposed

    def audit_rds_exposure(self) -> List[Dict[str, Any]]:
        exposed = []
        try:
            paginator = self.rds.get_paginator('describe_db_instances')
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    if db.get('PubliclyAccessible'):
                        exposed.append({
                            'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                            'Endpoint': db.get('Endpoint', {}).get('Address'),
                            'Engine': db.get('Engine'),
                            'VpcId': db.get('DBSubnetGroup', {}).get('VpcId')
                        })
            safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"audit_rds_exposure failed: {e}")
        return exposed

    def audit_resource_policy_exposure(self) -> Dict[str, List[Dict[str, Any]]]:
        exposure_map = {
            'SQS': [],
            'SNS': [],
            'Lambda': [],
            'KMS': [],
            'SecretsManager': [],
            'ECR': [],
            'Glacier': [],
            'APIGateway': [],
            'EFS': []
        }
        
        # SQS
        for q in self.list_sqs_queues():
            policy = self.get_sqs_queue_policy(q)
            if self._is_policy_publicly_exposed(policy):
                exposure_map['SQS'].append({'QueueUrl': q, 'Policy': policy})
            safe_sleep(self.rate_limit)
            
        # SNS
        for t in self.list_sns_topics():
            policy = self.get_sns_topic_policy(t)
            if self._is_policy_publicly_exposed(policy):
                exposure_map['SNS'].append({'TopicArn': t, 'Policy': policy})
            safe_sleep(self.rate_limit)
            
        # Lambda
        for f in self.list_lambda_functions():
            policy = self.get_lambda_policy(f)
            if self._is_policy_publicly_exposed(policy):
                exposure_map['Lambda'].append({'FunctionName': f, 'Policy': policy})
            safe_sleep(self.rate_limit)
            
        # KMS, SecretsManager, ECR, Glacier, APIGateway, EFS follow same pattern...
        # KMS
        for k in self.list_kms_keys():
            policy = self.get_kms_key_policy(k)
            if self._is_policy_publicly_exposed(policy):
                exposure_map['KMS'].append({'KeyId': k, 'Policy': policy})
            safe_sleep(self.rate_limit)
            
        # SecretsManager
        for s in self.list_secrets():
            policy = self.get_secret_policy(s)
            if self._is_policy_publicly_exposed(policy):
                exposure_map['SecretsManager'].append({'SecretArn': s, 'Policy': policy})
            safe_sleep(self.rate_limit)
            
        # ECR
        for r in self.list_ecr_repositories():
            policy = self.get_ecr_repository_policy(r)
            if self._is_policy_publicly_exposed(policy):
                exposure_map['ECR'].append({'RepositoryName': r, 'Policy': policy})
            safe_sleep(self.rate_limit)

        return exposure_map

    def audit_compute_exposure(self) -> Dict[str, List[Dict[str, Any]]]:
        compute = {
            'ECS': [],
            'ElasticBeanstalk': [],
            'Lightsail': []
        }
        
        # Lightsail
        try:
            res = self.lightsail.get_instances()
            for inst in res.get('instances', []):
                public_ip = inst.get('publicIpAddress')
                if public_ip:
                    compute['Lightsail'].append({
                        'Name': inst['name'],
                        'PublicIp': public_ip,
                        'IsStaticIp': inst.get('isStaticIp', False),
                        'Networking': inst.get('networking', {})
                    })
            safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError:
            pass
            
        # Elastic Beanstalk
        try:
            res = self.elasticbeanstalk.describe_environments()
            for env in res.get('Environments', []):
                cname = env.get('CNAME')
                if cname:
                    compute['ElasticBeanstalk'].append({
                        'EnvironmentName': env['EnvironmentName'],
                        'CNAME': cname,
                        'ApplicationName': env['ApplicationName'],
                        'Status': env['Status']
                    })
            safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError:
            pass
            
        # ECS
        try:
            clusters = self.ecs.list_clusters().get('clusterArns', [])
            for c_arn in clusters:
                services = self.ecs.list_services(cluster=c_arn).get('serviceArns', [])
                if services:
                    res = self.ecs.describe_services(cluster=c_arn, services=services)
                    for svc in res.get('services', []):
                        for lb in svc.get('loadBalancers', []):
                            compute['ECS'].append({
                                'ClusterArn': c_arn,
                                'ServiceName': svc['serviceName'],
                                'LoadBalancer': lb
                            })
            safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError:
            pass
            
        return compute

    def audit_federated_access(self) -> List[Dict[str, Any]]:
        """Audit IAM roles for Federated principals (OIDC/SAML)."""
        federated_roles = []
        try:
            roles = self.list_roles()
            for r in roles:
                role_name = r['RoleName']
                trust = r.get('AssumeRolePolicyDocument') or self.get_role_policy_document(role_name)
                if not trust:
                    continue
                
                statements = trust.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                    
                for stmt in statements:
                    if stmt.get('Effect') != 'Allow':
                        continue
                    
                    principals = stmt.get('Principal', {})
                    federated = principals.get('Federated')
                    if federated:
                        # Characterize the danger level
                        condition = stmt.get('Condition', {})
                        danger_reason = ""
                        
                        # Check for GitHub Actions specific broad patterns
                        cond_str = json.dumps(condition)
                        if "token.actions.githubusercontent.com" in str(federated):
                            if "repo:*/*" in cond_str:
                                danger_reason = "Extremely broad GitHub Actions condition (repo:*/*)"
                            elif ":ref:" not in cond_str and ":repo:" not in cond_str:
                                danger_reason = "Missing repo or ref restriction in GitHub Actions trust policy"
                        
                        federated_roles.append({
                            'RoleName': role_name,
                            'RoleArn': r['Arn'],
                            'FederatedPrincipal': federated,
                            'Condition': condition,
                            'DangerLevel': "HIGH" if danger_reason else "INFO",
                            'DangerReason': danger_reason
                        })
            safe_sleep(self.rate_limit)
        except botocore.exceptions.ClientError as e:
            logger.debug(f"audit_federated_access failed: {e}")
        return federated_roles

    def export_exposed_assets(self, outdir: str):
        """Audit and export exposed assets."""
        logger.info("Auditing exposed assets...")
        
        exposed_data = {
            'S3Buckets': self.audit_s3_exposure(),
            'EC2Instances': self.audit_ec2_exposure(),
            'RDSInstances': self.audit_rds_exposure(),
            'ResourcePolicies': self.audit_resource_policy_exposure(),
            'Compute': self.audit_compute_exposure(),
            'FederatedAccess': self.audit_federated_access()
        }
        
        exposed_path = os.path.join(outdir, 'exposed_assets.json')
        with open(exposed_path, 'w') as f:
            json.dump(exposed_data, f, indent=2, default=str)
        
        logger.info(f"Audit complete. Exposed assets exported to {exposed_path}")

    def export_caller_identity(self, outdir: str):
        """Export sts:GetCallerIdentity results for the current session."""
        try:
            identity = self.get_caller_identity()
            path = os.path.join(outdir, 'caller_identity.json')
            with open(path, 'w') as f:
                json.dump(identity, f, indent=2, default=str)
            logger.info(f"Caller identity exported to {path}")
        except Exception as e:
            logger.debug(f"export_caller_identity failed: {e}")

    def export_all(self, outdir: str):
        mkdir_p(outdir)
        
        # Export IAM data
        self.export_iam_data(outdir)
        
        
        # Export resource policies
        self.export_resource_policies(outdir)
        
        # Export infrastructure context
        self.export_infrastructure_context(outdir)
        
        # Export organization context
        self.export_organization_context(outdir)
        
        # Export caller identity
        self.export_caller_identity(outdir)
        
        # Export exposed assets audit
        self.export_exposed_assets(outdir)
        # Export graph data
        graph_path = os.path.join(outdir, 'graph.json')
        self.graph.export_json(graph_path)
        dot_path = os.path.join(outdir, 'graph.dot')
        self.graph.export_dot(dot_path)
        logger.info(f"Exported graph to {graph_path}, DOT to {dot_path}")


# --------- CLI ---------
def parse_args():
    p = argparse.ArgumentParser(description='AWS recursive enumeration agent (read-only by default)')
    p.add_argument('--profile', help='AWS CLI profile to use (optional)')
    p.add_argument('--region', help='AWS region', default='us-east-1')
    p.add_argument('--output', help='Output directory', default='out')
    p.add_argument('--assume-role', help='Role ARN to assume before starting enumeration (e.g., arn:aws:iam::123456789012:role/MyRole)')
    p.add_argument('--include-aws-policies', action='store_true', help='Include AWS-managed policies in export (warning: this can be slow)')
    p.add_argument('--dry-run', help='Do not perform state-changing actions or actual AssumeRole', action='store_true', default=True)
    p.add_argument('--allow-assume', help='Allow actual sts:AssumeRole calls (must also unset dry-run)', action='store_true')
    p.add_argument('--max-depth', type=int, default=3)
    p.add_argument('--rate-limit', type=float, default=0.2, help='Seconds to wait between API calls')
    p.add_argument('--deny', action='append', help='Deny-list substring for principal ARNs')
    p.add_argument('--allow', action='append', help='Allow-list substring for principal ARNs')
    return p.parse_args()


def main():
    args = parse_args()
    # if user explicitly passed --allow-assume, we require them to remove dry-run default
    dry_run = args.dry_run
    allow_assume = args.allow_assume
    if allow_assume and dry_run:
        logger.warning('You passed --allow-assume but dry-run is enabled by default. To perform AssumeRole, run without --dry-run flag (call script with --allow-assume and ensure not passing --dry-run).')

    # Create initial client factory
    cf = AWSClientFactory(profile=args.profile, region=args.region)
    
    # If --assume-role is provided, assume that role first
    if args.assume_role:
        logger.info(f"Assuming role: {args.assume_role}")
        try:
            sts = cf.client('sts')
            response = sts.assume_role(
                RoleArn=args.assume_role,
                RoleSessionName=f'iam-enum-{int(time.time())}'
            )
            creds = response['Credentials']
            logger.info(f"Successfully assumed role: {args.assume_role}")
            
            # Create new session with assumed role credentials
            session = boto3.Session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )
            cf = AWSClientFactory(profile=None, region=args.region)
            cf.session = session
        except botocore.exceptions.ClientError as e:
            logger.error(f"Failed to assume role {args.assume_role}: {e}")
            return
    
    enumerator = Enumerator(cf, dry_run=dry_run, allow_assume=allow_assume, max_depth=args.max_depth,
                            rate_limit=args.rate_limit, deny_list=args.deny or [], allow_list=args.allow or [],
                            include_aws_policies=args.include_aws_policies)

    try:
        cid = enumerator.get_caller_identity()
        start_arn = cid.get('Arn')
        enumerator.discover_from_identity(start_arn, depth=0, source=None)
        enumerator.export_all(args.output)
        logger.info('Enumeration complete.')
    except Exception as e:
        logger.exception('Fatal error during enumeration')


if __name__ == '__main__':
    main()

