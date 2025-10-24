import json
import logging
import os
from typing import Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from app.models.core import PolicyContext

logger = logging.getLogger(__name__)


class AWSAdapter:
    """
    AWS IAM data fetching adapter.
    Handles role assumption and IAM resource enumeration.
    """
    
    def __init__(self, aws_account_id: str, role_arn: str):
        self.aws_account_id = aws_account_id
        self.role_arn = role_arn
        # Fetch ExternalId from environment variables for security
        self.external_id = os.environ.get("AWS_EXTERNAL_ID")
        self.session = None
        self.iam_client = None
        self._assume_role()
    
    def _assume_role(self):
        """Assume the cross-account role for scanning"""
        if not self.external_id:
            error_msg = "AWS_EXTERNAL_ID environment variable is not set. Cannot assume role."
            logger.error(error_msg)
            raise ValueError(error_msg)

        try:
            sts_client = boto3.client('sts')
            
            # Add ExternalId to the assume_role call for enhanced security
            response = sts_client.assume_role(
                RoleArn=self.role_arn,
                RoleSessionName=f'iam-scanner-{self.aws_account_id}',
                DurationSeconds=3600,  # 1 hour
                ExternalId=self.external_id
            )
            
            credentials = response['Credentials']
            
            # Create session with assumed role credentials
            self.session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            # Initialize IAM client
            self.iam_client = self.session.client('iam')
            
            logger.info(f"Successfully assumed role: {self.role_arn}")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                logger.error(f"Access Denied assuming role {self.role_arn}. Check trust policy and ExternalId.")
            else:
                logger.error(f"ClientError assuming role {self.role_arn}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to assume role {self.role_arn}: {e}")
            raise
    
    async def get_all_iam_entities(self, targets: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
        """
        Fetch all IAM entities (roles, users, groups, policies).
        
        Args:
            targets: Optional list of specific ARNs to fetch
            
        Returns:
            Dictionary containing all IAM entities with their policies
        """
        entities = {
            'roles': [],
            'users': [],
            'groups': [],
            'policies': []
        }
        
        try:
            if targets:
                # Fetch specific targets
                entities = await self._fetch_specific_targets(targets)
            else:
                # Fetch all entities
                entities['roles'] = await self._fetch_all_roles()
                entities['users'] = await self._fetch_all_users()
                entities['groups'] = await self._fetch_all_groups()
                entities['policies'] = await self._fetch_customer_policies()
            
            logger.info(f"Fetched {sum(len(v) for v in entities.values())} IAM entities")
            return entities
            
        except Exception as e:
            logger.error(f"Failed to fetch IAM entities: {e}")
            raise
    
    async def _fetch_specific_targets(self, targets: List[str]) -> Dict[str, List[Dict]]:
        """Fetch specific IAM resources by ARN"""
        entities = {'roles': [], 'users': [], 'groups': [], 'policies': []}
        
        for arn in targets:
            try:
                if '/role/' in arn:
                    role_name = arn.split('/role/')[1]
                    role_data = await self._fetch_role_with_policies(role_name)
                    if role_data:
                        entities['roles'].append(role_data)
                        
                elif '/user/' in arn:
                    user_name = arn.split('/user/')[1]
                    user_data = await self._fetch_user_with_policies(user_name)
                    if user_data:
                        entities['users'].append(user_data)
                        
                elif '/group/' in arn:
                    group_name = arn.split('/group/')[1]
                    group_data = await self._fetch_group_with_policies(group_name)
                    if group_data:
                        entities['groups'].append(group_data)
                        
            except Exception as e:
                logger.error(f"Failed to fetch target {arn}: {e}")
                continue
        
        return entities
    
    async def _fetch_all_roles(self) -> List[Dict]:
        """Fetch all IAM roles with their policies"""
        roles = []
        
        try:
            paginator = self.iam_client.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_data = await self._fetch_role_with_policies(role['RoleName'])
                    if role_data:
                        roles.append(role_data)
            
            return roles
            
        except Exception as e:
            logger.error(f"Failed to fetch roles: {e}")
            return []
    
    async def _fetch_role_with_policies(self, role_name: str) -> Optional[Dict]:
        """Fetch a role with all its policies"""
        try:
            # Get role details
            role_response = self.iam_client.get_role(RoleName=role_name)
            role = role_response['Role']
            
            # Get role tags
            try:
                tags_response = self.iam_client.list_role_tags(RoleName=role_name)
                tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
            except Exception:
                tags = {}
            
            # Get inline policies
            inline_policies = []
            try:
                policy_names = self.iam_client.list_role_policies(RoleName=role_name)
                for policy_name in policy_names['PolicyNames']:
                    policy_doc = self.iam_client.get_role_policy(
                        RoleName=role_name,
                        PolicyName=policy_name
                    )
                    inline_policies.append({
                        'PolicyName': policy_name,
                        'PolicyDocument': policy_doc['PolicyDocument']
                    })
            except Exception as e:
                logger.error(f"Failed to get inline policies for role {role_name}: {e}")
            
            # Get attached managed policies
            attached_policies = []
            try:
                attached_response = self.iam_client.list_attached_role_policies(RoleName=role_name)
                for policy in attached_response['AttachedPolicies']:
                    try:
                        # Get policy version document
                        policy_response = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                        version_response = self.iam_client.get_policy_version(
                            PolicyArn=policy['PolicyArn'],
                            VersionId=policy_response['Policy']['DefaultVersionId']
                        )
                        
                        attached_policies.append({
                            'PolicyName': policy['PolicyName'],
                            'PolicyArn': policy['PolicyArn'],
                            'PolicyDocument': version_response['PolicyVersion']['Document']
                        })
                    except Exception as e:
                        logger.error(f"Failed to get attached policy {policy['PolicyArn']}: {e}")
            except Exception as e:
                logger.error(f"Failed to get attached policies for role {role_name}: {e}")
            
            return {
                'Type': 'Role',
                'Arn': role['Arn'],
                'RoleName': role['RoleName'],
                'AssumeRolePolicyDocument': role['AssumeRolePolicyDocument'],
                'Tags': tags,
                'CreateDate': role['CreateDate'].isoformat(),
                'InlinePolicies': inline_policies,
                'AttachedPolicies': attached_policies
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch role {role_name}: {e}")
            return None
    
    async def _fetch_all_users(self) -> List[Dict]:
        """Fetch all IAM users with their policies"""
        users = []
        
        try:
            paginator = self.iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    user_data = await self._fetch_user_with_policies(user['UserName'])
                    if user_data:
                        users.append(user_data)
            
            return users
            
        except Exception as e:
            logger.error(f"Failed to fetch users: {e}")
            return []
    
    async def _fetch_user_with_policies(self, user_name: str) -> Optional[Dict]:
        """Fetch a user with all policies"""
        try:
            # Get user details
            user_response = self.iam_client.get_user(UserName=user_name)
            user = user_response['User']
            
            # Get user tags
            try:
                tags_response = self.iam_client.list_user_tags(UserName=user_name)
                tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
            except Exception:
                tags = {}
            
            # Get inline policies (similar to roles)
            inline_policies = []
            try:
                policy_names = self.iam_client.list_user_policies(UserName=user_name)
                for policy_name in policy_names['PolicyNames']:
                    policy_doc = self.iam_client.get_user_policy(
                        UserName=user_name,
                        PolicyName=policy_name
                    )
                    inline_policies.append({
                        'PolicyName': policy_name,
                        'PolicyDocument': policy_doc['PolicyDocument']
                    })
            except Exception as e:
                logger.error(f"Failed to get inline policies for user {user_name}: {e}")
            
            # Get attached managed policies (similar to roles)
            attached_policies = []
            try:
                attached_response = self.iam_client.list_attached_user_policies(UserName=user_name)
                for policy in attached_response['AttachedPolicies']:
                    try:
                        policy_response = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                        version_response = self.iam_client.get_policy_version(
                            PolicyArn=policy['PolicyArn'],
                            VersionId=policy_response['Policy']['DefaultVersionId']
                        )
                        
                        attached_policies.append({
                            'PolicyName': policy['PolicyName'],
                            'PolicyArn': policy['PolicyArn'],
                            'PolicyDocument': version_response['PolicyVersion']['Document']
                        })
                    except Exception as e:
                        logger.error(f"Failed to get attached policy {policy['PolicyArn']}: {e}")
            except Exception as e:
                logger.error(f"Failed to get attached policies for user {user_name}: {e}")
            
            return {
                'Type': 'User',
                'Arn': user['Arn'],
                'UserName': user['UserName'],
                'Tags': tags,
                'CreateDate': user['CreateDate'].isoformat(),
                'InlinePolicies': inline_policies,
                'AttachedPolicies': attached_policies
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch user {user_name}: {e}")
            return None
    
    async def _fetch_all_groups(self) -> List[Dict]:
        """Fetch all IAM groups with their policies"""
        groups = []
        
        try:
            paginator = self.iam_client.get_paginator('list_groups')
            
            for page in paginator.paginate():
                for group in page['Groups']:
                    group_data = await self._fetch_group_with_policies(group['GroupName'])
                    if group_data:
                        groups.append(group_data)
            
            return groups
            
        except Exception as e:
            logger.error(f"Failed to fetch groups: {e}")
            return []
    
    async def _fetch_group_with_policies(self, group_name: str) -> Optional[Dict]:
        """Fetch a group with all policies"""
        try:
            # Get group details
            group_response = self.iam_client.get_group(GroupName=group_name)
            group = group_response['Group']
            
            # Get group tags
            try:
                tags_response = self.iam_client.list_group_tags(GroupName=group_name)
                tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
            except Exception:
                tags = {}
            
            # Get inline policies
            inline_policies = []
            try:
                policy_names = self.iam_client.list_group_policies(GroupName=group_name)
                for policy_name in policy_names['PolicyNames']:
                    policy_doc = self.iam_client.get_group_policy(
                        GroupName=group_name,
                        PolicyName=policy_name
                    )
                    inline_policies.append({
                        'PolicyName': policy_name,
                        'PolicyDocument': policy_doc['PolicyDocument']
                    })
            except Exception as e:
                logger.error(f"Failed to get inline policies for group {group_name}: {e}")
            
            # Get attached managed policies
            attached_policies = []
            try:
                attached_response = self.iam_client.list_attached_group_policies(GroupName=group_name)
                for policy in attached_response['AttachedPolicies']:
                    try:
                        policy_response = self.iam_client.get_policy(PolicyArn=policy['PolicyArn'])
                        version_response = self.iam_client.get_policy_version(
                            PolicyArn=policy['PolicyArn'],
                            VersionId=policy_response['Policy']['DefaultVersionId']
                        )
                        
                        attached_policies.append({
                            'PolicyName': policy['PolicyName'],
                            'PolicyArn': policy['PolicyArn'],
                            'PolicyDocument': version_response['PolicyVersion']['Document']
                        })
                    except Exception as e:
                        logger.error(f"Failed to get attached policy {policy['PolicyArn']}: {e}")
            except Exception as e:
                logger.error(f"Failed to get attached policies for group {group_name}: {e}")
            
            return {
                'Type': 'Group',
                'Arn': group['Arn'],
                'GroupName': group['GroupName'],
                'Tags': tags,
                'CreateDate': group['CreateDate'].isoformat(),
                'InlinePolicies': inline_policies,
                'AttachedPolicies': attached_policies
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch group {group_name}: {e}")
            return None
    
    async def _fetch_customer_policies(self) -> List[Dict]:
        """Fetch customer-managed policies"""
        policies = []
        
        try:
            paginator = self.iam_client.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):  # Only customer policies
                for policy in page['Policies']:
                    try:
                        # Get policy document
                        version_response = self.iam_client.get_policy_version(
                            PolicyArn=policy['Arn'],
                            VersionId=policy['DefaultVersionId']
                        )
                        
                        policies.append({
                            'Type': 'Policy',
                            'Arn': policy['Arn'],
                            'PolicyName': policy['PolicyName'],
                            'PolicyDocument': version_response['PolicyVersion']['Document'],
                            'CreateDate': policy['CreateDate'].isoformat()
                        })
                        
                    except Exception as e:
                        logger.error(f"Failed to get policy document for {policy['Arn']}: {e}")
            
            return policies
            
        except Exception as e:
            logger.error(f"Failed to fetch customer policies: {e}")
            return []
    
    def extract_policies_for_analysis(self, entities: Dict[str, List[Dict]]) -> List[tuple]:
        """
        Extract all policies that need analysis.
        
        Returns:
            List of (policy_document, context) tuples
        """
        policies_to_analyze = []
        
        # Process roles
        for role in entities.get('roles', []):
            context = PolicyContext(
                resource_arn=role['Arn'],
                resource_type='role',
                tags=role.get('Tags', {}),
                business_context=f"IAM role: {role['RoleName']}"
            )
            
            # Add trust policy
            policies_to_analyze.append((role['AssumeRolePolicyDocument'], context))
            
            # Add inline policies
            for inline_policy in role.get('InlinePolicies', []):
                policies_to_analyze.append((inline_policy['PolicyDocument'], context))
            
            # Add attached policies
            for attached_policy in role.get('AttachedPolicies', []):
                policies_to_analyze.append((attached_policy['PolicyDocument'], context))
        
        # Process users (similar pattern)
        for user in entities.get('users', []):
            context = PolicyContext(
                resource_arn=user['Arn'],
                resource_type='user',
                tags=user.get('Tags', {}),
                business_context=f"IAM user: {user['UserName']}"
            )
            
            # Add policies (inline and attached)
            for inline_policy in user.get('InlinePolicies', []):
                policies_to_analyze.append((inline_policy['PolicyDocument'], context))
                
            for attached_policy in user.get('AttachedPolicies', []):
                policies_to_analyze.append((attached_policy['PolicyDocument'], context))
        
        # Process groups
        for group in entities.get('groups', []):
            context = PolicyContext(
                resource_arn=group['Arn'],
                resource_type='group',
                tags=group.get('Tags', {}),
                business_context=f"IAM group: {group['GroupName']}"
            )
            
            # Add inline policies
            for inline_policy in group.get('InlinePolicies', []):
                policies_to_analyze.append((inline_policy['PolicyDocument'], context))
            
            # Add attached policies
            for attached_policy in group.get('AttachedPolicies', []):
                policies_to_analyze.append((attached_policy['PolicyDocument'], context))
        
        # Process standalone customer policies
        for policy in entities.get('policies', []):
            context = PolicyContext(
                resource_arn=policy['Arn'],
                resource_type='policy',
                tags={},  # Customer policies don't have tags in the same way
                business_context=f"Customer-managed policy: {policy['PolicyName']}"
            )
            
            # Add the policy document
            policies_to_analyze.append((policy['PolicyDocument'], context))
        
        return policies_to_analyze
    
    def get_entity_summary(self, entities: Dict[str, List[Dict]]) -> Dict[str, int]:
        """
        Get a summary of the entities fetched.
        
        Returns:
            Dictionary with counts of each entity type
        """
        return {
            'roles': len(entities.get('roles', [])),
            'users': len(entities.get('users', [])),
            'groups': len(entities.get('groups', [])),
            'policies': len(entities.get('policies', [])),
            'total_policies': sum(
                len(role.get('InlinePolicies', [])) + len(role.get('AttachedPolicies', []))
                for role in entities.get('roles', [])
            ) + sum(
                len(user.get('InlinePolicies', [])) + len(user.get('AttachedPolicies', []))
                for user in entities.get('users', [])
            ) + sum(
                len(group.get('InlinePolicies', [])) + len(group.get('AttachedPolicies', []))
                for group in entities.get('groups', [])
            ) + len(entities.get('policies', []))
        }
    
    def validate_aws_credentials(self) -> bool:
        """
        Validate that AWS credentials are working.
        
        Returns:
            True if credentials are valid, False otherwise
        """
        try:
            if not self.session or not self.iam_client:
                return False
                
            # Try to get caller identity
            sts_client = self.session.client('sts')
            sts_client.get_caller_identity()
            return True
            
        except Exception as e:
            logger.error(f"AWS credentials validation failed: {e}")
            return False
    
    def get_aws_account_info(self) -> Optional[Dict]:
        """
        Get AWS account information.
        
        Returns:
            Dictionary with account information or None if failed
        """
        try:
            if not self.session:
                return None
                
            sts_client = self.session.client('sts')
            response = sts_client.get_caller_identity()
            
            return {
                'account_id': response.get('Account'),
                'user_id': response.get('UserId'),
                'arn': response.get('Arn')
            }
            
        except Exception as e:
            logger.error(f"Failed to get AWS account info: {e}")
            return None
