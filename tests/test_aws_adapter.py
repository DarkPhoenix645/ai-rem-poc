"""
Tests for AWS Adapter functionality.
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from app.services.aws_adapter import AWSAdapter
from app.models.core import PolicyContext


class TestAWSAdapter:
    """Test cases for AWS Adapter."""
    
    @pytest.fixture
    def mock_aws_session(self):
        """Mock AWS session and clients."""
        mock_session = Mock()
        mock_iam_client = Mock()
        mock_sts_client = Mock()
        
        mock_session.client.side_effect = lambda service: {
            'iam': mock_iam_client,
            'sts': mock_sts_client
        }[service]
        
        return mock_session, mock_iam_client, mock_sts_client
    
    @pytest.fixture
    def aws_adapter(self, mock_aws_session):
        """Create AWS adapter with mocked session."""
        mock_session, mock_iam_client, mock_sts_client = mock_aws_session
        
        with patch('boto3.Session', return_value=mock_session), \
             patch('boto3.client', return_value=mock_sts_client):
            
            adapter = AWSAdapter(
                aws_account_id="123456789012",
                role_arn="arn:aws:iam::123456789012:role/ScannerRole"
            )
            adapter.session = mock_session
            adapter.iam_client = mock_iam_client
            return adapter
    
    def test_entity_summary(self, aws_adapter):
        """Test entity summary calculation."""
        entities = {
            'roles': [
                {
                    'InlinePolicies': [{'name': 'policy1'}, {'name': 'policy2'}],
                    'AttachedPolicies': [{'name': 'policy3'}]
                }
            ],
            'users': [
                {
                    'InlinePolicies': [{'name': 'policy4'}],
                    'AttachedPolicies': [{'name': 'policy5'}, {'name': 'policy6'}]
                }
            ],
            'groups': [
                {
                    'InlinePolicies': [{'name': 'policy7'}],
                    'AttachedPolicies': []
                }
            ],
            'policies': [{'name': 'policy8'}, {'name': 'policy9'}]
        }
        
        summary = aws_adapter.get_entity_summary(entities)
        
        assert summary['roles'] == 1
        assert summary['users'] == 1
        assert summary['groups'] == 1
        assert summary['policies'] == 2
        assert summary['total_policies'] == 9  # 3 + 3 + 1 + 2
    
    def test_extract_policies_for_analysis(self, aws_adapter):
        """Test policy extraction for analysis."""
        entities = {
            'roles': [
                {
                    'Arn': 'arn:aws:iam::123456789012:role/TestRole',
                    'RoleName': 'TestRole',
                    'Tags': {'Environment': 'test'},
                    'InlinePolicies': [
                        {
                            'PolicyName': 'inline-policy',
                            'PolicyDocument': {'Version': '2012-10-17', 'Statement': []}
                        }
                    ],
                    'AttachedPolicies': [
                        {
                            'PolicyName': 'attached-policy',
                            'PolicyArn': 'arn:aws:iam::123456789012:policy/TestPolicy',
                            'PolicyDocument': {'Version': '2012-10-17', 'Statement': []}
                        }
                    ]
                }
            ],
            'users': [],
            'groups': [],
            'policies': []
        }
        
        policies = aws_adapter.extract_policies_for_analysis(entities)
        
        assert len(policies) == 2  # 1 inline + 1 attached
        
        # Check first policy (inline)
        policy_doc, context = policies[0]
        assert policy_doc == {'Version': '2012-10-17', 'Statement': []}
        assert context.resource_arn == 'arn:aws:iam::123456789012:role/TestRole'
        assert context.resource_type == 'role'
        assert context.tags == {'Environment': 'test'}
        assert 'TestRole' in context.business_context
    
    def test_validate_aws_credentials_success(self, aws_adapter, mock_aws_session):
        """Test successful AWS credentials validation."""
        mock_session, mock_iam_client, mock_sts_client = mock_aws_session
        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        
        result = aws_adapter.validate_aws_credentials()
        assert result is True
        mock_sts_client.get_caller_identity.assert_called_once()
    
    def test_validate_aws_credentials_failure(self, aws_adapter, mock_aws_session):
        """Test failed AWS credentials validation."""
        mock_session, mock_iam_client, mock_sts_client = mock_aws_session
        mock_sts_client.get_caller_identity.side_effect = Exception("Invalid credentials")
        
        result = aws_adapter.validate_aws_credentials()
        assert result is False
    
    def test_get_aws_account_info_success(self, aws_adapter, mock_aws_session):
        """Test successful AWS account info retrieval."""
        mock_session, mock_iam_client, mock_sts_client = mock_aws_session
        mock_sts_client.get_caller_identity.return_value = {
            'Account': '123456789012',
            'UserId': 'AIDACKCEVSQ6C2EXAMPLE',
            'Arn': 'arn:aws:sts::123456789012:assumed-role/ScannerRole/iam-scanner-123456789012'
        }
        
        account_info = aws_adapter.get_aws_account_info()
        
        assert account_info['account_id'] == '123456789012'
        assert account_info['user_id'] == 'AIDACKCEVSQ6C2EXAMPLE'
        assert 'ScannerRole' in account_info['arn']
    
    def test_get_aws_account_info_failure(self, aws_adapter, mock_aws_session):
        """Test failed AWS account info retrieval."""
        mock_session, mock_iam_client, mock_sts_client = mock_aws_session
        mock_sts_client.get_caller_identity.side_effect = Exception("Access denied")
        
        account_info = aws_adapter.get_aws_account_info()
        assert account_info is None
    
    @pytest.mark.asyncio
    async def test_fetch_specific_targets(self, aws_adapter, mock_aws_session):
        """Test fetching specific IAM targets."""
        mock_session, mock_iam_client, mock_sts_client = mock_aws_session
        
        # Mock role response
        mock_iam_client.get_role.return_value = {
            'Role': {
                'Arn': 'arn:aws:iam::123456789012:role/TestRole',
                'RoleName': 'TestRole',
                'AssumeRolePolicyDocument': {'Version': '2012-10-17', 'Statement': []},
                'CreateDate': Mock()
            }
        }
        mock_iam_client.list_role_tags.return_value = {'Tags': []}
        mock_iam_client.list_role_policies.return_value = {'PolicyNames': []}
        mock_iam_client.list_attached_role_policies.return_value = {'AttachedPolicies': []}
        
        targets = ['arn:aws:iam::123456789012:role/TestRole']
        entities = await aws_adapter._fetch_specific_targets(targets)
        
        assert len(entities['roles']) == 1
        assert entities['roles'][0]['RoleName'] == 'TestRole'
        assert entities['users'] == []
        assert entities['groups'] == []
        assert entities['policies'] == []
    
    def test_policy_context_creation(self, aws_adapter):
        """Test PolicyContext creation in extract_policies_for_analysis."""
        entities = {
            'roles': [
                {
                    'Arn': 'arn:aws:iam::123456789012:role/TestRole',
                    'RoleName': 'TestRole',
                    'Tags': {'Environment': 'production', 'Owner': 'security-team'},
                    'InlinePolicies': [
                        {
                            'PolicyName': 'test-policy',
                            'PolicyDocument': {'Version': '2012-10-17', 'Statement': []}
                        }
                    ],
                    'AttachedPolicies': []
                }
            ],
            'users': [],
            'groups': [],
            'policies': []
        }
        
        policies = aws_adapter.extract_policies_for_analysis(entities)
        
        assert len(policies) == 1
        policy_doc, context = policies[0]
        
        # Verify PolicyContext
        assert isinstance(context, PolicyContext)
        assert context.resource_arn == 'arn:aws:iam::123456789012:role/TestRole'
        assert context.resource_type == 'role'
        assert context.tags == {'Environment': 'production', 'Owner': 'security-team'}
        assert 'TestRole' in context.business_context
