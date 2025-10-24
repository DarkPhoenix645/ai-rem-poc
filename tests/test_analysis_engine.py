import pytest
import json
from unittest.mock import AsyncMock, MagicMock

from app.models.core import Finding, PolicyContext, AnalysisRequest, FindingSeverity


@pytest.fixture
def sample_policy():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }


@pytest.fixture
def policy_context():
    return PolicyContext(
        resource_arn="arn:aws:iam::123456789012:role/TestRole",
        resource_type="role",
        tags={"Environment": "test"},
        business_context="Test role for development"
    )


@pytest.mark.asyncio
async def test_heuristics_wildcard_detection(sample_policy, policy_context):
    """Test that the heuristics engine detects wildcard permissions"""
    from app.services.heuristics import HeuristicsEngine
    
    heuristics = HeuristicsEngine()
    
    # Create analysis request
    request = AnalysisRequest(
        policy_document=sample_policy,
        context=policy_context
    )
    
    # Perform analysis
    result = await heuristics.analyze(request)
    
    # Assertions
    assert result.severity == FindingSeverity.CRITICAL
    assert result.risk_score >= 90
    assert "wildcard" in result.title.lower()


@pytest.mark.asyncio
async def test_heuristics_no_issues():
    """Test heuristics with a safe policy"""
    from app.services.heuristics import HeuristicsEngine
    
    safe_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }
    
    context = PolicyContext(
        resource_arn="arn:aws:iam::123456789012:role/SafeRole",
        resource_type="role"
    )
    
    heuristics = HeuristicsEngine()
    request = AnalysisRequest(
        policy_document=safe_policy,
        context=context
    )
    
    result = await heuristics.analyze(request)
    
    # Should find no issues or low severity
    assert result.severity in [FindingSeverity.INFORMATIONAL, FindingSeverity.LOW]
    assert result.risk_score < 50
