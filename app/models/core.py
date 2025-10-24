from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Finding(BaseModel):
    """
    Core model for security findings - this is the contract for LLM outputs.
    Uses instructor to guarantee structured responses.
    """
    resource_arn: str = Field(
        description="The full ARN of the affected AWS resource"
    )
    title: str = Field(
        description="A concise, descriptive title for the security finding"
    )
    description: str = Field(
        description="Detailed explanation of the vulnerability and its context"
    )
    severity: FindingSeverity = Field(
        description="The severity level of the finding"
    )
    risk_score: int = Field(
        ge=0, le=100,
        description="Calculated risk score from 0 to 100"
    )
    confidence_score: float = Field(
        ge=0.0, le=1.0,
        description="AI confidence in this finding being a true positive"
    )
    remediation_plan: str = Field(
        description="Step-by-step guide to fix the issue"
    )
    remediation_cli: Optional[str] = Field(
        None,
        description="Executable AWS CLI command to apply the fix"
    )
    compliance_frameworks: Optional[Dict[str, List[str]]] = Field(
        None,
        description="Mapping to compliance controls like CIS or NIST"
    )

    @validator('risk_score')
    def validate_risk_score(cls, v, values):
        """Ensure risk score aligns with severity"""
        severity = values.get('severity')
        if severity == FindingSeverity.CRITICAL and v < 80:
            return 85  # Auto-adjust for consistency
        elif severity == FindingSeverity.HIGH and v < 60:
            return 70
        return v


class PolicyContext(BaseModel):
    """Context information for policy analysis"""
    resource_arn: str
    resource_type: str  # role, user, group
    tags: Dict[str, str] = {}
    usage_patterns: Optional[str] = None
    business_context: Optional[str] = None


class AnalysisRequest(BaseModel):
    """Request model for policy analysis"""
    policy_document: dict
    context: PolicyContext


class ScanTriggerRequest(BaseModel):
    scan_name: Optional[str] = None
    targets: Optional[List[str]] = None

    @validator('targets')
    def validate_arns(cls, v):
        if v:
            for arn in v:
                if not arn.startswith('arn:aws:iam::'):
                    raise ValueError(f"Invalid IAM ARN: {arn}")
        return v


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    message: str


class AWSConfig(BaseModel):
    aws_account_id: str = Field(pattern=r'^\d{12}$')
    aws_role_to_assume_arn: str = Field(
        pattern=r'^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$'
    )


class KnowledgeBaseEntry(BaseModel):
    """
    Knowledge base entry model for storing compliance rules and security guidelines.
    Maps to the knowledge_base table in PostgreSQL.
    """
    id: Optional[str] = None
    cloud_type: str = Field(description="Cloud provider: aws, azure, gcp")
    service: str = Field(description="Service name: iam, s3, bedrock, etc.")
    rule_name: str = Field(description="Rule name / page title")
    rule_id: Optional[str] = None
    content: str = Field(description="Full page content for vector similarity search")
    source_url: Optional[str] = None
    source_type: str = Field(description="compliance_framework, best_practices, documentation")
    source_category: Optional[str] = None
    compliance_frameworks: Optional[Dict[str, List[str]]] = None
    compliance_controls: Optional[Dict[str, List[str]]] = None
    focus_areas: Optional[List[str]] = None
    certification: Optional[str] = None
    analysis: Optional[str] = None
    vector_id: Optional[str] = None


class KnowledgeBaseSearchRequest(BaseModel):
    """Request model for searching knowledge base"""
    cloud_type: str = Field(description="Cloud provider filter")
    service: Optional[str] = None
    rule_name_filter: Optional[str] = None
    focus_areas: Optional[List[str]] = None
    compliance_frameworks: Optional[List[str]] = None
    top_k: int = Field(default=5, ge=1, le=50, description="Number of results to return")
