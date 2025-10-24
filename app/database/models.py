from datetime import datetime
from typing import Optional
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, JSON, Enum, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
import uuid

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_name = Column(String(255), nullable=True)
    status = Column(String(50), nullable=False)  # PENDING, RUNNING, COMPLETED, FAILED
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    error_message = Column(Text, nullable=True)
    total_policies = Column(Integer, default=0)
    processed_policies = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)


class Finding(Base):
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), nullable=False)
    resource_arn = Column(String(500), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    risk_score = Column(Integer, nullable=False)
    confidence_score = Column(Float, nullable=False)
    remediation_plan = Column(Text, nullable=False)
    remediation_cli = Column(Text, nullable=True)
    compliance_frameworks = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AWSConfig(Base):
    __tablename__ = "aws_configs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(100), nullable=False, unique=True)
    aws_account_id = Column(String(12), nullable=False)
    aws_role_to_assume_arn = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class KnowledgeBase(Base):
    """
    Knowledge base table for storing compliance rules and security guidelines.
    Provider-agnostic table supporting AWS, Azure, GCP and their services.
    Each entry represents a rule/guideline with full content for vector similarity search.
    """
    __tablename__ = "knowledge_base"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Provider and service information
    cloud_type = Column(String(50), nullable=False)  # aws, azure, gcp
    service = Column(String(100), nullable=False)  # iam, s3, bedrock, compute, etc.
    
    # Rule identification
    rule_name = Column(String(500), nullable=False)  # Page title / rule name
    rule_id = Column(String(255), nullable=True)  # Unique identifier for the rule
    
    # Full content for vector similarity search
    content = Column(Text, nullable=False)  # Complete page content (markdown/text)
    
    # Source information
    source_url = Column(String(1000), nullable=True)  # Original URL
    source_type = Column(String(100), nullable=False)  # compliance_framework, best_practices, documentation
    source_category = Column(String(255), nullable=True)  # Category/subcategory from crawler
    
    # Compliance and analysis metadata
    compliance_frameworks = Column(JSON, nullable=True)  # ["CIS", "NIST", "SOC2"]
    compliance_controls = Column(JSON, nullable=True)  # {"CIS": ["1.1", "1.2"], "NIST": ["AC-3"]}
    
    # Focus areas this rule addresses
    focus_areas = Column(JSON, nullable=True)  # ["least_privilege_violations", "privilege_escalation_risks"]
    
    # Analysis and certification
    certification = Column(Text, nullable=True)  # Content about certification/compliance
    analysis = Column(Text, nullable=True)  # Analysis content
    
    # Vector reference (ChromaDB ID)
    vector_id = Column(String(255), nullable=True)  # Reference to ChromaDB embedding
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes for faster lookups
    __table_args__ = (
        Index('idx_kb_cloud_service', 'cloud_type', 'service'),
        Index('idx_kb_rule_name', 'rule_name'),
        Index('idx_kb_source_type', 'source_type'),
    )
