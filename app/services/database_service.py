import logging
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload

from app.models.core import Finding, ScanStatus, AWSConfig as AWSConfigModel, KnowledgeBaseSearchRequest
from app.database.models import Scan, Finding as FindingDB, AWSConfig as AWSConfigDB, KnowledgeBase
from app.database.connection import AsyncSessionLocal

logger = logging.getLogger(__name__)


class DatabaseService:
    """Database service for storing and retrieving scan data"""
    
    async def create_scan(self, scan_name: Optional[str], targets: Optional[List[str]]) -> str:
        """Create a new scan record"""
        async with AsyncSessionLocal() as session:
            try:
                scan = Scan(
                    scan_name=scan_name,
                    status=ScanStatus.PENDING.value,
                    total_policies=0,
                    processed_policies=0,
                    findings_count=0
                )
                session.add(scan)
                await session.commit()
                await session.refresh(scan)
                
                logger.info(f"Created scan: {scan.id}")
                return str(scan.id)
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to create scan: {e}")
                raise
    
    async def update_scan_status(
        self, 
        scan_id: str, 
        status: ScanStatus, 
        error_message: Optional[str] = None
    ) -> bool:
        """Update scan status"""
        async with AsyncSessionLocal() as session:
            try:
                stmt = update(Scan).where(Scan.id == scan_id).values(
                    status=status.value,
                    error_message=error_message
                )
                await session.execute(stmt)
                await session.commit()
                
                logger.info(f"Updated scan {scan_id} status to {status.value}")
                return True
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to update scan status: {e}")
                return False
    
    async def store_findings(self, scan_id: str, findings: List[Finding]) -> bool:
        """Store multiple findings for a scan"""
        if not findings:
            return True
        
        async with AsyncSessionLocal() as session:
            try:
                # Convert findings to database models
                finding_records = []
                for finding in findings:
                    finding_db = FindingDB(
                        scan_id=scan_id,
                        resource_arn=finding.resource_arn,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity.value,
                        risk_score=finding.risk_score,
                        confidence_score=finding.confidence_score,
                        remediation_plan=finding.remediation_plan,
                        remediation_cli=finding.remediation_cli,
                        compliance_frameworks=finding.compliance_frameworks
                    )
                    finding_records.append(finding_db)
                
                # Bulk insert
                session.add_all(finding_records)
                await session.commit()
                
                # Update scan with findings count
                stmt = update(Scan).where(Scan.id == scan_id).values(
                    findings_count=len(findings)
                )
                await session.execute(stmt)
                await session.commit()
                
                logger.info(f"Stored {len(findings)} findings for scan {scan_id}")
                return True
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to store findings: {e}")
                return False
    
    async def get_scan(self, scan_id: str) -> Optional[Dict]:
        """Get scan details"""
        async with AsyncSessionLocal() as session:
            try:
                stmt = select(Scan).where(Scan.id == scan_id)
                result = await session.execute(stmt)
                scan = result.scalar_one_or_none()
                
                if scan:
                    return {
                        "id": str(scan.id),
                        "scan_name": scan.scan_name,
                        "status": scan.status,
                        "created_at": scan.created_at,
                        "updated_at": scan.updated_at,
                        "error_message": scan.error_message,
                        "total_policies": scan.total_policies,
                        "processed_policies": scan.processed_policies,
                        "findings_count": scan.findings_count
                    }
                return None
                
            except Exception as e:
                logger.error(f"Failed to get scan: {e}")
                return None
    
    async def get_scan_findings(self, scan_id: str) -> List[Dict]:
        """Get all findings for a scan"""
        async with AsyncSessionLocal() as session:
            try:
                stmt = select(FindingDB).where(FindingDB.scan_id == scan_id)
                result = await session.execute(stmt)
                findings = result.scalars().all()
                
                return [
                    {
                        "id": str(finding.id),
                        "resource_arn": finding.resource_arn,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity,
                        "risk_score": finding.risk_score,
                        "confidence_score": finding.confidence_score,
                        "remediation_plan": finding.remediation_plan,
                        "remediation_cli": finding.remediation_cli,
                        "compliance_frameworks": finding.compliance_frameworks,
                        "created_at": finding.created_at
                    }
                    for finding in findings
                ]
                
            except Exception as e:
                logger.error(f"Failed to get scan findings: {e}")
                return []
    
    async def get_aws_config(self, tenant_id: str) -> Optional[Dict]:
        """Get AWS configuration for a tenant"""
        async with AsyncSessionLocal() as session:
            try:
                stmt = select(AWSConfigDB).where(AWSConfigDB.tenant_id == tenant_id)
                result = await session.execute(stmt)
                config = result.scalar_one_or_none()
                
                if config:
                    return {
                        "aws_account_id": config.aws_account_id,
                        "aws_role_to_assume_arn": config.aws_role_to_assume_arn
                    }
                return None
                
            except Exception as e:
                logger.error(f"Failed to get AWS config: {e}")
                return None
    
    async def save_aws_config(self, tenant_id: str, aws_config: AWSConfigModel) -> bool:
        """Save AWS configuration for a tenant"""
        async with AsyncSessionLocal() as session:
            try:
                # Check if config exists
                stmt = select(AWSConfigDB).where(AWSConfigDB.tenant_id == tenant_id)
                result = await session.execute(stmt)
                existing_config = result.scalar_one_or_none()
                
                if existing_config:
                    # Update existing config
                    existing_config.aws_account_id = aws_config.aws_account_id
                    existing_config.aws_role_to_assume_arn = aws_config.aws_role_to_assume_arn
                else:
                    # Create new config
                    config_db = AWSConfigDB(
                        tenant_id=tenant_id,
                        aws_account_id=aws_config.aws_account_id,
                        aws_role_to_assume_arn=aws_config.aws_role_to_assume_arn
                    )
                    session.add(config_db)
                
                await session.commit()
                logger.info(f"Saved AWS config for tenant {tenant_id}")
                return True
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to save AWS config: {e}")
                return False
    
    async def health_check(self) -> bool:
        """Check database connectivity"""
        try:
            async with AsyncSessionLocal() as session:
                await session.execute(select(1))
                return True
        except Exception:
            return False
    
    async def search_knowledge_base(
        self,
        request: KnowledgeBaseSearchRequest
    ) -> List[Dict]:
        """
        Search knowledge base by cloud type, service, and filters.
        Returns top k matching rules based on criteria.
        """
        async with AsyncSessionLocal() as session:
            try:
                # Build query
                stmt = select(KnowledgeBase).where(
                    KnowledgeBase.cloud_type == request.cloud_type
                )
                
                # Add service filter if provided
                if request.service:
                    stmt = stmt.where(KnowledgeBase.service == request.service)
                
                # Add rule name filter if provided
                if request.rule_name_filter:
                    stmt = stmt.where(
                        KnowledgeBase.rule_name.ilike(f"%{request.rule_name_filter}%")
                    )
                
                # Add focus areas filter if provided
                if request.focus_areas:
                    # PostgreSQL JSONB contains operator
                    from sqlalchemy import func
                    for focus_area in request.focus_areas:
                        stmt = stmt.where(
                            func.jsonb_array_elements_text(KnowledgeBase.focus_areas).contains(focus_area)
                        )
                
                # Add compliance frameworks filter if provided
                if request.compliance_frameworks:
                    for framework in request.compliance_frameworks:
                        stmt = stmt.where(
                            func.jsonb_array_elements_text(KnowledgeBase.compliance_frameworks).contains(framework)
                        )
                
                # Order by relevance (could be improved with vector similarity)
                stmt = stmt.order_by(KnowledgeBase.created_at.desc())
                
                # Limit results
                stmt = stmt.limit(request.top_k)
                
                # Execute query
                result = await session.execute(stmt)
                entries = result.scalars().all()
                
                # Convert to dict
                return [
                    {
                        "id": str(entry.id),
                        "cloud_type": entry.cloud_type,
                        "service": entry.service,
                        "rule_name": entry.rule_name,
                        "rule_id": entry.rule_id,
                        "content": entry.content,
                        "source_url": entry.source_url,
                        "source_type": entry.source_type,
                        "source_category": entry.source_category,
                        "compliance_frameworks": entry.compliance_frameworks,
                        "compliance_controls": entry.compliance_controls,
                        "focus_areas": entry.focus_areas,
                        "certification": entry.certification,
                        "analysis": entry.analysis,
                        "vector_id": entry.vector_id,
                        "created_at": entry.created_at
                    }
                    for entry in entries
                ]
                
            except Exception as e:
                logger.error(f"Failed to search knowledge base: {e}")
                return []
    
    async def get_knowledge_by_ids(self, vector_ids: List[str]) -> List[Dict]:
        """Get knowledge base entries by vector IDs"""
        async with AsyncSessionLocal() as session:
            try:
                stmt = select(KnowledgeBase).where(
                    KnowledgeBase.vector_id.in_(vector_ids)
                )
                result = await session.execute(stmt)
                entries = result.scalars().all()
                
                return [
                    {
                        "id": str(entry.id),
                        "cloud_type": entry.cloud_type,
                        "service": entry.service,
                        "rule_name": entry.rule_name,
                        "content": entry.content,
                        "certification": entry.certification,
                        "analysis": entry.analysis,
                        "compliance_frameworks": entry.compliance_frameworks,
                        "focus_areas": entry.focus_areas
                    }
                    for entry in entries
                ]
                
            except Exception as e:
                logger.error(f"Failed to get knowledge by IDs: {e}")
                return []


# Singleton instance
database_service = DatabaseService()
