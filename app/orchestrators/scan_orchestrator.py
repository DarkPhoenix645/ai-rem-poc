"""
Scan orchestrator for coordinating the full IAM scanning pipeline.
"""
import asyncio
import logging
from typing import Dict, List, Optional

from app.models.core import ScanStatus
from app.services.database_service import database_service
from app.tasks.scan_tasks import process_iam_scan

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """
    Orchestrates the complete IAM scanning pipeline.
    Coordinates between API, database, and Celery workers.
    """
    
    def __init__(self):
        self.database_service = database_service
    
    async def initiate_scan(
        self,
        scan_name: str,
        aws_config: Dict,
        targets: Optional[List[str]] = None
    ) -> str:
        """
        Initiate a new IAM scan.
        
        Args:
            scan_name: Human-readable name for the scan
            aws_config: AWS configuration (account_id, role_arn)
            targets: Optional list of specific ARNs to scan
            
        Returns:
            scan_id: Unique identifier for the scan
        """
        try:
            # Create scan record
            scan_id = await self.database_service.create_scan(
                scan_name=scan_name,
                aws_config=aws_config,
                targets=targets
            )
            
            logger.info(f"Created scan {scan_id}: {scan_name}")
            
            # Queue the scan task
            task = process_iam_scan.delay(scan_id, aws_config, targets)
            
            # Store task ID for tracking
            await self.database_service.update_scan_task_id(scan_id, task.id)
            
            logger.info(f"Queued scan task {task.id} for scan {scan_id}")
            
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to initiate scan: {e}")
            raise
    
    async def get_scan_status(self, scan_id: str) -> Dict:
        """
        Get current status of a scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Dictionary with scan status and progress
        """
        try:
            # Get scan from database
            scan = await self.database_service.get_scan(scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            # Get progress from cache
            from app.services.cache_service import CacheService
            cache_service = CacheService()
            progress = await cache_service.get_scan_progress(scan_id)
            
            return {
                'scan_id': scan_id,
                'scan_name': scan.scan_name,
                'status': scan.status.value,
                'created_at': scan.created_at.isoformat(),
                'updated_at': scan.updated_at.isoformat(),
                'progress': progress or {},
                'aws_account_id': scan.aws_config.get('aws_account_id'),
                'targets': scan.targets
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            raise
    
    async def get_scan_results(self, scan_id: str) -> Dict:
        """
        Get results of a completed scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Dictionary with scan results and findings
        """
        try:
            # Get scan details
            scan = await self.database_service.get_scan(scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            # Get findings
            findings = await self.database_service.get_scan_findings(scan_id)
            
            # Get insights
            insights = await self.database_service.get_scan_insights(scan_id)
            
            return {
                'scan_id': scan_id,
                'scan_name': scan.scan_name,
                'status': scan.status.value,
                'created_at': scan.created_at.isoformat(),
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'total_findings': len(findings),
                'findings': [
                    {
                        'resource_arn': f.resource_arn,
                        'title': f.title,
                        'severity': f.severity.value,
                        'risk_score': f.risk_score,
                        'confidence_score': f.confidence_score
                    }
                    for f in findings
                ],
                'insights': insights
            }
            
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
            raise
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            True if cancelled successfully
        """
        try:
            # Get scan details
            scan = await self.database_service.get_scan(scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            
            if scan.status in [ScanStatus.COMPLETED, ScanStatus.FAILED]:
                logger.warning(f"Cannot cancel scan {scan_id} with status {scan.status}")
                return False
            
            # Cancel Celery task if it exists
            if scan.task_id:
                from app.tasks.celery_app import celery_app
                celery_app.control.revoke(scan.task_id, terminate=True)
                logger.info(f"Cancelled Celery task {scan.task_id}")
            
            # Update scan status
            await self.database_service.update_scan_status(
                scan_id,
                ScanStatus.CANCELLED,
                error_message="Scan cancelled by user"
            )
            
            logger.info(f"Cancelled scan {scan_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel scan: {e}")
            return False
    
    async def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict]:
        """
        List recent scans.
        
        Args:
            limit: Maximum number of scans to return
            offset: Number of scans to skip
            
        Returns:
            List of scan summaries
        """
        try:
            scans = await self.database_service.list_scans(limit, offset)
            
            return [
                {
                    'scan_id': scan.scan_id,
                    'scan_name': scan.scan_name,
                    'status': scan.status.value,
                    'created_at': scan.created_at.isoformat(),
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'aws_account_id': scan.aws_config.get('aws_account_id')
                }
                for scan in scans
            ]
            
        except Exception as e:
            logger.error(f"Failed to list scans: {e}")
            raise


# Singleton instance
scan_orchestrator = ScanOrchestrator()
