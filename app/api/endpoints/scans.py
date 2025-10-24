import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.models.core import ScanTriggerRequest, ScanResponse
from app.services.cache_service import CacheService
from app.services.database_service import database_service
from app.orchestrators.scan_orchestrator import scan_orchestrator

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize services
cache_service = CacheService()

class ScanProgressResponse(BaseModel):
    scan_id: str
    status: str
    total_policies: int
    processed_policies: int
    findings_count: int
    error: Optional[str] = None

@router.post("/scans/trigger", response_model=ScanResponse, status_code=202)
async def trigger_scan(
    request: ScanTriggerRequest,
    tenant_id: str = "default"  # Would come from authentication in real app
):
    """
    Trigger a new IAM scan.
    Returns immediately with scan ID for tracking.
    """
    try:
        # Get AWS configuration
        aws_config = await database_service.get_aws_config(tenant_id)
        if not aws_config:
            raise HTTPException(
                status_code=404, 
                detail="AWS configuration not found. Please configure AWS access first."
            )
        
        # Use orchestrator to initiate scan
        scan_id = await scan_orchestrator.initiate_scan(
            scan_name=request.scan_name,
            aws_config=aws_config,
            targets=request.targets
        )
        
        logger.info(f"Triggered scan {scan_id}")
        
        return ScanResponse(
            scan_id=scan_id,
            status="PENDING",
            message="Scan has been successfully queued"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to trigger scan")


@router.get("/scans/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(scan_id: str):
    """
    Get real-time progress of a running scan.
    Useful for progress bars and status updates.
    """
    try:
        # Use orchestrator to get scan status (includes progress)
        status = await scan_orchestrator.get_scan_status(scan_id)
        
        return ScanProgressResponse(
            scan_id=scan_id,
            status=status.get('status', 'unknown'),
            total_policies=status.get('progress', {}).get('total_policies', 0),
            processed_policies=status.get('progress', {}).get('processed_policies', 0),
            findings_count=status.get('progress', {}).get('findings_count', 0),
            error=status.get('progress', {}).get('error')
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan progress: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan progress")


@router.get("/scans/{scan_id}/insights")
async def get_scan_insights(scan_id: str):
    """
    Get comprehensive scan results and insights.
    """
    try:
        # Use orchestrator to get scan results
        results = await scan_orchestrator.get_scan_results(scan_id)
        return results
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get scan insights: {e}")
        raise HTTPException(status_code=500, detail="Failed to get scan insights")


@router.get("/scans/")
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    tenant_id: str = "default"
):
    """
    List recent scans for a tenant.
    """
    try:
        scans = await scan_orchestrator.list_scans(limit, offset)
        return {"scans": scans}
        
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scans")


@router.delete("/scans/{scan_id}")
async def cancel_scan(scan_id: str):
    """
    Cancel a running scan.
    """
    try:
        success = await scan_orchestrator.cancel_scan(scan_id)
        if not success:
            raise HTTPException(status_code=400, detail="Cannot cancel scan in current state")
        
        return {"message": "Scan cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to cancel scan")
