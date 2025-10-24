import asyncio
import logging
from typing import List, Optional

from celery import current_task

from app.models.core import AnalysisRequest, ScanStatus
from app.services.analysis_engine import analysis_engine
from app.services.aws_adapter import AWSAdapter
from app.services.cache_service import CacheService
from app.services.database_service import database_service
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3)
def process_iam_scan(self, scan_id: str, aws_config: dict, targets: Optional[List[str]] = None):
    """
    Main Celery task for processing IAM scans.
    This runs the entire analysis pipeline asynchronously.
    """
    
    # Run the async scan process
    return asyncio.run(_async_scan_process(self, scan_id, aws_config, targets))


async def _async_scan_process(task, scan_id: str, aws_config: dict, targets: Optional[List[str]]):
    """Async scan processing logic"""
    
    cache_service = CacheService()
    
    try:
        # Update scan status to RUNNING
        await database_service.update_scan_status(scan_id, ScanStatus.RUNNING)
        
        # Initialize progress tracking
        await cache_service.update_scan_progress(scan_id, {
            'status': 'initializing',
            'total_policies': 0,
            'processed_policies': 0,
            'findings_count': 0
        })
        
        # Initialize AWS adapter
        logger.info(f"Initializing AWS adapter for scan {scan_id}")
        aws_adapter = AWSAdapter(
            aws_config['aws_account_id'],
            aws_config['aws_role_to_assume_arn']
        )
        
        # Fetch IAM data
        logger.info(f"Fetching IAM entities for scan {scan_id}")
        entities = await aws_adapter.get_all_iam_entities(targets)
        
        # Extract policies for analysis
        policies_to_analyze = aws_adapter.extract_policies_for_analysis(entities)
        total_policies = len(policies_to_analyze)
        
        logger.info(f"Scan {scan_id}: Found {total_policies} policies to analyze")
        
        # Update progress
        await cache_service.update_scan_progress(scan_id, {
            'status': 'analyzing',
            'total_policies': total_policies,
            'processed_policies': 0,
            'findings_count': 0
        })
        
        # Process policies with controlled concurrency
        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent analyses
        tasks = []
        
        for i, (policy_doc, context) in enumerate(policies_to_analyze):
            task_coro = _analyze_single_policy_with_progress(
                semaphore, scan_id, i, policy_doc, context, total_policies, cache_service
            )
            tasks.append(task_coro)
        
        # Execute all analysis tasks
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful findings
        findings = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Policy analysis failed: {result}")
            else:
                findings.append(result)
        
        # Store findings in batches
        logger.info(f"Storing {len(findings)} findings for scan {scan_id}")
        await database_service.store_findings(scan_id, findings)
        
        # Update final progress
        await cache_service.update_scan_progress(scan_id, {
            'status': 'completed',
            'total_policies': total_policies,
            'processed_policies': total_policies,
            'findings_count': len(findings)
        })
        
        # Mark scan as completed
        await database_service.update_scan_status(scan_id, ScanStatus.COMPLETED)
        
        logger.info(f"Scan {scan_id} completed successfully with {len(findings)} findings")
        
        return {
            'scan_id': scan_id,
            'status': 'completed',
            'total_policies': total_policies,
            'findings_count': len(findings)
        }
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {str(e)}")
        
        # Update scan status to failed
        await database_service.update_scan_status(
            scan_id, 
            ScanStatus.FAILED, 
            error_message=str(e)
        )
        
        # Update progress to show failure
        await cache_service.update_scan_progress(scan_id, {
            'status': 'failed',
            'error': str(e)
        })
        
        # Re-raise for Celery retry mechanism
        raise


async def _analyze_single_policy_with_progress(
    semaphore: asyncio.Semaphore,
    scan_id: str,
    policy_index: int,
    policy_document: dict,
    context,
    total_policies: int,
    cache_service: CacheService
):
    """Analyze a single policy and update progress"""
    
    async with semaphore:
        try:
            # Create analysis request
            request = AnalysisRequest(
                policy_document=policy_document,
                context=context
            )
            
            # Perform analysis
            finding = await analysis_engine.analyze_policy(request)
            
            # Update progress
            processed_count = policy_index + 1
            await cache_service.update_scan_progress(scan_id, {
                'status': 'analyzing',
                'total_policies': total_policies,
                'processed_policies': processed_count,
                'findings_count': processed_count  # Approximate
            })
            
            logger.info(f"Scan {scan_id}: Analyzed policy {processed_count}/{total_policies}")
            
            return finding
            
        except Exception as e:
            logger.error(f"Failed to analyze policy {policy_index} in scan {scan_id}: {e}")
            raise
