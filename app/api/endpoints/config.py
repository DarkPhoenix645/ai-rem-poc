import logging
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.models.core import AWSConfig
from app.services.database_service import database_service
from app.services.aws_adapter import AWSAdapter

logger = logging.getLogger(__name__)
router = APIRouter()

class AWSConfigRequest(BaseModel):
    aws_account_id: str
    aws_role_to_assume_arn: str

@router.put("/config/aws")
async def configure_aws_access(
    request: AWSConfigRequest,
    tenant_id: str = "default"
):
    """
    Configure AWS access for a tenant.
    Updates the AWS connection configuration for the account.
    """
    try:
        # Validate and save the configuration
        config = AWSConfig(
            aws_account_id=request.aws_account_id,
            aws_role_to_assume_arn=request.aws_role_to_assume_arn
        )
        
        # Save to database
        success = await database_service.save_aws_config(tenant_id, config)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to save AWS configuration")
        
        logger.info(f"Configured AWS access for tenant {tenant_id}")
        
        return {
            "status": "success",
            "message": "AWS configuration updated successfully."
        }
        
    except Exception as e:
        logger.error(f"Failed to configure AWS access: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/config/aws/{tenant_id}")
async def get_aws_config(tenant_id: str):
    """
    Get AWS configuration for a tenant.
    """
    try:
        config = await database_service.get_aws_config(tenant_id)
        if not config:
            raise HTTPException(status_code=404, detail="AWS configuration not found")
        
        return config
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get AWS config: {e}")
        raise HTTPException(status_code=500, detail="Failed to get AWS configuration")


@router.get("/aws/iam-roles")
async def get_iam_roles(
    limit: int = 50,
    next_token: Optional[str] = None,
    tenant_id: str = "default"
):
    """
    Fetches a list of IAM roles from the configured AWS account.
    Useful for UIs that allow users to select specific roles for a targeted scan.
    """
    try:
        # Get AWS configuration
        aws_config = await database_service.get_aws_config(tenant_id)
        if not aws_config:
            raise HTTPException(
                status_code=404, 
                detail="AWS configuration not found. Please configure AWS access first."
            )
        
        # Initialize AWS adapter
        aws_adapter = AWSAdapter(
            aws_config['aws_account_id'],
            aws_config['aws_role_to_assume_arn']
        )
        
        # Fetch roles (this would need pagination implementation)
        entities = await aws_adapter.get_all_iam_entities()
        roles = entities.get('roles', [])
        
        # Format response according to spec
        formatted_roles = []
        for role in roles[:limit]:
            formatted_roles.append({
                "role_name": role['RoleName'],
                "arn": role['Arn'],
                "created_date": role['CreateDate']
            })
        
        return {
            "roles": formatted_roles,
            "next_token": None  # Would implement proper pagination
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get IAM roles: {e}")
        raise HTTPException(status_code=502, detail="Could not assume role or communicate with AWS APIs")
