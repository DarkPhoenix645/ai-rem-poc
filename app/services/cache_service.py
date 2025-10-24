import json
import logging
from typing import Optional

import redis.asyncio as redis

from app.config import get_settings
from app.models.core import Finding

logger = logging.getLogger(__name__)


class CacheService:
    """Redis-based caching service for LLM analysis results"""
    
    def __init__(self):
        self.settings = get_settings()
        self.redis_client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Redis client"""
        try:
            self.redis_client = redis.from_url(
                self.settings.redis_url,
                decode_responses=True
            )
            logger.info("Initialized Redis client")
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            raise
    
    async def get_finding(self, cache_key: str) -> Optional[Finding]:
        """Retrieve cached finding"""
        try:
            cached_data = await self.redis_client.get(f"finding:{cache_key}")
            if cached_data:
                finding_dict = json.loads(cached_data)
                return Finding(**finding_dict)
            return None
        except Exception as e:
            logger.error(f"Failed to get cached finding: {e}")
            return None
    
    async def store_finding(self, cache_key: str, finding: Finding) -> bool:
        """Store finding in cache"""
        try:
            finding_json = finding.json()
            await self.redis_client.setex(
                f"finding:{cache_key}",
                self.settings.cache_ttl_seconds,
                finding_json
            )
            return True
        except Exception as e:
            logger.error(f"Failed to cache finding: {e}")
            return False
    
    async def get_scan_progress(self, scan_id: str) -> Optional[dict]:
        """Get scan progress info"""
        try:
            progress_data = await self.redis_client.get(f"scan_progress:{scan_id}")
            if progress_data:
                return json.loads(progress_data)
            return None
        except Exception as e:
            logger.error(f"Failed to get scan progress: {e}")
            return None
    
    async def update_scan_progress(self, scan_id: str, progress_info: dict) -> bool:
        """Update scan progress"""
        try:
            await self.redis_client.setex(
                f"scan_progress:{scan_id}",
                3600,  # 1 hour TTL
                json.dumps(progress_info)
            )
            return True
        except Exception as e:
            logger.error(f"Failed to update scan progress: {e}")
            return False
    
    async def health_check(self) -> bool:
        """Check Redis connectivity"""
        try:
            await self.redis_client.ping()
            return True
        except Exception:
            return False
