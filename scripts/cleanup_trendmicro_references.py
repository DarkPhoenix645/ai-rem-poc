#!/usr/bin/env python3
"""
Script to remove identifying information about sources (Trend Micro references).
Simple search and replace for "Trend Micro" works for now.
"""

import asyncio
import logging
from sqlalchemy import select, update

from app.database.connection import AsyncSessionLocal
from app.database.models import KnowledgeBase

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def cleanup_trendmicro_references():
    """Remove Trend Micro references from knowledge base content"""
    
    async with AsyncSessionLocal() as session:
        try:
            # Get all entries that contain "Trend Micro" or variations
            stmt = select(KnowledgeBase).where(
                KnowledgeBase.content.ilike('%trend micro%')
            )
            result = await session.execute(stmt)
            entries = result.scalars().all()
            
            logger.info(f"Found {len(entries)} entries with Trend Micro references")
            
            replacements = [
                ("Trend Micro", ""),
                ("trend micro", ""),
                ("TREND MICRO", ""),
                ("TrendMicro", ""),
                ("trendmicro", ""),
                ("Cloud One Conformity", "Cloud Security"),
                ("CloudOne Conformity", "Cloud Security"),
            ]
            
            updated_count = 0
            
            for entry in entries:
                original_content = entry.content
                updated_content = original_content
                
                # Apply all replacements
                for old_text, new_text in replacements:
                    updated_content = updated_content.replace(old_text, new_text)
                
                # Update entry if content changed
                if updated_content != original_content:
                    entry.content = updated_content
                    updated_count += 1
                    logger.info(f"Updated: {entry.rule_name}")
            
            # Commit all changes
            await session.commit()
            logger.info(f"Updated {updated_count} entries")
            
        except Exception as e:
            await session.rollback()
            logger.error(f"Failed to cleanup references: {e}")
            raise


async def main():
    """Main function"""
    await cleanup_trendmicro_references()
    logger.info("Cleanup completed!")


if __name__ == "__main__":
    asyncio.run(main())

