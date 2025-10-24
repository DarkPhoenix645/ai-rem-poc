#!/usr/bin/env python3
"""
Migration script to populate knowledge_base table from crawler output.
Reads markdown files from crawler and stores them in PostgreSQL + ChromaDB.
"""

import asyncio
import hashlib
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert

from app.config import get_settings
from app.database.connection import AsyncSessionLocal, engine
from app.database.models import Base, KnowledgeBase
from app.services.rag_service import RAGService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KnowledgeBasePopulator:
    """Populates knowledge_base table from crawler markdown files"""
    
    def __init__(self):
        self.settings = get_settings()
        self.rag_service = RAGService()
        self.focus_areas = [
            "least_privilege_violations",
            "privilege_escalation_risks",
            "compliance_violations",
            "resource_wildcards"
        ]
    
    async def populate_from_directory(self, data_dir: str, cloud_type: str = "aws"):
        """
        Populate knowledge base from crawler output directory.
        
        Args:
            data_dir: Path to directory containing markdown files (e.g., "data/AZURE")
            cloud_type: Cloud provider (aws, azure, gcp)
        """
        data_path = Path(data_dir)
        
        if not data_path.exists():
            logger.error(f"Directory not found: {data_dir}")
            return
        
        # Create tables if they don't exist
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        total_files = 0
        total_inserted = 0
        
        # Process each category directory
        for category_dir in data_path.iterdir():
            if not category_dir.is_dir():
                continue
            
            category_name = category_dir.name
            logger.info(f"Processing category: {category_name}")
            
            # Process each markdown file in the category
            for md_file in category_dir.glob("*.md"):
                total_files += 1
                try:
                    await self._process_markdown_file(
                        md_file=md_file,
                        cloud_type=cloud_type,
                        category=category_name
                    )
                    total_inserted += 1
                except Exception as e:
                    logger.error(f"Failed to process {md_file}: {e}")
        
        logger.info(f"Processed {total_files} files, inserted {total_inserted} entries")
    
    async def _process_markdown_file(
        self,
        md_file: Path,
        cloud_type: str,
        category: str
    ):
        """Process a single markdown file and insert into database"""
        
        # Read markdown content
        with open(md_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if not content.strip():
            logger.warning(f"Empty file: {md_file}")
            return
        
        # Extract rule name from filename
        rule_name = md_file.stem
        
        # Determine service based on category and content
        service = self._extract_service(cloud_type, category, content)
        
        # Extract compliance frameworks and controls
        compliance_info = self._extract_compliance_info(content)
        
        # Extract source URL (if available in content)
        source_url = self._extract_source_url(content)
        
        # Generate unique ID
        rule_id = hashlib.md5(f"{cloud_type}_{service}_{rule_name}".encode()).hexdigest()
        
        # Extract certification and analysis content
        certification, analysis = self._extract_certification_and_analysis(content)
        
        # Determine focus areas based on content
        focus_areas = self._determine_focus_areas(content)
        
        # Store vector embedding in ChromaDB
        vector_id = await self._store_vector_embedding(
            content=content,
            metadata={
                "cloud_type": cloud_type,
                "service": service,
                "rule_name": rule_name,
                "category": category,
                "rule_id": rule_id
            }
        )
        
        # Prepare database entry
        kb_entry = {
            "cloud_type": cloud_type,
            "service": service,
            "rule_name": rule_name,
            "rule_id": rule_id,
            "content": content,
            "source_url": source_url,
            "source_type": "compliance_framework",
            "source_category": category,
            "compliance_frameworks": compliance_info.get("frameworks"),
            "compliance_controls": compliance_info.get("controls"),
            "focus_areas": focus_areas,
            "certification": certification,
            "analysis": analysis,
            "vector_id": vector_id
        }
        
        # Insert into PostgreSQL using upsert
        async with AsyncSessionLocal() as session:
            stmt = insert(KnowledgeBase).values(**kb_entry)
            stmt = stmt.on_conflict_do_update(
                index_elements=['rule_id'],
                set_=dict(
                    content=stmt.excluded.content,
                    compliance_frameworks=stmt.excluded.compliance_frameworks,
                    compliance_controls=stmt.excluded.compliance_controls,
                    focus_areas=stmt.excluded.focus_areas,
                    certification=stmt.excluded.certification,
                    analysis=stmt.excluded.analysis,
                    vector_id=stmt.excluded.vector_id,
                    updated_at=stmt.excluded.updated_at
                )
            )
            await session.execute(stmt)
            await session.commit()
        
        logger.info(f"Inserted: {rule_name} ({service})")
    
    def _extract_service(self, cloud_type: str, category: str, content: str) -> str:
        """Extract service name from category and content"""
        # Default mapping based on category keywords
        category_lower = category.lower()
        content_lower = content.lower()
        
        if "iam" in category_lower or "iam" in content_lower:
            return "iam"
        elif "s3" in category_lower or "storage" in category_lower:
            return "s3"
        elif "bedrock" in category_lower or "bedrock" in content_lower:
            return "bedrock"
        elif "compute" in category_lower or "ec2" in content_lower:
            return "compute"
        elif "lambda" in category_lower or "lambda" in content_lower:
            return "lambda"
        elif "vpc" in category_lower or "network" in category_lower:
            return "network"
        else:
            return "general"
    
    def _extract_compliance_info(self, content: str) -> Dict:
        """Extract compliance frameworks and controls from content"""
        frameworks = []
        controls = {}
        
        content_lower = content.lower()
        
        # Detect compliance frameworks
        if "cis" in content_lower:
            frameworks.append("CIS")
            cis_controls = re.findall(r'cis\s*\d+\.\d+', content_lower)
            if cis_controls:
                controls["CIS"] = list(set(cis_controls))
        
        if "nist" in content_lower:
            frameworks.append("NIST")
            nist_controls = re.findall(r'nist\s*[-\s]*(\d+[a-z]+-\d+)', content_lower)
            if nist_controls:
                controls["NIST"] = list(set(nist_controls))
        
        if "soc2" in content_lower or "soc 2" in content_lower:
            frameworks.append("SOC2")
        
        if "hipaa" in content_lower:
            frameworks.append("HIPAA")
        
        if "pci" in content_lower:
            frameworks.append("PCI-DSS")
        
        if not frameworks:
            frameworks = ["General"]
        
        return {
            "frameworks": frameworks,
            "controls": controls
        }
    
    def _extract_source_url(self, content: str) -> Optional[str]:
        """Extract source URL from content"""
        # Look for URLs in the content
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)
        
        if urls:
            # Return the first non-common URL
            for url in urls:
                if any(domain in url for domain in ['trendmicro.com', 'aws.amazon.com', 'azure.com', 'gcp.com']):
                    return url
            return urls[0]
        
        return None
    
    def _extract_certification_and_analysis(self, content: str) -> tuple:
        """Extract certification and analysis sections from content"""
        certification = None
        analysis = None
        
        # Look for common section headers
        sections = re.split(r'##+', content)
        
        for section in sections:
            section_lower = section.lower()
            
            if "certification" in section_lower or "certified" in section_lower:
                certification = section.strip()
            elif "analysis" in section_lower or "assessment" in section_lower:
                analysis = section.strip()
        
        # If no specific sections found, use content for both
        if not certification and not analysis:
            certification = content[:1000]  # First 1000 chars
            analysis = content
        
        return certification, analysis
    
    def _determine_focus_areas(self, content: str) -> List[str]:
        """Determine focus areas based on content"""
        detected_areas = []
        content_lower = content.lower()
        
        if any(keyword in content_lower for keyword in ['least privilege', 'minimal permissions', 'principle of least privilege']):
            detected_areas.append("least_privilege_violations")
        
        if any(keyword in content_lower for keyword in ['privilege escalation', 'escalation', 'privilege creep']):
            detected_areas.append("privilege_escalation_risks")
        
        if any(keyword in content_lower for keyword in ['compliance', 'violation', 'non-compliant', 'audit']):
            detected_areas.append("compliance_violations")
        
        if any(keyword in content_lower for keyword in ['wildcard', '*', 'any', 'all resources']):
            detected_areas.append("resource_wildcards")
        
        return detected_areas if detected_areas else self.focus_areas
    
    async def _store_vector_embedding(self, content: str, metadata: Dict) -> str:
        """Store content in ChromaDB and return vector ID"""
        vector_id = metadata.get("rule_id", hashlib.md5(content.encode()).hexdigest())
        
        try:
            await self.rag_service.add_documents(
                documents=[content],
                metadatas=[metadata],
                ids=[vector_id]
            )
            return vector_id
        except Exception as e:
            logger.error(f"Failed to store vector embedding: {e}")
            return vector_id


async def main():
    """Main function"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python populate_knowledge_base.py <data_directory> [cloud_type]")
        print("Example: python populate_knowledge_base.py data/AZURE azure")
        sys.exit(1)
    
    data_dir = sys.argv[1]
    cloud_type = sys.argv[2] if len(sys.argv) > 2 else "aws"
    
    populator = KnowledgeBasePopulator()
    await populator.populate_from_directory(data_dir, cloud_type)


if __name__ == "__main__":
    asyncio.run(main())

