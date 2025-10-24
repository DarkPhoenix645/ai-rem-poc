#!/usr/bin/env python3
"""
Knowledge base ingestion script for security research and best practices.
Run this to populate the RAG system with external knowledge.
"""

import asyncio
import hashlib
import logging
import re
from typing import List, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.config import get_settings
from app.services.rag_service import RAGService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KnowledgeIngester:
    """Ingests security knowledge from various sources"""
    
    def __init__(self):
        self.settings = get_settings()
        self.rag_service = RAGService()
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.settings.chunk_size,
            chunk_overlap=self.settings.chunk_overlap,
            separators=["\n\n", "\n", " ", ""]
        )
    
    async def ingest_web_content(self, urls: List[str]) -> None:
        """Ingest content from web URLs"""
        for url in urls:
            try:
                logger.info(f"Processing URL: {url}")
                content = self._scrape_web_content(url)
                
                if content:
                    await self._process_and_store(
                        content=content,
                        source_type="web",
                        source_url=url
                    )
                    
            except Exception as e:
                logger.error(f"Failed to process {url}: {e}")
    
    def _scrape_web_content(self, url: str) -> str:
        """Scrape and clean web content"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; IAMScanner/1.0; Security Research)'
            }
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Remove script, style, and navigation elements
            for element in soup(["script", "style", "nav", "header", "footer"]):
                element.decompose()
            
            # Extract main content
            content = soup.get_text(separator='\n', strip=True)
            
            # Clean up whitespace
            content = re.sub(r'\n\s*\n', '\n\n', content)
            content = re.sub(r' +', ' ', content)
            
            return content
            
        except Exception as e:
            logger.error(f"Failed to scrape {url}: {e}")
            return ""
    
    async def _process_and_store(self, content: str, source_type: str, source_url: str) -> None:
        """Process content into chunks and store in vector database"""
        try:
            # Split into chunks
            chunks = self.text_splitter.split_text(content)
            
            if not chunks:
                logger.warning(f"No chunks generated from {source_url}")
                return
            
            # Extract compliance framework metadata
            framework_metadata = self._extract_framework_metadata(source_url, content)
            
            # Prepare data for storage
            documents = []
            metadatas = []
            ids = []
            
            for i, chunk in enumerate(chunks):
                # Skip very short chunks
                if len(chunk.strip()) < 100:
                    continue
                
                # Generate unique ID
                chunk_id = hashlib.md5(f"{source_url}_{i}_{chunk[:100]}".encode()).hexdigest()
                
                # Create metadata with compliance framework information
                metadata = {
                    "source": source_url,
                    "source_type": source_type,
                    "chunk_index": i,
                    "chunk_length": len(chunk),
                    **framework_metadata
                }
                
                documents.append(chunk)
                metadatas.append(metadata)
                ids.append(chunk_id)
            
            if documents:
                await self.rag_service.add_documents(documents, metadatas, ids)
                logger.info(f"Stored {len(documents)} chunks from {source_url} with framework: {framework_metadata.get('compliance_framework', 'general')}")
            
        except Exception as e:
            logger.error(f"Failed to process content from {source_url}: {e}")
    
    def _extract_framework_metadata(self, source_url: str, content: str) -> dict:
        """Extract compliance framework metadata from source URL and content"""
        framework_metadata = {
            "compliance_framework": "general",
            "security_domain": "IAM",
            "framework_version": None
        }
        
        # Determine compliance framework from URL
        if "cisecurity.org" in source_url or "cis" in source_url.lower():
            framework_metadata["compliance_framework"] = "CIS"
            framework_metadata["security_domain"] = "CIS_Benchmarks"
        elif "nist.gov" in source_url or "nist" in source_url.lower():
            framework_metadata["compliance_framework"] = "NIST"
            framework_metadata["security_domain"] = "NIST_Framework"
        elif "aicpa.org" in source_url or "soc2" in source_url.lower():
            framework_metadata["compliance_framework"] = "SOC2"
            framework_metadata["security_domain"] = "SOC2_Framework"
        elif "hhs.gov" in source_url or "hipaa" in source_url.lower():
            framework_metadata["compliance_framework"] = "HIPAA"
            framework_metadata["security_domain"] = "HIPAA_Compliance"
        elif "pcisecuritystandards.org" in source_url or "pci" in source_url.lower():
            framework_metadata["compliance_framework"] = "PCI-DSS"
            framework_metadata["security_domain"] = "PCI_DSS_Compliance"
        elif "aws.amazon.com" in source_url:
            framework_metadata["compliance_framework"] = "AWS"
            framework_metadata["security_domain"] = "AWS_IAM"
        elif "owasp.org" in source_url:
            framework_metadata["compliance_framework"] = "OWASP"
            framework_metadata["security_domain"] = "Web_Security"
        
        # Extract version information from content
        version_patterns = [
            r"version\s+(\d+\.\d+)",
            r"rev\s*(\d+)",
            r"revision\s+(\d+)",
            r"v(\d+\.\d+)"
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, content[:1000], re.IGNORECASE)
            if match:
                framework_metadata["framework_version"] = match.group(1)
                break
        
        return framework_metadata


async def main():
    """Main ingestion function"""
    ingester = KnowledgeIngester()
    
    # Security research sources
    security_urls = [
        # AWS Security Best Practices
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples.html",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed.html",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html",
        
        # OWASP Cloud Security
        "https://owasp.org/www-project-cloud-security/",
        "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html",
        
        # CIS Benchmarks (publicly available summaries)
        "https://www.cisecurity.org/benchmark/amazon_web_services",
        "https://www.cisecurity.org/controls/",
        
        # NIST Framework Documentation
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        "https://csrc.nist.gov/publications/detail/sp/800-53b/rev-5/final",
        "https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final",
        "https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final",
        
        # SOC2 Framework Documentation
        "https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html",
        "https://www.coso.org/Pages/default.aspx",
        
        # HIPAA Framework Documentation
        "https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html",
        "https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html",
        "https://www.hhs.gov/hipaa/for-professionals/security/technical-safeguards/index.html",
        
        # PCI-DSS Framework Documentation
        "https://www.pcisecuritystandards.org/document_library/",
        "https://www.pcisecuritystandards.org/merchants/",
        
        # Additional Security Resources
        "https://cloudsecurityalliance.org/",
        "https://www.sans.org/white-papers/",
    ]
    
    # Ingest web content
    await ingester.ingest_web_content(security_urls)
    
    logger.info("Knowledge base ingestion completed!")


if __name__ == "__main__":
    asyncio.run(main())
