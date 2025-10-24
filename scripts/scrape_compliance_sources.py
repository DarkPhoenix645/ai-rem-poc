#!/usr/bin/env python3
"""
Web scraper to extract compliance knowledge from official sources.
Outputs markdown files in the format expected by populate_knowledge_base.py
"""

import asyncio
import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse

import aiohttp
import requests
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MAX_WORKERS = 5
REQUEST_TIMEOUT = 30
RETRY_DELAY = 2
MAX_RETRIES = 3

# Headers to mimic a real browser
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
}

class ComplianceScraper:
    """Scrapes compliance documentation and outputs markdown files"""
    
    def __init__(self, output_dir: str = "data"):
        self.output_dir = Path(output_dir)
        self.session = None
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            headers=HEADERS,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def scrape_all_sources(self):
        """Scrape all compliance sources"""
        
        # Create output directories
        self.output_dir.mkdir(exist_ok=True)
        
        # AWS Sources
        aws_dir = self.output_dir / "AWS"
        aws_dir.mkdir(exist_ok=True)
        
        # TrendMicro Sources
        trendmicro_dir = self.output_dir / "TrendMicro"
        trendmicro_dir.mkdir(exist_ok=True)
        
        # Scrape AWS IAM documentation
        await self.scrape_aws_iam_docs(aws_dir)
        
        # Scrape TrendMicro knowledge base
        await self.scrape_trendmicro_kb(trendmicro_dir)
        
        logger.info("Scraping completed!")
    
    async def scrape_aws_iam_docs(self, output_dir: Path):
        """Scrape AWS IAM documentation"""
        logger.info("Scraping AWS IAM documentation...")
        
        aws_sources = {
            "IAM": {
                "urls": [
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples.html",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
                ],
                "category": "IAM"
            },
            "S3": {
                "urls": [
                    "https://docs.aws.amazon.com/s3/latest/userguide/security.html",
                    "https://docs.aws.amazon.com/s3/latest/userguide/access-policy-language-overview.html"
                ],
                "category": "S3"
            },
            "Security": {
                "urls": [
                    "https://docs.aws.amazon.com/security/latest/userguide/security.html",
                    "https://docs.aws.amazon.com/security/latest/userguide/security-best-practices.html"
                ],
                "category": "Security"
            }
        }
        
        for service_name, config in aws_sources.items():
            service_dir = output_dir / service_name
            service_dir.mkdir(exist_ok=True)
            
            for url in config["urls"]:
                try:
                    await self.scrape_url_to_markdown(url, service_dir, config["category"])
                except Exception as e:
                    logger.error(f"Failed to scrape {url}: {e}")
    
    async def scrape_trendmicro_kb(self, output_dir: Path):
        """Scrape TrendMicro knowledge base"""
        logger.info("Scraping TrendMicro knowledge base...")
        
        # TrendMicro knowledge base URLs
        trendmicro_sources = {
            "AWS": {
                "base_url": "https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/",
                "category": "AWS"
            },
            "Azure": {
                "base_url": "https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/",
                "category": "Azure"
            }
        }
        
        for cloud_provider, config in trendmicro_sources.items():
            cloud_dir = output_dir / cloud_provider
            cloud_dir.mkdir(exist_ok=True)
            
            try:
                await self.scrape_trendmicro_category(config["base_url"], cloud_dir, config["category"])
            except Exception as e:
                logger.error(f"Failed to scrape TrendMicro {cloud_provider}: {e}")
    
    async def scrape_trendmicro_category(self, base_url: str, output_dir: Path, category: str):
        """Scrape a TrendMicro category page and all its articles"""
        
        # Get the main category page
        async with self.session.get(base_url) as response:
            if response.status != 200:
                logger.error(f"Failed to fetch {base_url}: {response.status}")
                return
            
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            
            # Find all article links
            article_links = []
            
            # Look for links in various selectors that TrendMicro might use
            selectors = [
                'a[href*="/knowledge-base/"]',
                'a[href*="/article/"]',
                '.article-link',
                '.kb-link',
                'h3 a',
                'h4 a'
            ]
            
            for selector in selectors:
                links = soup.select(selector)
                for link in links:
                    href = link.get('href')
                    if href and '/knowledge-base/' in href:
                        full_url = urljoin(base_url, href)
                        title = link.get_text(strip=True)
                        if title and full_url not in [l['url'] for l in article_links]:
                            article_links.append({
                                'url': full_url,
                                'title': title
                            })
            
            logger.info(f"Found {len(article_links)} articles in {category}")
            
            # Scrape each article
            for i, article in enumerate(article_links[:10]):  # Limit to 10 for testing
                try:
                    await self.scrape_url_to_markdown(
                        article['url'], 
                        output_dir, 
                        category,
                        custom_title=article['title']
                    )
                    await asyncio.sleep(1)  # Be respectful
                except Exception as e:
                    logger.error(f"Failed to scrape article {article['url']}: {e}")
    
    async def scrape_url_to_markdown(self, url: str, output_dir: Path, category: str, custom_title: str = None):
        """Scrape a single URL and save as markdown"""
        
        for attempt in range(MAX_RETRIES):
            try:
                async with self.session.get(url) as response:
                    if response.status != 200:
                        logger.warning(f"HTTP {response.status} for {url}")
                        continue
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Extract title
                    title = custom_title or self.extract_title(soup, url)
                    if not title:
                        logger.warning(f"No title found for {url}")
                        continue
                    
                    # Extract content
                    content = self.extract_content(soup, url)
                    if not content:
                        logger.warning(f"No content found for {url}")
                        continue
                    
                    # Create markdown content
                    markdown_content = self.create_markdown_content(title, content, url, category)
                    
                    # Save to file
                    filename = self.sanitize_filename(title)
                    filepath = output_dir / f"{filename}.md"
                    
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(markdown_content)
                    
                    logger.info(f"Saved: {filepath}")
                    return
                    
            except Exception as e:
                logger.warning(f"Attempt {attempt + 1} failed for {url}: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY * (attempt + 1))
                else:
                    raise
    
    def extract_title(self, soup: BeautifulSoup, url: str) -> str:
        """Extract title from HTML"""
        
        # Try various title selectors
        title_selectors = [
            'h1',
            'title',
            '.page-title',
            '.article-title',
            '.kb-title',
            '[data-testid="title"]'
        ]
        
        for selector in title_selectors:
            title_elem = soup.select_one(selector)
            if title_elem:
                title = title_elem.get_text(strip=True)
                if title and len(title) > 3:
                    return title
        
        # Fallback to URL-based title
        parsed_url = urlparse(url)
        path_parts = parsed_url.path.strip('/').split('/')
        if path_parts:
            return path_parts[-1].replace('-', ' ').replace('_', ' ').title()
        
        return "Untitled Document"
    
    def extract_content(self, soup: BeautifulSoup, url: str) -> str:
        """Extract main content from HTML"""
        
        # Remove unwanted elements
        for element in soup(['script', 'style', 'nav', 'footer', 'header', 'aside']):
            element.decompose()
        
        # Try to find main content area
        content_selectors = [
            'main',
            '.main-content',
            '.content',
            '.article-content',
            '.kb-content',
            '.post-content',
            '[role="main"]'
        ]
        
        main_content = None
        for selector in content_selectors:
            content_elem = soup.select_one(selector)
            if content_elem:
                main_content = content_elem
                break
        
        if not main_content:
            main_content = soup.find('body') or soup
        
        # Extract text content
        content = main_content.get_text(separator='\n', strip=True)
        
        # Clean up the content
        content = re.sub(r'\n\s*\n', '\n\n', content)  # Normalize line breaks
        content = re.sub(r'[ \t]+', ' ', content)  # Normalize spaces
        
        return content.strip()
    
    def create_markdown_content(self, title: str, content: str, url: str, category: str) -> str:
        """Create markdown content in the format expected by populate_knowledge_base.py"""
        
        # Extract compliance frameworks based on URL and content
        compliance_frameworks = self.extract_compliance_frameworks(url, content)
        compliance_controls = self.extract_compliance_controls(content)
        focus_areas = self.extract_focus_areas(content)
        
        # Create markdown
        markdown = f"""# {title}

## Overview
{self.extract_overview(content)}

## Key Principles
{self.extract_key_principles(content)}

## Compliance Frameworks
{', '.join(compliance_frameworks)}

## Compliance Controls
{self.format_compliance_controls(compliance_controls)}

## Focus Areas
{', '.join(focus_areas)}

## Analysis
{self.extract_analysis(content)}

## Certification
{self.extract_certification(content)}

## Source
{url}

## Full Content
{content}
"""
        
        return markdown
    
    def extract_compliance_frameworks(self, url: str, content: str) -> List[str]:
        """Extract compliance frameworks from URL and content"""
        frameworks = []
        
        url_lower = url.lower()
        content_lower = content.lower()
        
        # AWS-specific
        if 'aws.amazon.com' in url_lower or 'aws' in content_lower:
            frameworks.append('AWS')
        
        # TrendMicro-specific
        if 'trendmicro.com' in url_lower:
            frameworks.append('TrendMicro')
        
        # Standard frameworks
        if any(keyword in content_lower for keyword in ['cis', 'center for internet security']):
            frameworks.append('CIS')
        
        if any(keyword in content_lower for keyword in ['nist', 'national institute']):
            frameworks.append('NIST')
        
        if any(keyword in content_lower for keyword in ['soc2', 'soc 2', 'service organization']):
            frameworks.append('SOC2')
        
        if any(keyword in content_lower for keyword in ['hipaa', 'health insurance']):
            frameworks.append('HIPAA')
        
        if any(keyword in content_lower for keyword in ['pci', 'payment card']):
            frameworks.append('PCI-DSS')
        
        return frameworks if frameworks else ['General']
    
    def extract_compliance_controls(self, content: str) -> Dict[str, List[str]]:
        """Extract compliance controls from content"""
        controls = {}
        content_lower = content.lower()
        
        # CIS controls
        cis_controls = re.findall(r'cis\s*\d+\.\d+', content_lower)
        if cis_controls:
            controls['CIS'] = list(set(cis_controls))
        
        # NIST controls
        nist_controls = re.findall(r'nist\s*[-\s]*(\d+[a-z]+-\d+)', content_lower)
        if nist_controls:
            controls['NIST'] = list(set(nist_controls))
        
        return controls
    
    def extract_focus_areas(self, content: str) -> List[str]:
        """Extract focus areas from content"""
        focus_areas = []
        content_lower = content.lower()
        
        if any(keyword in content_lower for keyword in ['least privilege', 'minimal permissions', 'principle of least privilege']):
            focus_areas.append('least_privilege_violations')
        
        if any(keyword in content_lower for keyword in ['privilege escalation', 'escalation', 'privilege creep']):
            focus_areas.append('privilege_escalation_risks')
        
        if any(keyword in content_lower for keyword in ['compliance', 'violation', 'non-compliant', 'audit']):
            focus_areas.append('compliance_violations')
        
        if any(keyword in content_lower for keyword in ['wildcard', '*', 'any', 'all resources']):
            focus_areas.append('resource_wildcards')
        
        return focus_areas if focus_areas else ['general']
    
    def extract_overview(self, content: str) -> str:
        """Extract overview from content"""
        # Look for overview section or use first paragraph
        overview_match = re.search(r'##?\s*overview\s*\n(.*?)(?=\n##|\Z)', content, re.IGNORECASE | re.DOTALL)
        if overview_match:
            return overview_match.group(1).strip()
        
        # Use first paragraph
        paragraphs = content.split('\n\n')
        for para in paragraphs:
            if len(para.strip()) > 50:
                return para.strip()
        
        return "Security best practices and compliance guidelines."
    
    def extract_key_principles(self, content: str) -> str:
        """Extract key principles from content"""
        principles_match = re.search(r'##?\s*(?:principles|best practices|guidelines)\s*\n(.*?)(?=\n##|\Z)', content, re.IGNORECASE | re.DOTALL)
        if principles_match:
            return principles_match.group(1).strip()
        
        return "Follow security best practices and compliance requirements."
    
    def extract_analysis(self, content: str) -> str:
        """Extract analysis from content"""
        analysis_match = re.search(r'##?\s*(?:analysis|assessment|evaluation)\s*\n(.*?)(?=\n##|\Z)', content, re.IGNORECASE | re.DOTALL)
        if analysis_match:
            return analysis_match.group(1).strip()
        
        return "Regular security assessments help identify potential risks and compliance gaps."
    
    def extract_certification(self, content: str) -> str:
        """Extract certification information from content"""
        cert_match = re.search(r'##?\s*(?:certification|certified|compliance)\s*\n(.*?)(?=\n##|\Z)', content, re.IGNORECASE | re.DOTALL)
        if cert_match:
            return cert_match.group(1).strip()
        
        return "Compliant with industry security standards and best practices."
    
    def format_compliance_controls(self, controls: Dict[str, List[str]]) -> str:
        """Format compliance controls for markdown"""
        if not controls:
            return "Standard security controls apply"
        
        formatted = []
        for framework, control_list in controls.items():
            formatted.append(f"- {framework}: {', '.join(control_list)}")
        
        return '\n'.join(formatted)
    
    def sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for filesystem"""
        # Remove invalid characters
        filename = re.sub(r'[<>:"/\\|?*]', '', filename)
        # Replace spaces with underscores
        filename = filename.replace(' ', '_')
        # Limit length
        filename = filename[:100]
        return filename


async def main():
    """Main function"""
    async with ComplianceScraper() as scraper:
        await scraper.scrape_all_sources()


if __name__ == "__main__":
    asyncio.run(main())
