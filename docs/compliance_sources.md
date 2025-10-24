# Compliance Framework Sources

Official sources used for compliance framework knowledge ingestion.

## Compliance Frameworks

### CIS (Center for Internet Security)

- **Source**: https://www.cisecurity.org/benchmark/amazon_web_services
- **Controls**: https://www.cisecurity.org/controls/
- **Framework**: CIS Controls v8
- **Coverage**: AWS-specific security benchmarks

### NIST (National Institute of Standards and Technology)

- **Source**: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- **Assessment**: https://csrc.nist.gov/publications/detail/sp/800-53a/rev-5/final
- **Framework**: NIST SP 800-53 Rev 5
- **Coverage**: Comprehensive security controls

### SOC2 (Service Organization Control 2)

- **Source**: https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html
- **Framework**: SOC2 Type II
- **Coverage**: Service organization controls

### HIPAA (Health Insurance Portability and Accountability Act)

- **Source**: https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html
- **Security**: https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html
- **Framework**: HIPAA Security Rule
- **Coverage**: Healthcare data protection

### PCI-DSS (Payment Card Industry Data Security Standard)

- **Source**: https://www.pcisecuritystandards.org/document_library/
- **Framework**: PCI-DSS v4.0
- **Coverage**: Payment card data security

## AWS Security Documentation

### IAM Resources

- **Best Practices**: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
- **Policy Examples**: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_examples.html
- **Access Policies**: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
- **Managed Policies**: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed.html
- **Policy Boundaries**: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html

### Additional Resources

- **OWASP Cloud Security**: https://owasp.org/www-project-cloud-security/
- **Cloud Security Alliance**: https://cloudsecurityalliance.org/

## Ingestion Process

### 1. Web Scraping

- **Tool**: BeautifulSoup4
- **Process**: Extract content from official documentation URLs
- **Cleaning**: Remove navigation, scripts, and formatting

### 2. Text Processing

- **Chunking**: RecursiveCharacterTextSplitter
- **Chunk Size**: 1000 characters
- **Overlap**: 200 characters
- **Separators**: Paragraphs, sentences, words

### 3. Vector Storage

- **Database**: ChromaDB
- **Embeddings**: SentenceTransformer (all-MiniLM-L6-v2)
- **Dimensions**: 384
- **Metadata**: Framework, version, domain, source

## Metadata Structure

```json
{
  "source": "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
  "source_type": "web",
  "chunk_index": 0,
  "chunk_length": 856,
  "compliance_framework": "AWS",
  "security_domain": "AWS_IAM",
  "framework_version": "2024"
}
```

## Framework-Specific Retrieval

### Query Examples

```python
# Retrieve CIS-specific context
cis_context = await rag_service.retrieve_context_with_filters(
    query="IAM policy with wildcard permissions",
    filters={"compliance_framework": "CIS"},
    k=5
)

# Retrieve NIST-specific context
nist_context = await rag_service.retrieve_context_with_filters(
    query="IAM policy with wildcard permissions",
    filters={"compliance_framework": "NIST"},
    k=5
)
```

## Usage

### Scraping Sources

```bash
python scripts/scrape_compliance_sources.py
```

### Populating Knowledge Base

```bash
python scripts/setup_knowledge_base.py
```

## Maintenance

### Regular Updates

- **Frequency**: TBD
- **Process**: CRON job for automated updates

### Adding New Frameworks

1. Add new URLs to `scripts/scrape_compliance_sources.py`
2. Update framework detection logic
3. Add framework-specific metadata extraction
