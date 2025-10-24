# Knowledge Base Table Summary

Overview of the `knowledge_base` table structure and usage.

## Table Structure

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "cloud_type": "aws",
  "service": "iam",
  "rule_name": "IAM Policy with Wildcard Permissions",
  "rule_id": "aws_iam_wildcard_policy",
  "content": "# Complete page content here...",
  "source_url": "https://...",
  "source_type": "compliance_framework",
  "source_category": "Identity and Access Management",
  "compliance_frameworks": ["CIS", "NIST"], // which compliance frameworks this text is associated to
  "compliance_controls": {
    // which exact rules this text is associated to
    "CIS": ["1.8"],
    "NIST": ["AC-3"]
  },
  "focus_areas": ["least_privilege_violations", "resource_wildcards"],
  "certification": "Ensures compliance with CIS Benchmark 1.8...",
  "analysis": "Wildcard permissions allow access to all resources...",
  "vector_id": "chromadb_vector_id_12345",
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z"
}
```

## Key Fields Mapping

| Requirement                             | Field Name             | Description                                              |
| --------------------------------------- | ---------------------- | -------------------------------------------------------- |
| cloudtype                               | `cloud_type`           | Cloud provider (aws, azure, gcp)                         |
| rule name (page title)                  | `rule_name`            | Page title or rule name from crawler                     |
| vector (text): completely page          | `content`              | Full page content for vector similarity search           |
| similarity on title with {rules, roles} | `rule_name` + ChromaDB | Used for similarity matching with IAM policy rules/roles |
| top 5 (config)                          | `top_k` parameter      | Configurable number of results to return (default: 5)    |
| analysis (1)                            | `analysis`             | Analysis content about the rule                          |
| certification: content!                 | `certification`        | Certification/compliance content                         |

## Provider-Agnostic Design

**AWS Example:**

```json
{
  "cloud_type": "aws",
  "service": "iam",
  "rule_name": "IAM Policy Wildcards"
}
```

**Azure Example:**

```json
{
  "cloud_type": "azure",
  "service": "rbac",
  "rule_name": "Role Assignment Permissions"
}
```

**GCP Example:**

```json
{
  "cloud_type": "gcp",
  "service": "iam",
  "rule_name": "IAM Binding Permissions"
}
```

## Usage Flow

### 1. Crawler → Database

```
Crawler saves: data/AWS/IAM/Wildcard Permissions.md
  ↓
Migration script processes files
  ↓
PostgreSQL stores metadata + content
  ↓
ChromaDB stores vector embeddings
  ↓
Linked via vector_id
```

### 2. RAG Retrieval

```python
# Search knowledge base for IAM rules
search_request = KnowledgeBaseSearchRequest(
    cloud_type="aws",
    service="iam",
    focus_areas=["least_privilege_violations"],
    top_k=5  # configurable
)

# Get top k matching rules
kb_entries = await database_service.search_knowledge_base(search_request)
```

### 3. LLM Prompt Construction

```plaintext
Prompt to LLM:

"Here is the IAM policy JSON:
{rules, roles}

Here are the top 5 most relevant compliance rules based on similarity:
1. {rule_name}: {content}
2. {rule_name}: {content}
...

Analysis for this policy: {analysis}
Certification: {certification}

Focus areas: {focus_areas}

Generate findings for this policy."
```

### 4. LLM Response

Returns a Markdown table for frontend rendering:

```markdown
| Resource ARN                          | Finding              | Severity | Risk Score | Remediation             |
| ------------------------------------- | -------------------- | -------- | ---------- | ----------------------- |
| arn:aws:iam::123456789012:role/MyRole | Wildcard permissions | HIGH     | 85         | Remove '\*' from Action |
```

## Migration Scripts

### Populate Knowledge Base

```bash
python scripts/populate_knowledge_base.py data/AWS aws
```

**Process:**

1. Reads markdown files from crawler output directory
2. Extracts metadata (rule name, service, compliance info)
3. Stores full content in PostgreSQL `knowledge_base` table
4. Creates vector embeddings in ChromaDB
5. Links both via `vector_id`

### Cleanup References

```bash
python scripts/cleanup_trendmicro_references.py
```

**Process:**

1. Finds all entries with "Trend Micro" references
2. Removes identifying information
3. Replaces "Cloud One Conformity" with "Cloud Security"

## Configuration

Default focus areas (configurable in `.env`):

- `least_privilege_violations`
- `privilege_escalation_risks`
- `compliance_violations`
- `resource_wildcards`

Default retrieval k (configurable in `.env`):

- `retrieval_k=5` (default top 5 results)
