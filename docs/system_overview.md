# AI-Powered IAM Security Scanner

High-level overview of the complete AI-powered IAM security scanning system.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AI-Powered IAM Security Scanner              │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌──────────┐  ┌────────────┐ │
│  │   FastAPI   │  │   Celery    │  │  Redis   │  │  Postgres  │ │
│  │   App       │  │   Workers   │  │  Cache   │  │   DB       │ │
│  └─────────────┘  └─────────────┘  └──────────┘  └────────────┘ │
│         │                │                │            │        │
│         └────────────────┼────────────────┼────────────┘        │
│                          │                │                     │
│  ┌───────────────────────┼────────────────┼──────────────────┐  │
│  │              ChromaDB Vector Database                     │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │
│  │  │  Security   │  │ Compliance  │  │   Best      │        │  │
│  │  │ Knowledge   │  │ Frameworks  │  │ Practices   │        │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                      │
│  ┌───────────────────────┼───────────────────────────────────┐  │
│  │              AI Analysis Engine                           │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │
│  │  │  Claude 3.5 │  │   GPT-4o    │  │ Heuristics  │        │  │
│  │  │   Sonnet    │  │             │  │   Engine    │        │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                      │
│  ┌───────────────────────┼───────────────────────────────────┐  │
│  │              AWS Integration                              │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │  │
│  │  │   IAM API   │  │   STS API   │  │   S3 API    │        │  │
│  │  │   Access    │  │   Assume    │  │   Policies  │        │  │
│  │  └─────────────┘  └─────────────┘  └─────────────┘        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Knowledge Ingestion

- Web scraping: AWS docs, compliance frameworks
- Text processing: chunking, cleaning, embedding
- Vector storage: ChromaDB with metadata

### 2. IAM Data Collection

- AWS API calls: IAM roles, users, groups, policies
- Policy extraction: inline and managed policies
- Context gathering: tags, business context

### 3. RAG Context Retrieval

- Query generation: convert policy to searchable text
- Vector search: find relevant security knowledge
- Context assembly: combine retrieved information

### 4. AI Analysis

- Prompt construction: policy + context + knowledge
- LLM processing: Claude 3.5 Sonnet or GPT-4o
- Structured output: Pydantic model enforcement
- Fallback: heuristics if LLM fails

### 5. Finding Generation

- Security findings: vulnerabilities, risks, violations
- Risk scoring: 0-100 scale with severity mapping
- Compliance mapping: CIS, NIST, SOC2 control IDs
- Remediation: specific AWS CLI commands

### 6. Storage & Caching

- Database: PostgreSQL for findings and scans
- Cache: Redis for analysis results
- Vector DB: ChromaDB for knowledge base

## Key Features

### AI-Powered Analysis

- Large Language Models with structured output enforcement
- Context-aware analysis considering business context
- Fallback mechanisms when LLMs fail

### RAG-Enhanced Knowledge

- Security knowledge base: AWS docs, best practices
- Compliance frameworks: CIS, NIST, SOC2, HIPAA, PCI-DSS
- Dynamic retrieval: policy-specific knowledge
- Continuous updates: regular knowledge ingestion

### Comprehensive Scanning

- IAM entities: roles, users, groups, policies
- Policy types: inline, managed, trust policies
- Context analysis: tags, business context, usage patterns
- Batch processing: concurrent analysis with limits

### Intelligent Remediation

- Specific commands: AWS CLI remediation steps
- Policy generation: corrected policy documents
- Risk prioritization: severity-based findings
- Compliance guidance: framework-specific remediation

## Analysis Types

| Type                  | Description                     | Use Case                    |
| --------------------- | ------------------------------- | --------------------------- |
| **General**           | Comprehensive security analysis | Standard policy review      |
| **Trust Policy**      | Role assumption analysis        | Cross-account access risks  |
| **Resource Specific** | Entity type analysis            | Role vs User vs Group       |
| **Compliance**        | Framework compliance            | Regulatory requirements     |
| **Risk Assessment**   | Detailed risk analysis          | Risk scoring and mitigation |

## Configuration

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=sk-ant-api03-...
OPENAI_API_KEY=sk-...

# Optional (with defaults)
ANALYSIS_FOCUS_AREAS=least_privilege_violations,privilege_escalation_risks
COMPLIANCE_FRAMEWORKS=CIS,NIST,SOC2
RISK_ASSESSMENT_STRICTNESS=medium
```

### Model Configuration

```bash
# Anthropic
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
ANTHROPIC_MAX_TOKENS=2000
ANTHROPIC_TEMPERATURE=0.1

# OpenAI
OPENAI_MODEL=gpt-4o
OPENAI_MAX_TOKENS=2000
OPENAI_TEMPERATURE=0.1
```

## Quick Start

```bash
# 1. Setup environment
cp env.sample .env
# Edit .env with your API keys

# 2. Start services
./setup.sh

# 3. Configure AWS access
curl -X PUT http://localhost:8000/api/v1/config/aws \
  -H 'Content-Type: application/json' \
  -d '{"aws_account_id": "123456789012", "aws_role_to_assume_arn": "arn:aws:iam::123456789012:role/ScannerRole"}'

# 4. Trigger scan
curl -X POST http://localhost:8000/api/v1/scans/trigger \
  -H 'Content-Type: application/json' \
  -d '{"scan_name": "Security Scan"}'
```

## Performance

### Scalability

- Horizontal scaling: multiple Celery workers
- Caching: Redis for analysis results
- Concurrent processing: configurable limits
- Batch operations: efficient database operations

### Cost Optimization

- Result caching: avoid duplicate LLM calls
- Model selection: cost vs performance balance
- Chunk optimization: efficient text processing
- Fallback mechanisms: reduce LLM usage

## Use Cases

### Security Teams

- Policy review: automated security analysis
- Compliance audits: framework-specific checks
- Risk assessment: prioritized findings
- Remediation: specific fix guidance

### DevOps Teams

- Policy validation: pre-deployment checks
- Access reviews: regular permission audits
- Compliance: regulatory requirement checks
- Automation: CI/CD integration

### Compliance Teams

- Audit preparation: comprehensive reports
- Framework mapping: control ID references
- Risk scoring: quantified compliance status
- Remediation tracking: progress monitoring

This AI-powered system combines large language models, retrieval augmented generation, and AWS security expertise to provide intelligent, context-aware IAM policy analysis with specific remediation guidance.
