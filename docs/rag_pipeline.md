# RAG Pipeline & AI Analysis System

Data flow from knowledge ingestion to AI-powered IAM policy analysis and remediation generation.

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Knowledge     │    │   Vector Store  │    │   AI Analysis   │
│   Ingestion     │ ─▶│   (ChromaDB)    │ ─▶│     Engine      │
│                 │    │                 │    │                 │
│ • Web Scraping  │    │ • Embeddings    │    │ • LLM Analysis  │
│ • PDF Parsing   │    │ • Similarity    │    │ • RAG Context   │
│ • API Sources   │    │ • Retrieval     │    │ • Structured    │
└─────────────────┘    └─────────────────┘    │   Output        │
                                              └─────────────────┘
                                                       │
                                                       ▼
                                              ┌─────────────────┐
                                              │   Findings &    │
                                              │   Remediation   │
                                              │                 │
                                              │ • Security      │
                                              │   Findings      │
                                              │ • Risk Scores   │
                                              │ • CLI Commands  │
                                              └─────────────────┘
```

## Analysis Pipeline

### 1. Knowledge Ingestion

- Scrape AWS docs, compliance frameworks (CIS, NIST, SOC2, HIPAA, PCI-DSS)
- Clean, chunk, and embed content into ChromaDB
- **Reference**: [Compliance Sources](compliance_sources.md)

### 2. RAG Context Retrieval

- Convert policy JSON to searchable text
- Generate vector embeddings for policy content
- Perform similarity search to find relevant knowledge chunks
- Assemble retrieved chunks into context for LLM

### 3. AI Analysis

- Use structured output enforcement with LLMs (Claude 3.5 Sonnet or GPT-4o)
- Build comprehensive prompts with policy documents, context, and retrieved knowledge
- **Reference**: [Prompt Manager Details](prompt_manager.md)

### 4. Finding Generation

- LLM returns structured findings with severity classification
- Include risk scores and remediation guidance
- Map findings to compliance framework control IDs
- Provide specific AWS CLI commands

### 5. Storage & Caching

- Cache results in Redis (30-day TTL)
- Store findings in PostgreSQL for persistence
- Include fallback mechanisms for LLM failures

## Key Features

- Framework-specific compliance context
- Continuous updates through knowledge ingestion
- IAM entities: roles, users, groups, policies
- Policy types: inline, managed, trust policies
- Specific AWS CLI commands for remediation
- Compliance framework-specific guidance
- Result caching to avoid duplicate LLM calls
- Efficient text chunking and processing
- Configurable model selection for cost/performance balance

## Configuration

Highly configurable through environment variables:

- Analysis focus areas
- Compliance frameworks
- Risk assessment strictness
- Model parameters

**Reference**: [System Overview](system_overview.md) for complete configuration options.
