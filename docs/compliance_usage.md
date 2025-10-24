# Compliance Fields Usage in Finding Generation

## Overview

The `compliance_frameworks` and `compliance_controls` fields in the `knowledge_base` table are used to:

1. **Filter knowledge base entries** during RAG retrieval
2. **Inform the LLM** about which compliance frameworks to check
3. **Map findings** to specific compliance control IDs
4. **Include in final findings** for frontend display

## Field Definitions

### In Knowledge Base Table

```python
# compliance_frameworks: JSONB array
["CIS", "NIST", "SOC2"]

# compliance_controls: JSONB object
{
  "CIS": ["1.1", "1.2", "1.8"],
  "NIST": ["AC-3", "AC-6"],
  "SOC2": ["CC6.1"]
}
```

### In Finding Output

```python
# compliance_frameworks in Finding model
{
  "CIS": ["1.8"],
  "NIST": ["AC-3"]
}
```

## How They're Used During Finding Generation

### Step 1: RAG Retrieval with Compliance Filtering

When searching the knowledge base for relevant rules:

```python
# Example from prompt_manager.py line 89-92
compliance_chunks = await self.rag_service.retrieve_context_with_filters(
    query=policy_text,
    filters={"compliance_framework": {"$in": frameworks}},  # Uses compliance_frameworks field
    k=5
)
```

**Purpose**: Retrieves only rules relevant to the requested compliance frameworks.

### Step 2: Prompt Construction

The compliance information is included in the LLM prompt:

```python
# From analysis_prompts.py lines 187-241
prompt = f"""...
{compliance_framework} COMPLIANCE ANALYSIS INSTRUCTIONS:
1. Analyze the policy against {compliance_framework} best practices
2. Identify specific {compliance_framework} control violations
3. Map findings to specific {compliance_framework} controls
...
"""
```

**Purpose**: Instructs the LLM which frameworks to check and what controls to reference.

### Step 3: LLM Analysis

The LLM receives:

- Policy JSON
- Knowledge base content (filtered by `compliance_frameworks`)
- Compliance control IDs from `compliance_controls`
- Instructions to map findings to controls

**LLM Response**: Generates findings with `compliance_frameworks` field populated:

```json
{
  "resource_arn": "arn:aws:iam::123456789012:role/MyRole",
  "title": "IAM Policy with Wildcard Permissions",
  "description": "The policy contains wildcard (*) permissions...",
  "severity": "HIGH",
  "risk_score": 85,
  "confidence_score": 0.95,
  "remediation_plan": "Remove wildcard permissions...",
  "remediation_cli": "aws iam put-role-policy...",
  "compliance_frameworks": {
    "CIS": ["1.8"], // Control ID from knowledge_base.compliance_controls
    "NIST": ["AC-3"] // Control ID from knowledge_base.compliance_controls
  }
}
```

### Step 4: Frontend Display

The compliance mapping is rendered on the frontend:

```markdown
| Finding              | Severity | CIS Controls | NIST Controls | Remediation             |
| -------------------- | -------- | ------------ | ------------- | ----------------------- |
| Wildcard permissions | HIGH     | 1.8          | AC-3          | Remove '\*' from Action |
```

## Example Flow

### Knowledge Base Entry

```json
{
  "cloud_type": "aws",
  "service": "iam",
  "rule_name": "IAM Policy with Wildcard Permissions",
  "compliance_frameworks": ["CIS", "NIST"], // ← Used for filtering
  "compliance_controls": {
    // ← Used for mapping
    "CIS": ["1.8"],
    "NIST": ["AC-3"]
  },
  "content": "Wildcard permissions violate least privilege..."
}
```

### RAG Retrieval

```python
# User requests CIS compliance analysis
frameworks = ["CIS"]

# Search knowledge base filtered by CIS
kb_entries = await database_service.search_knowledge_base(
    KnowledgeBaseSearchRequest(
        cloud_type="aws",
        compliance_frameworks=["CIS"],  # Filters by compliance_frameworks field
        top_k=5
    )
)
```

### LLM Prompt

```plaintext
You are analyzing for CIS compliance.

RELEVANT SECURITY KNOWLEDGE:
Knowledge #1: IAM Policy with Wildcard Permissions
- CIS Control: 1.8 (Ensure IAM policies are assigned only to groups or roles)
- Description: Wildcard permissions violate least privilege...

IAM POLICY TO ANALYZE:
{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}

CIS COMPLIANCE ANALYSIS INSTRUCTIONS:
1. Identify specific CIS control violations
2. Map findings to CIS control IDs (e.g., 1.8)
...
```

### LLM Response (Finding)

```json
{
  "title": "Wildcard Permissions Violate CIS 1.8",
  "description": "Policy contains wildcard (*) permissions...",
  "severity": "HIGH",
  "compliance_frameworks": {
    "CIS": ["1.8"] // ← From knowledge_base.compliance_controls
  }
}
```

## Why This Matters

### 1. **Precise Compliance Mapping**

- Knowledge base stores exact control IDs
- LLM receives specific controls to reference
- Findings include accurate compliance mappings

### 2. **Filtered Context**

- Only relevant compliance rules are retrieved
- Reduces token usage and improves focus
- Ensures context relevance

### 3. **Audit Trail**

- Frontend can show which controls are violated
- Compliance teams can track framework coverage
- Evidence for audits

### 4. **Multi-Framework Support**

- Single rule can address multiple frameworks
- Knowledge base entry: `["CIS", "NIST", "SOC2"]`
- Finding output: `{"CIS": ["1.8"], "NIST": ["AC-3"]}`

## Database Query Pattern

```python
# Search for rules that address specific frameworks
async def search_knowledge_base_for_compliance(frameworks: List[str]):
    stmt = select(KnowledgeBase).where(
        KnowledgeBase.compliance_frameworks.contains(frameworks)
    )
    # Returns rules that have ANY of the requested frameworks
```

## Summary

| Field                             | Used In          | Purpose                                    |
| --------------------------------- | ---------------- | ------------------------------------------ |
| `compliance_frameworks`           | RAG filtering    | Filter knowledge base entries by framework |
| `compliance_controls`             | LLM context      | Provide specific control IDs to reference  |
| `compliance_frameworks` (Finding) | Frontend display | Show which controls are violated           |
| Both                              | Audit/reporting  | Map violations to compliance requirements  |

These fields ensure that:

1. The right compliance knowledge is retrieved
2. The LLM knows which controls to check
3. Findings include precise compliance mappings
4. Frontend can display compliance status accurately
