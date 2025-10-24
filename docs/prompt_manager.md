# Prompt Management System

## Analysis Types

The system supports multiple analysis types, each designed for specific use cases and security requirements.

### General Analysis

**Purpose**: Comprehensive security analysis covering all aspects of IAM policy security.

**Use Case**: Standard policy review and security assessment.

**Features**:

- Least privilege violation detection
- Privilege escalation risk assessment
- Resource wildcard analysis
- Cross-service access evaluation
- Sensitive action identification

**Prompt Focus**:

- Broad security coverage
- Multiple risk categories
- Comprehensive remediation guidance
- Business context consideration

### Trust Policy Analysis

**Purpose**: Specialized analysis for IAM role trust relationships and assume role policies.

**Use Case**: Cross-account access risks and role assumption security.

**Features**:

- Trust relationship evaluation
- Assume role policy analysis
- Cross-account access assessment
- External entity trust validation
- Principal restriction analysis

**Prompt Focus**:

- Trust policy specific risks
- Cross-account security implications
- Principal validation requirements
- Assume role best practices

### Resource Specific Analysis

**Purpose**: Analysis tailored to specific IAM resource types (roles, users, groups).

**Use Case**: Role vs User vs Group specific security assessment.

**Features**:

- Resource type specific risk assessment
- Entity-specific permission analysis
- Group membership risk evaluation
- User direct permission review
- Role inheritance analysis

**Prompt Focus**:

- Resource type specific vulnerabilities
- Entity-specific security patterns
- Inheritance and delegation risks
- Resource-specific best practices

### Compliance Analysis

**Purpose**: Framework-specific compliance analysis against regulatory requirements.

**Use Case**: Regulatory requirements and compliance audits.

**Features**:

- CIS benchmark compliance
- NIST framework alignment
- SOC2 control compliance
- HIPAA requirement validation
- PCI-DSS standard adherence

**Prompt Focus**:

- Compliance framework specific requirements
- Control ID mapping
- Regulatory violation identification
- Compliance-specific remediation
- Framework-specific risk scoring

### Risk Assessment Analysis

**Purpose**: Detailed risk analysis with comprehensive risk scoring and prioritization.

**Use Case**: Risk scoring and mitigation planning.

**Features**:

- Quantitative risk scoring
- Risk level classification
- Mitigation priority ranking
- Risk trend analysis
- Business impact assessment

**Prompt Focus**:

- Detailed risk evaluation
- Risk scoring methodology
- Mitigation strategy development
- Risk prioritization
- Business impact analysis

## Usage Examples

### Basic Analysis

```python
from app.prompts.prompt_manager import prompt_manager

# Get standard analysis prompt
prompt = prompt_manager.get_analysis_prompt(policy_document, context, rag_context)
```

### Specialized Analysis

```python
# Trust policy analysis
prompt = prompt_manager.get_analysis_prompt(
    policy_document, context, rag_context,
    analysis_type="trust_policy"
)

# Compliance analysis
prompt = prompt_manager.get_analysis_prompt(
    policy_document, context, rag_context,
    analysis_type="compliance"
)
```

### Custom Analysis

```python
# Custom analysis with specific instructions
prompt = prompt_manager.get_custom_prompt(
    policy_document, context, rag_context,
    custom_instructions="Focus on S3 bucket permissions and cross-account access",
    focus_areas=["s3_permissions", "cross_account_access"],
    compliance_frameworks=["CIS", "NIST"]
)
```

## Configuration

### Analysis Focus Areas

```python
ANALYSIS_FOCUS_AREAS = [
    "least_privilege_violations",
    "privilege_escalation_risks",
    "compliance_violations",
    "resource_wildcards",
    "cross_service_access",
    "sensitive_actions"
]
```

### Compliance Frameworks

```python
COMPLIANCE_FRAMEWORKS = [
    "CIS",
    "NIST",
    "SOC2",
    "PCI-DSS",
    "HIPAA"
]
```

### Risk Assessment Criteria

```python
RISK_CRITERIA = {
    "critical": {"min_score": 80, "indicators": [...]},
    "high": {"min_score": 60, "indicators": [...]},
    "medium": {"min_score": 40, "indicators": [...]},
    "low": {"min_score": 20, "indicators": [...]}
}
```
