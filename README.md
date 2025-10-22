# IAM Scanning

References:

1. CloudSploit: [https://github.com/aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit)
2. Prowler: [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)
3. CIS Benchmarks: [https://www.cisecurity.org/cis-benchmarks](https://www.cisecurity.org/cis-benchmarks)
4. NIST CyberSec Frameworks: [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)
5. Pydantic: [https://docs.pydantic.dev/latest/](https://docs.pydantic.dev/latest/)
6. Instructor: [https://python.useinstructor.com/](https://python.useinstructor.com/)

---

## 1\. What We're Building

This engine will replace our current scanner with a system that:

1. **Analyzes Policy Intent:** Uses LLMs to understand the _purpose_ of a policy, not just its syntax.
2. **Provides Intelligent Remediation:** Generates actionable, step-by-step fix instructions augmented by a security knowledge base.
3. **Leverages a RAG Knowledge Base:** Integrates with security research from sources like TrendMicro to provide up-to-date, relevant context.
4. **Guarantees Structured Outputs:** Delivers reliable, schema-enforced JSON for robust API integrations.
5. **Offers a Multi-Cloud Ready Architecture:** Establishes a foundation to extend analysis to Azure and GCP, will initially be AWS only.
6. **Heuristics Fallback:** A built-in safety net to ensure service reliability and availability during AI service disruptions.

---

## 2\. Product Goals & Success Metrics

### 2.1 Product Goals

| Goal                    | Target                                                   | Timeline   |
| ----------------------- | -------------------------------------------------------- | ---------- |
| **Detection Accuracy**  | 95% true positive rate                                   | GA Release |
| **Issue Coverage**      | 3x more issue types detected                             | GA Release |
| **Remediation Quality** | 80% implementable without expert help                    | GA Release |
| **Scan Performance**    | No real limit, but should be reasonably fast (<=15 mins) | GA Release |
| **Multi Cloud Support** | AWS (GA), Azure (+2mo), GCP (+2mo)                       | Mixed      |

### 2.2 Technical Goals

| **Metric**             | **Target**       | **Measurement Method**         |
| ---------------------- | ---------------- | ------------------------------ |
| LLM Response Structure | 100% valid JSON  | Schema validation success rate |
| Cache Hit Rate         | 60%+             | Redis cache analytics          |
| API Cost per Scan      | < $0.10          | LLM token usage tracking       |
| Concurrent Scans       | 100 simultaneous | Load testing results           |

---

## 3\. User Needs & Pain Points

### 3.1 Primary User Problems to Solve

1. **Alert Fatigue from False Positives:** Users are overwhelmed by low-confidence alerts that require extensive manual triage, eroding trust in the system.
2. **Lack of Context:** Security findings fail to understand business intent (e.g., a backup role needing broad S3 access), leading to irrelevant alerts.
3. **Unactionable Remediation:** Users receive vague advice like "reduce scope" without specific, context-aware instructions or commands, delaying fixes.
4. **Inability to Detect New Threats:** The system cannot adapt to new AWS services or emerging attack vectors without manual code updates, creating windows of vulnerability.
5. **Blindness to Complex Risks:** The system misses sophisticated risks like cross-policy privilege escalation paths that require multi-step reasoning to uncover.

### 3.2 User Success Criteria

1. **Security Engineers:** "I trust StackGuard to prioritize what actually matters, and I spend 80% less time on false positive triage."
2. **DevOps Engineers:** "I can fix IAM issues myself using the clear, actionable commands provided, without needing to consult the security team."
3. **Not Necessarily Implementing This Now: Compliance Officers:** "I can export audit-ready reports that clearly map our IAM posture to compliance frameworks like CIS and NIST."

---

## 4\. Target Users & Use Cases

### 4.1 Primary Personas

1. **Security Engineer:** Responsible for cloud security posture and compliance. Needs high-confidence, prioritized findings with deep context to reduce manual triage and quickly address real risks.
2. **DevOps Engineer:** Manages infrastructure and CI/CD pipelines. Needs clear, actionable remediation with exact commands to fix security issues independently and without delaying deployments.
3. **Compliance Officer:** Ensures the organization meets regulatory standards. Needs audit-ready reports that map IAM configurations to specific compliance controls (CIS, NIST, SOC 2, etc.).

### 4.2 Key Use Cases

1. **Weekly Security Posture Review:** A security engineer runs a comprehensive scan across all cloud accounts to identify and prioritize the most critical IAM risks.
2. **Pre-Deployment Validation:** A DevOps engineer integrates the scanner into a CI/CD pipeline to validate IAM policies in Terraform or CloudFormation before they are deployed, preventing misconfigurations from reaching production.
3. **Compliance Audit Preparation:** A compliance officer generates an audit-ready report that maps all IAM findings to specific CIS and NIST controls, providing evidence of continuous monitoring to auditors.
4. **Incident Response:** A security engineer performs a targeted scan on a potentially compromised IAM role to quickly understand its permissions, identify escalation paths, and apply immediate, restrictive remediation.

---

## 5\. Competitive Landscape

| **Feature**               | **StackGuard (planned)**                                                                        | **Prowler (OSS)**                                                                             | **CloudSploit (Aqua)**                                                                      |
| ------------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Core Analysis Engine      | AI-powered (LLM with RAG) for contextual analysis. Heuristics as a fallback.                    | Heuristic-based. Relies on a large, community-maintained library of predefined checks.        | Heuristic-based. Uses a proprietary set of rules and pattern matching.                      |
| Context-Awareness         | High. Understands policy intent, role purpose, and can differentiate legitimate vs. risky uses. | Low. Lacks context. A wildcard is always a finding, regardless of the business case.          | Low. Cannot interpret business intent; focuses on strict pattern matching.                  |
| Remediation Guidance      | High. Generates specific, step-by-step plans with executable AWS CLI commands.                  | Medium. Provides links to AWS documentation and generic advice. No context-specific commands. | Medium. Offers generic remediation advice and links to documentation.                       |
| Knowledge Base (RAG)      | Yes. Integrates with TrendMicro and other security research for up-to-date threat intelligence. | No. Relies on manually updated check definitions within the open-source project.              | No. Relies on Aqua's internal research team to update its proprietary rule set.             |
| False Positive Likelihood | Low. AI analysis and confidence scoring significantly reduce noise.                             | High. Prone to false positives due to lack of context; requires extensive manual tuning.      | Medium-High. Less noisy than Prowler but still generates many false positives.              |
| Cross-Policy Analysis     | Planned (Agentic). Architecture supports evolving to detect complex privilege escalation paths. | No. Analyzes resources and policies in isolation.                                             | No. Limited to single-policy analysis.                                                      |
| Compliance Mapping        | High. AI maps findings to specific controls in frameworks like CIS, NIST, PCI-DSS, and SOC 2.   | High. Excellent coverage of CIS benchmarks and other frameworks, but mapping is static.       | Medium. Supports major compliance frameworks, but with less granularity than Prowler.       |
| User Experience           | High. Provides natural language explanations, clear remediation, and an integrated workflow.    | Low. CLI-based tool requiring technical expertise. Output is verbose and requires parsing.    | Medium. UI-based, but the experience is centered around a list of findings, not a workflow. |
| Extensibility             | High. Designed with a multi-cloud abstraction layer for future Azure and GCP support.           | Medium. Primarily AWS-focused, with some community support for GCP and Azure.                 | High. Supports AWS, Azure, GCP, Oracle Cloud, and Kubernetes.                               |

---

## 6\. Functional Requirements

### 6.1 Cloud Provider Integration

1. **FR-1: Multi-Cloud Adapter Framework (P0):** Implement an extensible adapter pattern that abstracts cloud-specific IAM implementations into a unified interface, supporting AWS at launch.
2. **FR-2: AWS IAM Data Collection (P0):** Fetch all IAM entities from a customer's AWS account, including users, roles, groups, and policies, along with their associated documents and metadata. The system must support role assumption for multi-account scanning and require only read-only permissions.
3. **FR-3: Azure & GCP Support (P1):** Develop and integrate adapters for Azure (Azure AD, RBAC) and Google Cloud Platform (IAM Policies, Service Accounts), allowing for consistent security analysis across major cloud providers.

### 6.2 AI Analysis Engine

1. **FR-4: LLM-Based Policy Analysis (P0):** Utilize a primary LLM (Claude 3.5 Sonnet) with a fallback (GPT-4o) to analyze IAM policies for overpermissive issues, security vulnerabilities, and compliance violations. We can also run a custom LLM with tuned parameters.
2. **FR-5: Structured Output Enforcement (P0):** Guarantee that all LLM responses conform to a predefined `pydantic` JSON schema, using libraries like `instructor` to ensure reliable, type-safe data for API consumption and frontend display.
3. **FR-6: Context-Aware Risk Scoring (P0):** Calculate a composite risk score (0-100) for each finding based on severity, exploitability, business impact, and resource context (e.g., production vs. dev tags).
4. **FR-7: Heuristics Fallback Engine (P0):** Maintain the existing heuristic engine as a high-availability fallback to ensure scans can be completed if the primary AI engine is unavailable.

### 6.3 RAG Knowledge Base

- **FR-8: Security Intelligence Knowledge Base (P0):** Establish a vector database (e.g., ChromaDB/Pinecone) containing embedded security research, best practices, and threat intelligence from trusted sources.
- **FR-9: TrendMicro Content Integration (P1):** Implement an automated web scraper and data pipeline to ingest, chunk, and embed content from TrendMicro's security blogs and research portals into the RAG knowledge base on a weekly basis.
- **FR-10: Knowledge Base Management (P2):** Develop an internal admin interface for managing the knowledge base, including manual document uploads, source quality scoring, and content lifecycle management.

### 6.4 Remediation Generation

- **FR-11: AI-Powered Remediation Plans (P0):** Generate detailed, step-by-step remediation plans for each finding, augmented with context from the RAG retriever. Plans must include executable AWS CLI commands, risk explanations, and links to relevant documentation.
- **FR-12: Remediation Validation (P1):** Integrate with the AWS IAM Policy Simulator to validate that proposed remediation steps will not inadvertently break application functionality by removing necessary permissions.
- **FR-13: Automated Remediation Workflow (P2):** Introduce a "one-click" remediation feature with an approval workflow, allowing users to apply suggested fixes directly from the UI after a security review.

### 6.5 Reporting & Visualization

- **FR-14: Comprehensive Scan Reports (P1):** Generate audit-ready scan reports in multiple formats, including interactive HTML, a structured JSON API response, and a professional PDF export suitable for auditors and executives.
- **FR-15: Security Posture Dashboard (P1):** Create a visual dashboard that displays the overall security grade, risk score trends over time, findings by severity, and top 5 riskiest resources.
- **FR-16: Historical Trend Analysis (P1):** Store scan results over time to provide historical trend analysis, showing whether security posture is improving or degrading and detecting regressions.

### 6.6 Integration & API

- **FR-17: REST API (P0):** Provide a well-documented REST API for all core functions, including initiating scans, retrieving findings, and downloading reports, secured by API keys.
- **FR-18: CI/CD Integration (P1):** Develop integrations for CI/CD platforms (GitHub Actions, GitLab CI) to enable pre-deployment IAM policy validation that can fail a build based on configurable risk thresholds.
- **FR-19: SIEM & ChatOps Integration (P2):** Support exporting findings to common SIEMs (Splunk, DataDog) and sending real-time alerts to collaboration tools (Slack, Microsoft Teams) via webhooks.

---

## 7\. Non-Functional Requirements

1. **Performance:** None as of now, will be updated later
2. **Scalability:** The system must support scanning environments with over 10,000 IAM entities and handle at least 50 concurrent scans.
3. **Reliability:** The service must maintain a 99.9% uptime SLA, with fallback to the heuristics engine.
4. **Security:** The platform must be SOC 2 Type II compliant. Customer cloud credentials must never be stored persistently and all data must be encrypted in transit and at rest. --> Vault
5. **Cost Efficiency:** The total cost of LLM API calls, infrastructure, and services must average less than $0.10 per 100 policies scanned, use intelligent caching and batch processing.
6. **Data Privacy:** Customer data must be logically isolated in a multi-tenant arch. Must be GDPR compliant.

---

## 8\. Technical Architecture

### 8.1 High-Level Architecture

The system will use a modular, event-driven architecture based on a task queue.

1. **API Layer (FastAPI):** Receives scan requests and serves results.
2. **Orchestration Layer (Celery & Redis):** Manages the scan job queue and schedules tasks for workers.
3. **Cloud Abstraction Layer:** A factory of provider-specific adapters (e.g., `AWSAdapter`) fetches data.
4. **AI Analysis Layer:** A core service that routes policies to the LLM, validates structured output, and consults the RAG retriever.
5. **Knowledge Layer (RAG):** A vector database (Pinecone/ChromaDB) and a retriever service provide context to the analysis layer.
6. **Data Layer:** PostgreSQL stores scan history and findings, Redis caches LLM responses, and S3 stores raw policy documents and generated reports.

### 8.2 Technology Stack

| **Component**      | **Technology**                                          | **Rationale**                                               |
| ------------------ | ------------------------------------------------------- | ----------------------------------------------------------- |
| Backend & API      | Python 3 + FastAPI                                      | High performance, strong ML ecosystem, async support.       |
| Primary LLM        | Claude 3.5 Sonnet, GPT 4o Fallback, Can also run custom | Excellent reasoning, strong JSON mode, cost-effective.      |
| Structured Outputs | pydantic + instructor                                   | Guarantees type-safe, validated JSON from the LLM.          |
| Vector Database    | ChromaDB (dev) / Pinecone (prod)                        | Easy local development and scalable production performance. |
| Task Queue         | Celery + Redis                                          | Mature, reliable, and scalable for async job processing.    |

---

## 9\. Risk Assessment & Mitigation

| **Risk**               | **Impact** | **Probability** | **Mitigation Strategy**                                                                                                                                                                                   |
| ---------------------- | ---------- | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| LLM Hallucinations     | High       | Medium          | Enforce strict JSON schema validation. Use RAG to ground responses in factual data. Include confidence scores with each finding. Benchmark against a dataset of known vulnerabilities.                    |
| High API Costs         | Medium     | Medium          | Implement aggressive caching of LLM responses in Redis. Use batch processing for API calls. Monitor cost per scan in real-time and alert on spikes. Select cost-effective models (e.g., Sonnet vs. Opus). |
| LLM Provider Outage    | High       | Low             | Implement an automated failover to a secondary LLM provider (GPT-4o). If both LLMs fail, fall back to the legacy heuristics engine to ensure service availability.                                        |
| Sensitive Data Leakage | Critical   | Low             | Perform prompt injection testing. Sanitize all user-provided data before including it in prompts. Never include PII in prompts.                                                                           |
| Slow Scan Performance  | Medium     | Medium          | Optimize batch sizes for parallel LLM calls. Profile and optimize the data fetching process. Use asynchronous processing for all I/O-bound operations.                                                    |

---

## 10\. API Spec and DB Models

### 10.1. Overall Flow

1. **Configuration (One-Time Setup)**:
   1. A user (Security / DevOps Engineer) accesses the UI / API.
   2. They add access credentials (Account ID + ARN of the IAM role that the application assumes). The IAM role has read-only permissions to all tenant wide IAM resources.
   3. The user saves this configuration via the `PUT /config` endpoint. The system stores these credentials securely (e.g., in HashiCorp Vault).
2. **Triggering a Scan (On-Demand)**:
   1. The user decides to run a scan.
   2. Fetch a list of available roles using `GET /iam/roles` to help select specific targets.
   3. The user initiates the scan via the `POST /scans/trigger` endpoint, optionally specifying target resource ARNs. If no targets are specified, a full scan of all IAM entities is performed.
   4. The API layer accepts the request, creates a new `Scan` record in the database with a `PENDING` status, and immediately returns a `scan_id` to the user.
   5. This action enqueues a new job in the Celery task queue.
3. **Executing the Scan (Asynchronous Backend Process)**:
   1. A Celery worker picks up the job.
   2. The worker updates the `Scan` status to `RUNNING`.
   3. **Data Fetching**: The worker uses the **Cloud Abstraction Layer** to assume the configured role in the customer's AWS account and fetches all relevant IAM policies, roles, users, and groups.
   4. **Analysis Loop**: For each policy document:
      1. The system generates a cache key (e.g., a hash of the policy content). It checks Redis for an existing result. If a cache hit occurs, the cached finding is used.
      2. If it's a cache miss, the policy is sent to the **Detection Layer**.
      3. The Detection Layer routes the policy to the primary LLM (Claude 3.5 Sonnet), with context from the **RAG Knowledge Base**.
      4. The `instructor` library enforces that the LLM's response strictly adheres to the `Finding` Pydantic schema.
   5. In case primary fails, use fallback LLM (GPT-4o). If both fail, fallback to the **Heuristics Engine**.
   6. **Storing Results**: Each validated finding is saved as a `Finding` record in the PostgreSQL database, linked to the current `scan_id`.
   7. Once all policies are analyzed, the worker updates the main `Scan` record's status to `COMPLETED` and sets a `completed_at` timestamp.
4. **Scheduling a Scan (Automated)**:
   1. Setup recurring scans with `POST /scans/schedule` endpoint.
   2. A scheduler process (like Celery Beat) triggers new scan jobs according to the defined schedules, kicking off the same process from point 3.
5. **Retrieving Insights**:
   1. After a scan is complete, the user calls the `GET /insights?scan_id={scan_id}` endpoint.
   2. The API queries the PostgreSQL database, aggregating the findings from the specified scan to generate a summary report, including risk scores, trends, and remediation advice.
   3. The results are returned to the user, who can view them in a dashboard or consume them via the API.

### 10.2. API Specification

(fields might change in the final implementation, pagination implementation will be mostly similar to the one we use on the current Go Backend server)

#### `PUT /api/v1/config/aws`

Updates the AWS connection configuration for the account.

- **Description**: Configures the cross-account role the scanner will assume. This is the primary setup step.
- **Request Body**: `application/json`

  ```json
  {
    "aws_account_id": "123456789012",
    "aws_role_to_assume_arn": "arn:aws:iam::123456789012:role/StackGuardScannerRole"
  }
  ```

- **Success Response**: `200 OK`

  ```json
  {
    "status": "success",
    "message": "AWS configuration updated successfully."
  }
  ```

- **Error Responses**:
  - `400 Bad Request`: Invalid ARN format or missing fields.
  - `401 Unauthorized`: Invalid or missing authentication token.

#### `GET /api/v1/aws/iam-roles`

Fetches a list of IAM roles from the configured AWS account.

- **Description**: Useful for UIs that allow users to select specific roles for a targeted scan.
- **Query Parameters**:
  - `limit` (integer, optional, default: 50): Number of roles to return.
  - `next_token` (string, optional): Pagination token from a previous request.
- **Success Response**: `200 OK`

  ```json
  {
    "roles": [
      {
        "role_name": "WebApp-EC2-InstanceRole",
        "arn": "arn:aws:iam::123456789012:role/WebApp-EC2-InstanceRole",
        "created_date": "2025-10-21T10:00:00Z"
      }
    ],
    "next_token": "some-pagination-token"
  }
  ```

- **Error Responses**:
  - `401 Unauthorized`: Invalid auth token.
  - `404 Not Found`: Configuration not found.
  - `502 Bad Gateway`: Could not assume role or communicate with AWS APIs.

#### `POST /api/v1/scans/trigger`

Triggers a new, on-demand IAM scan.

- **Description**: Initiates an asynchronous scan. Returns immediately with a scan ID for status tracking.
- **Request Body**: `application/json`

  ```json
  {
    "scan_name": "Weekly Production IAM Audit",
    "targets": [
      "arn:aws:iam::123456789012:role/AdminRole",
      "arn:aws:iam::123456789012:user/RootUser"
    ]
  }
  ```

- **Success Response**: `202 Accepted`

  ```json
  {
    "scan_id": "scn-a1b2c3d4e5f6",
    "status": "PENDING",
    "message": "Scan has been successfully queued."
  }
  ```

- **Error Responses**:
  - `400 Bad Request`: Invalid ARN format in `targets`.
  - `404 Not Found`: Configuration not found, unable to start scan.

#### `GET /api/v1/scans/{scan_id}/insights`

Retrieves the results and insights of a completed scan.

- **Description**: The primary endpoint for fetching scan results.
- **Path Parameters**:
  - `scan_id` (string, required): The ID of the scan.
- **Success Response**: `200 OK`

  ```json
  {
    "scan_id": "scn-a1b2c3d4e5f6",
    "scan_name": "Weekly Production IAM Audit",
    "status": "COMPLETED",
    "started_at": "2025-10-22T14:10:00Z",
    "completed_at": "2025-10-22T14:25:00Z",
    "summary": {
      "total_findings": 15,
      "critical": 2,
      "high": 5,
      "medium": 8,
      "low": 0,
      "overall_risk_score": 78
    },
    "findings": [
      {
        "finding_id": "fng-xyz789",
        "title": "Overly Permissive S3 Write Access",
        "severity": "HIGH",
        "risk_score": 85,
        "resource_arn": "arn:aws:iam::123456789012:role/BackupRole",
        "remediation_plan": "The policy should be scoped down to a specific S3 bucket prefix instead of using a wildcard.",
        "remediation_cli": "aws iam put-role-policy --role-name BackupRole --policy-name S3Access --policy-document file://new-policy.json"
      }
    ]
  }
  ```

- **Error Responses**:
  - `404 Not Found`: The specified `scan_id` does not exist.

#### `POST /api/v1/scans/schedules`

Creates a new schedule for recurring scans.

- **Description**: Sets up automated, recurring scans based on a cron expression.
- **Request Body**: `application/json`

  ```json
  {
    "schedule_name": "Daily Compliance Check",
    "cron_expression": "0 2 * * *",
    "is_enabled": true
  }
  ```

- **Success Response**: `201 Created`

  ```json
  {
    "schedule_id": "sch-g7h8i9j0k1",
    "schedule_name": "Daily Compliance Check",
    "cron_expression": "0 2 * * *",
    "is_enabled": true,
    "next_run_time": "2025-10-23T02:00:00Z"
  }
  ```

- **Error Responses**:
  - `400 Bad Request`: Invalid cron expression.

### 10.3. Database Model (PostgreSQL)

Here is a relational schema to store the necessary data.

```sql
-- Stores customer cloud connection details.
-- Credentials themselves are in Vault; this links a user/tenant to their cloud setup.
CREATE TABLE cloud_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL, -- Belongs to a specific tenant/user
    provider VARCHAR(10) NOT NULL DEFAULT 'AWS',
    aws_account_id VARCHAR(20) NOT NULL,
    aws_role_to_assume_arn VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Main table for tracking each scan job.
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID REFERENCES cloud_connections(id) ON DELETE CASCADE,
    scan_name VARCHAR(255),
    status VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Stores each individual finding discovered during a scan.
-- This table will be the largest.
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    resource_arn VARCHAR(255) NOT NULL, -- The ARN of the IAM role/user/policy with the issue.
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
    status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED')),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    confidence_score FLOAT NOT NULL CHECK (confidence_score >= 0.0 AND confidence_score <= 1.0),
    remediation_plan TEXT,
    remediation_cli TEXT,
    compliance_frameworks JSONB, -- e.g., {"CIS": ["1.2", "1.16"], "NIST": ["AC-6"]}
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- Stores scan schedules.
CREATE TABLE schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID REFERENCES cloud_connections(id) ON DELETE CASCADE,
    schedule_name VARCHAR(255) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 10.4. Core Data Models (`pydantic`)

```python
import pydantic
from typing import List, Optional, Dict
from enum import Enum
from datetime import datetime
# --- Enums for controlled vocabularies ---
class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
# --- API Input/Output Models ---
class AWSConfig(pydantic.BaseModel):
    aws_account_id: str
    aws_role_to_assume_arn: pydantic.constr(pattern=r'^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$')
class ScanTriggerRequest(pydantic.BaseModel):
    scan_name: Optional[str] = None
    targets: Optional[List[str]] = None # List of ARNs to scan
class ScanTriggerResponse(pydantic.BaseModel):
    scan_id: str
    status: ScanStatus
    message: str
class ScheduleCreateRequest(pydantic.BaseModel):
    schedule_name: str
    cron_expression: str
    is_enabled: bool = True
# --- Core LLM/Internal Models ---
# This is the primary model that `instructor` will use to enforce the LLM's output.
# It aligns directly with the `findings` database table.
class Finding(pydantic.BaseModel):
    resource_arn: str = pydantic.Field(description="The full ARN of the affected AWS resource.")
    title: str = pydantic.Field(description="A concise, descriptive title for the security finding.")
    description: str = pydantic.Field(description="A detailed explanation of the vulnerability, its potential impact, and the context.")
    severity: FindingSeverity = pydantic.Field(description="The severity level of the finding.")
    risk_score: int = pydantic.Field(ge=0, le=100, description="A calculated risk score from 0 to 100.")
    confidence_score: float = pydantic.Field(ge=0.0, le=1.0, description="The AI's confidence in this finding being a true positive.")
    remediation_plan: str = pydantic.Field(description="A step-by-step, human-readable guide to fix the issue.")
    remediation_cli: Optional[str] = pydantic.Field(None, description="An executable AWS CLI command to apply the fix.")
    compliance_frameworks: Optional[Dict[str, List[str]]] = pydantic.Field(None, description="Mapping to compliance controls like CIS or NIST.")
class ScanInsightsSummary(pydantic.BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    overall_risk_score: int
class ScanInsightsResponse(pydantic.BaseModel):
    scan_id: str
    scan_name: Optional[str]
    status: ScanStatus
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    summary: ScanInsightsSummary
    findings: List[Finding]
```
