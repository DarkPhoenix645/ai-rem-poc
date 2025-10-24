import os
from functools import lru_cache
from typing import Optional

from pydantic import Field
try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings

class Settings(BaseSettings):
    # Database Configuration
    database_url: str = Field(default="postgresql://postgres:postgres@localhost:5432/postgres")
    
    # Redis Configuration
    redis_url: str = Field(default="redis://localhost:6379/0")
    
    # ChromaDB Configuration
    chromadb_url: str = Field(default="http://localhost:8001")
    chromadb_collection: str = "security_knowledge_base"
    
    # LLM Configuration
    anthropic_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    primary_llm: str = "anthropic"  # anthropic or openai
    
    # Anthropic Models
    anthropic_model: str = "claude-3-5-sonnet-20241022"
    anthropic_max_tokens: int = 2000
    anthropic_temperature: float = 0.1
    
    # OpenAI Models
    openai_model: str = "gpt-4o"
    openai_max_tokens: int = 2000
    openai_temperature: float = 0.1
    
    # Analysis Configuration
    max_concurrent_analyses: int = 5
    cache_ttl_seconds: int = 86400 * 30  # 30 days
    max_retries: int = 3
    
    # RAG Configuration
    embedding_model: str = "all-MiniLM-L6-v2"
    chunk_size: int = 1000
    chunk_overlap: int = 200
    retrieval_k: int = 5  # Number of chunks to retrieve
    
    # Security Configuration
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    
    # Celery Configuration
    celery_broker_url: str = Field(default="redis://localhost:6379/0")
    celery_result_backend: str = Field(default="redis://localhost:6379/0")
    celery_task_serializer: str = "json"
    celery_result_serializer: str = "json"
    celery_accept_content: str = "json"
    celery_timezone: str = "UTC"
    celery_enable_utc: bool = True
    
    # AI Analysis Configuration
    analysis_focus_areas: str = "least_privilege_violations,privilege_escalation_risks,compliance_violations,resource_wildcards"
    compliance_frameworks: str = "CIS,NIST,SOC2"
    risk_assessment_strictness: str = "medium"
    
    # Prompt Configuration
    default_analysis_type: str = "general"
    include_business_context: bool = True
    include_compliance_mapping: bool = True
    include_risk_scoring: bool = True
    include_remediation_commands: bool = True
    include_confidence_scoring: bool = True
    max_context_length: int = 4000
    
    # AWS Configuration
    default_aws_account_id: str = "123456789012"
    default_aws_role_arn: str = "arn:aws:iam::123456789012:role/StackGuardScannerRole"
    aws_external_id: Optional[str] = None
    
    # Application Configuration
    api_v1_str: str = "/api/v1"
    project_name: str = "IAM Scanner"
    enable_health_checks: bool = True
    health_check_interval: int = 30
    
    # Docker Configuration
    compose_project_name: str = "iam-scanner"
    docker_network: str = "iam-scanner-network"
    
    model_config = {"env_file": ".env", "extra": "ignore"}

@lru_cache()
def get_settings():
    return Settings()
