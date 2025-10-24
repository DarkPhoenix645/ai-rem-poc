"""
Consolidated prompt templates for IAM policy analysis.
All LLM prompts are defined here for easy management and modification.
"""

from typing import Dict, Any


class AnalysisPrompts:
    """Centralized prompt templates for IAM security analysis"""
    
    @staticmethod
    def get_policy_analysis_prompt(
        policy_document: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str
    ) -> str:
        """
        Main prompt for IAM policy security analysis.
        
        Args:
            policy_document: The IAM policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            
        Returns:
            Formatted prompt string for LLM
        """
        
        policy_json = str(policy_document).replace("'", '"')
        
        prompt = f"""You are a senior AWS cloud security architect with expertise in IAM policy analysis. Your task is to analyze the provided IAM policy for security vulnerabilities, compliance violations, and potential risks.

CONTEXT INFORMATION:
- Resource: {context.get('resource_arn', 'Unknown')}
- Resource Type: {context.get('resource_type', 'Unknown')}
- Tags: {context.get('tags', {})}
- Business Context: {context.get('business_context', 'Not provided')}
- Usage Patterns: {context.get('usage_patterns', 'Not available')}

RELEVANT SECURITY KNOWLEDGE:
{rag_context}

IAM POLICY TO ANALYZE:
{policy_json}

ANALYSIS INSTRUCTIONS:
1. First, understand what this policy is intended to accomplish based on the context
2. Identify any permissions that violate the principle of least privilege
3. Look for potential privilege escalation paths
4. Consider compliance framework violations (CIS, NIST, etc.)
5. Account for the business context - some broad permissions may be legitimate
6. Provide specific, actionable remediation steps

CRITICAL REQUIREMENTS:
- Consider the resource tags and business context when determining if permissions are appropriate
- A production resource with broad permissions is more concerning than a development resource
- Backup roles may legitimately need broad S3 access
- Service-linked roles should be analyzed differently than user-assumed roles
- Provide specific AWS CLI commands for remediation when possible
- Include confidence scoring - be less confident when business context justifies the permissions

Focus on real security risks, not theoretical violations. Your analysis should help security teams prioritize actual threats."""

        return prompt
    
    @staticmethod
    def get_trust_policy_analysis_prompt(
        trust_policy: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str
    ) -> str:
        """
        Specialized prompt for analyzing IAM trust policies.
        
        Args:
            trust_policy: The IAM trust policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            
        Returns:
            Formatted prompt string for LLM
        """
        
        trust_json = str(trust_policy).replace("'", '"')
        
        prompt = f"""You are a senior AWS cloud security architect specializing in IAM trust policy analysis. Your task is to analyze the provided IAM trust policy for security vulnerabilities and potential attack vectors.

CONTEXT INFORMATION:
- Resource: {context.get('resource_arn', 'Unknown')}
- Resource Type: {context.get('resource_type', 'Unknown')}
- Tags: {context.get('tags', {})}
- Business Context: {context.get('business_context', 'Not provided')}

RELEVANT SECURITY KNOWLEDGE:
{rag_context}

TRUST POLICY TO ANALYZE:
{trust_json}

TRUST POLICY ANALYSIS INSTRUCTIONS:
1. Identify who can assume this role and under what conditions
2. Look for overly permissive trust relationships
3. Check for potential for privilege escalation through role assumption
4. Identify any cross-account trust relationships that may be risky
5. Look for missing conditions that could allow unauthorized access
6. Consider if the trust policy aligns with the business context

CRITICAL REQUIREMENTS:
- Focus on who can assume the role and what conditions are required
- Identify potential for unauthorized role assumption
- Look for missing IP restrictions, time-based conditions, or MFA requirements
- Consider cross-account trust relationships and their security implications
- Provide specific remediation steps for trust policy hardening

Focus on trust policy specific risks like unauthorized role assumption and privilege escalation through role chaining."""

        return prompt
    
    @staticmethod
    def get_resource_specific_analysis_prompt(
        policy_document: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str,
        resource_type: str
    ) -> str:
        """
        Specialized prompt for analyzing policies based on resource type.
        
        Args:
            policy_document: The IAM policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            resource_type: Type of resource (role, user, group, policy)
            
        Returns:
            Formatted prompt string for LLM
        """
        
        policy_json = str(policy_document).replace("'", '"')
        
        resource_specific_guidance = {
            "role": "Focus on role-specific risks like privilege escalation, cross-service access, and service-linked role permissions.",
            "user": "Focus on user-specific risks like direct user permissions, console access, and programmatic access keys.",
            "group": "Focus on group-based access patterns and potential for privilege escalation through group membership.",
            "policy": "Focus on policy-specific risks like overly broad permissions, missing conditions, and policy attachment risks."
        }
        
        guidance = resource_specific_guidance.get(resource_type, "Analyze for general IAM security risks.")
        
        prompt = f"""You are a senior AWS cloud security architect specializing in {resource_type.upper()} policy analysis. Your task is to analyze the provided IAM policy for security vulnerabilities specific to {resource_type} resources.

CONTEXT INFORMATION:
- Resource: {context.get('resource_arn', 'Unknown')}
- Resource Type: {resource_type.upper()}
- Tags: {context.get('tags', {})}
- Business Context: {context.get('business_context', 'Not provided')}
- Usage Patterns: {context.get('usage_patterns', 'Not available')}

RELEVANT SECURITY KNOWLEDGE:
{rag_context}

{resource_type.upper()} POLICY TO ANALYZE:
{policy_json}

{resource_type.upper()}-SPECIFIC ANALYSIS INSTRUCTIONS:
{guidance}

1. Understand the intended purpose of this {resource_type} based on context
2. Identify {resource_type}-specific security risks and vulnerabilities
3. Look for permissions that are inappropriate for the {resource_type} type
4. Consider the business context and legitimate use cases
5. Provide specific remediation steps for {resource_type} security hardening

CRITICAL REQUIREMENTS:
- Focus on {resource_type}-specific security patterns and risks
- Consider the business context and legitimate use cases for this {resource_type}
- Provide specific, actionable remediation steps
- Include confidence scoring based on {resource_type} context
- Generate specific AWS CLI commands for remediation when possible

Focus on real security risks specific to {resource_type} resources, not theoretical violations."""

        return prompt
    
    @staticmethod
    def get_compliance_analysis_prompt(
        policy_document: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str,
        compliance_framework: str = "CIS"
    ) -> str:
        """
        Specialized prompt for compliance-focused analysis.
        
        Args:
            policy_document: The IAM policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            compliance_framework: Compliance framework to focus on (CIS, NIST, etc.)
            
        Returns:
            Formatted prompt string for LLM
        """
        
        policy_json = str(policy_document).replace("'", '"')
        
        prompt = f"""You are a senior AWS cloud security architect and compliance expert specializing in {compliance_framework} framework analysis. Your task is to analyze the provided IAM policy for compliance violations and security best practices.

CONTEXT INFORMATION:
- Resource: {context.get('resource_arn', 'Unknown')}
- Resource Type: {context.get('resource_type', 'Unknown')}
- Tags: {context.get('tags', {})}
- Business Context: {context.get('business_context', 'Not provided')}
- Usage Patterns: {context.get('usage_patterns', 'Not available')}

RELEVANT SECURITY KNOWLEDGE:
{rag_context}

IAM POLICY TO ANALYZE:
{policy_json}

{compliance_framework} COMPLIANCE ANALYSIS INSTRUCTIONS:
1. Analyze the policy against {compliance_framework} best practices and requirements
2. Identify specific {compliance_framework} control violations
3. Look for permissions that violate {compliance_framework} guidelines
4. Consider the business context and legitimate use cases
5. Provide specific remediation steps to achieve {compliance_framework} compliance
6. Map findings to specific {compliance_framework} controls

CRITICAL REQUIREMENTS:
- Focus on {compliance_framework} compliance requirements and best practices
- Identify specific control violations with {compliance_framework} control IDs
- Consider business context while maintaining compliance standards
- Provide specific remediation steps for {compliance_framework} compliance
- Include confidence scoring based on {compliance_framework} requirements
- Generate specific AWS CLI commands for compliance remediation

Focus on {compliance_framework} compliance violations and provide actionable remediation steps."""

        return prompt
    
    @staticmethod
    def get_risk_assessment_prompt(
        policy_document: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str
    ) -> str:
        """
        Specialized prompt for risk assessment and scoring.
        
        Args:
            policy_document: The IAM policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            
        Returns:
            Formatted prompt string for LLM
        """
        
        policy_json = str(policy_document).replace("'", '"')
        
        prompt = f"""You are a senior AWS cloud security architect and risk assessment expert. Your task is to perform a comprehensive risk assessment of the provided IAM policy and provide detailed risk scoring.

CONTEXT INFORMATION:
- Resource: {context.get('resource_arn', 'Unknown')}
- Resource Type: {context.get('resource_type', 'Unknown')}
- Tags: {context.get('tags', {})}
- Business Context: {context.get('business_context', 'Not provided')}
- Usage Patterns: {context.get('usage_patterns', 'Not available')}

RELEVANT SECURITY KNOWLEDGE:
{rag_context}

IAM POLICY TO ANALYZE:
{policy_json}

RISK ASSESSMENT INSTRUCTIONS:
1. Identify all potential security risks and attack vectors
2. Assess the likelihood of exploitation for each risk
3. Evaluate the potential impact if exploited
4. Consider the business context and legitimate use cases
5. Calculate overall risk scores (0-100) for each finding
6. Provide detailed risk justification and mitigation strategies

CRITICAL REQUIREMENTS:
- Perform comprehensive risk analysis considering multiple attack vectors
- Provide detailed risk scoring with justification
- Consider business context while maintaining security standards
- Include likelihood and impact assessments
- Provide specific risk mitigation strategies
- Generate actionable remediation steps with priority levels

Focus on comprehensive risk assessment with detailed scoring and mitigation strategies."""

        return prompt


