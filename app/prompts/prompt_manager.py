"""
Prompt management utilities for dynamic prompt generation and customization.
"""

import logging
from typing import Dict, Any, List, Optional
from app.prompts.analysis_prompts import AnalysisPrompts
from app.prompts.prompt_config import PromptConfig

logger = logging.getLogger(__name__)


class PromptManager:
    """Centralized prompt management and customization"""
    
    def __init__(self):
        self.analysis_prompts = AnalysisPrompts()
        self.config = PromptConfig()
        from app.services.rag_service import RAGService
        self.rag_service = RAGService()
    
    async def get_analysis_prompt(
        self,
        policy_document: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str,
        analysis_type: str = "general",
        custom_focus_areas: Optional[List[str]] = None
    ) -> str:
        """
        Get a customized analysis prompt based on the analysis type and context.
        
        Args:
            policy_document: The IAM policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            analysis_type: Type of analysis (general, trust_policy, resource_specific, compliance, risk_assessment)
            custom_focus_areas: Custom focus areas to include
            
        Returns:
            Formatted prompt string for LLM
        """
        
        # Get focus areas based on context
        resource_type = context.get('resource_type', 'unknown')
        business_context = context.get('business_context', '')
        
        if custom_focus_areas:
            focus_areas = custom_focus_areas
        else:
            focus_areas = self.config.get_analysis_focus(resource_type, business_context)
        
        # Route to appropriate prompt method based on analysis type
        if analysis_type == "trust_policy":
            return self.analysis_prompts.get_trust_policy_analysis_prompt(
                policy_document, context, rag_context
            )
        elif analysis_type == "resource_specific":
            return self.analysis_prompts.get_resource_specific_analysis_prompt(
                policy_document, context, rag_context, resource_type
            )
        elif analysis_type == "compliance":
            # Get relevant compliance frameworks
            frameworks = self.config.get_compliance_frameworks(business_context)
            compliance_framework = frameworks[0] if frameworks else "CIS"
            
            # Get compliance-specific context
            compliance_context = await self._get_compliance_context(policy_document, frameworks)
            
            return self.analysis_prompts.get_compliance_analysis_prompt(
                policy_document, context, compliance_context, compliance_framework
            )
        elif analysis_type == "risk_assessment":
            return self.analysis_prompts.get_risk_assessment_prompt(
                policy_document, context, rag_context
            )
        else:  # general analysis
            return self.analysis_prompts.get_policy_analysis_prompt(
                policy_document, context, rag_context
            )
    
    async def _get_compliance_context(self, policy_document: dict, frameworks: list) -> str:
        """Get compliance-specific context for the given frameworks"""
        try:
            # Convert policy to searchable text
            policy_text = self._policy_to_text(policy_document)
            
            # Retrieve compliance-specific context
            compliance_chunks = await self.rag_service.retrieve_context_with_filters(
                query=policy_text,
                filters={"compliance_framework": {"$in": frameworks}},
                k=5
            )
            
            # Format compliance context
            if compliance_chunks:
                formatted_context = "\n\n".join([
                    f"Compliance Knowledge #{i+1}:\n{chunk}"
                    for i, chunk in enumerate(compliance_chunks)
                ])
                return formatted_context
            else:
                return "No specific compliance context found for the requested frameworks."
                
        except Exception as e:
            logger.error(f"Failed to get compliance context: {e}")
            return "Error retrieving compliance context."
    
    def _policy_to_text(self, policy_document: dict) -> str:
        """Convert policy document to searchable text"""
        text_parts = []
        
        if 'Statement' in policy_document:
            for stmt in policy_document['Statement']:
                # Extract actions
                if 'Action' in stmt:
                    actions = stmt['Action'] if isinstance(stmt['Action'], list) else [stmt['Action']]
                    text_parts.extend(actions)
                
                # Extract resources
                if 'Resource' in stmt:
                    resources = stmt['Resource'] if isinstance(stmt['Resource'], list) else [stmt['Resource']]
                    text_parts.extend(resources)
        
        return " ".join(text_parts)
    
    def get_custom_prompt(
        self,
        policy_document: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str,
        custom_instructions: str,
        focus_areas: List[str],
        compliance_frameworks: List[str]
    ) -> str:
        """
        Generate a completely custom prompt with user-defined instructions.
        
        Args:
            policy_document: The IAM policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            custom_instructions: User-defined analysis instructions
            focus_areas: Specific areas to focus on
            compliance_frameworks: Compliance frameworks to check
            
        Returns:
            Custom formatted prompt string for LLM
        """
        
        policy_json = str(policy_document).replace("'", '"')
        
        prompt = f"""You are a senior AWS cloud security architect with expertise in IAM policy analysis. Your task is to analyze the provided IAM policy according to the specific instructions provided.

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

CUSTOM ANALYSIS INSTRUCTIONS:
{custom_instructions}

FOCUS AREAS:
{', '.join(focus_areas)}

COMPLIANCE FRAMEWORKS:
{', '.join(compliance_frameworks)}

CRITICAL REQUIREMENTS:
- Follow the custom instructions precisely
- Focus on the specified areas: {', '.join(focus_areas)}
- Consider compliance with: {', '.join(compliance_frameworks)}
- Provide specific, actionable remediation steps
- Include confidence scoring and risk assessment
- Generate specific AWS CLI commands for remediation when possible

Focus on the custom requirements while maintaining security best practices."""

        return prompt
    
    def get_prompt_variants(
        self,
        policy_document: Dict[str, Any],
        context: Dict[str, Any],
        rag_context: str
    ) -> Dict[str, str]:
        """
        Get multiple prompt variants for different analysis approaches.
        
        Args:
            policy_document: The IAM policy JSON
            context: Policy context information
            rag_context: Retrieved security knowledge from RAG
            
        Returns:
            Dictionary of prompt variants
        """
        
        variants = {}
        
        # General analysis
        variants['general'] = self.get_analysis_prompt(
            policy_document, context, rag_context, "general"
        )
        
        # Trust policy analysis
        variants['trust_policy'] = self.get_analysis_prompt(
            policy_document, context, rag_context, "trust_policy"
        )
        
        # Resource-specific analysis
        variants['resource_specific'] = self.get_analysis_prompt(
            policy_document, context, rag_context, "resource_specific"
        )
        
        # Compliance analysis
        variants['compliance'] = self.get_analysis_prompt(
            policy_document, context, rag_context, "compliance"
        )
        
        # Risk assessment
        variants['risk_assessment'] = self.get_analysis_prompt(
            policy_document, context, rag_context, "risk_assessment"
        )
        
        return variants
    
    def validate_prompt_config(self) -> Dict[str, Any]:
        """
        Validate the current prompt configuration and return status.
        
        Returns:
            Validation results and recommendations
        """
        
        validation_results = {
            "valid": True,
            "warnings": [],
            "recommendations": []
        }
        
        # Check prompt settings
        settings = self.config.PROMPT_SETTINGS
        
        if settings.get("max_context_length", 0) < 1000:
            validation_results["warnings"].append(
                "Max context length may be too low for comprehensive analysis"
            )
        
        if not settings.get("include_business_context", False):
            validation_results["recommendations"].append(
                "Consider enabling business context inclusion for better analysis"
            )
        
        if not settings.get("include_compliance_mapping", False):
            validation_results["recommendations"].append(
                "Consider enabling compliance mapping for regulatory requirements"
            )
        
        return validation_results


# Global prompt manager instance
prompt_manager = PromptManager()
