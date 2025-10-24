"""
Configuration settings for prompt templates.
Allows easy customization of prompt behavior without code changes.
"""

from typing import Dict, Any, List
from app.config import get_settings

settings = get_settings()


class PromptConfig:
    """Configuration for prompt templates and behavior"""
    
    def __init__(self):
        # Load configuration from environment variables
        self.analysis_focus_areas = self._parse_list(settings.analysis_focus_areas)
        self.compliance_frameworks = self._parse_list(settings.compliance_frameworks)
        self.risk_assessment_strictness = settings.risk_assessment_strictness
        
        # Load prompt settings from environment variables
        self.prompt_settings = {
            "include_business_context": settings.include_business_context,
            "include_compliance_mapping": settings.include_compliance_mapping,
            "include_risk_scoring": settings.include_risk_scoring,
            "include_remediation_commands": settings.include_remediation_commands,
            "include_confidence_scoring": settings.include_confidence_scoring,
            "max_context_length": settings.max_context_length,
        }
    
    def _parse_list(self, value: str) -> List[str]:
        """Parse comma-separated string into list"""
        return [item.strip() for item in value.split(',') if item.strip()]
    
    # Risk assessment criteria
    RISK_CRITERIA = {
        "critical": {
            "min_score": 80,
            "indicators": [
                "wildcard_permissions",
                "admin_access",
                "privilege_escalation",
                "cross_account_access"
            ]
        },
        "high": {
            "min_score": 60,
            "indicators": [
                "broad_permissions",
                "sensitive_actions",
                "missing_conditions"
            ]
        },
        "medium": {
            "min_score": 40,
            "indicators": [
                "resource_wildcards",
                "unnecessary_permissions"
            ]
        },
        "low": {
            "min_score": 20,
            "indicators": [
                "minor_violations",
                "best_practice_deviations"
            ]
        }
    }
    
    # Context-aware analysis settings
    CONTEXT_ANALYSIS = {
        "production": {
            "strictness": "high",
            "focus_areas": ["security", "compliance", "audit"]
        },
        "development": {
            "strictness": "medium", 
            "focus_areas": ["security", "functionality"]
        },
        "testing": {
            "strictness": "low",
            "focus_areas": ["functionality"]
        }
    }
    
    # Specialized analysis types
    ANALYSIS_TYPES = {
        "general": "comprehensive_security_analysis",
        "trust_policy": "trust_relationship_analysis", 
        "resource_specific": "resource_type_analysis",
        "compliance": "compliance_framework_analysis",
        "risk_assessment": "detailed_risk_analysis"
    }
    
    def get_analysis_focus(self, resource_type: str, business_context: str) -> list:
        """Get analysis focus areas based on resource type and business context"""
        base_focus = self.ANALYSIS_FOCUS_AREAS.copy()
        
        # Add resource-specific focus areas
        if resource_type == "role":
            base_focus.extend(["trust_policy_analysis", "assume_role_risks"])
        elif resource_type == "user":
            base_focus.extend(["direct_permissions", "console_access"])
        elif resource_type == "group":
            base_focus.extend(["group_membership_risks", "inherited_permissions"])
            
        # Add context-specific focus areas
        if "production" in business_context.lower():
            base_focus.extend(["compliance", "audit_requirements"])
        elif "development" in business_context.lower():
            base_focus.extend(["development_practices", "testing_requirements"])
            
        return list(set(base_focus))  # Remove duplicates
    
    def get_risk_thresholds(self, business_context: str) -> Dict[str, int]:
        """Get risk score thresholds based on business context and strictness setting"""
        base_thresholds = {level: config["min_score"] for level, config in self.RISK_CRITERIA.items()}
        
        # Adjust based on strictness setting
        strictness_adjustment = {
            "low": -15,    # More lenient
            "medium": 0,   # Default
            "high": 15     # More strict
        }
        
        adjustment = strictness_adjustment.get(self.risk_assessment_strictness, 0)
        adjusted_thresholds = {
            level: max(0, min(100, score + adjustment)) 
            for level, score in base_thresholds.items()
        }
        
        # Further adjust based on business context
        if "production" in business_context.lower():
            # Stricter thresholds for production
            return {level: min(100, score + 10) for level, score in adjusted_thresholds.items()}
        elif "development" in business_context.lower():
            # More lenient thresholds for development
            return {level: max(0, score - 10) for level, score in adjusted_thresholds.items()}
        
        return adjusted_thresholds
    
    def get_compliance_frameworks(self, business_context: str) -> list:
        """Get relevant compliance frameworks based on business context"""
        base_frameworks = self.COMPLIANCE_FRAMEWORKS.copy()
        
        # Add context-specific frameworks
        if "healthcare" in business_context.lower():
            base_frameworks.append("HIPAA")
        elif "financial" in business_context.lower():
            base_frameworks.extend(["PCI-DSS", "SOX"])
        elif "government" in business_context.lower():
            base_frameworks.extend(["FISMA", "FedRAMP"])
            
        return base_frameworks


