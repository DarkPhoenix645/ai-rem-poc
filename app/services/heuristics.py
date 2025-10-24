import json
import logging
from typing import Dict, List, Optional

from app.models.core import Finding, FindingSeverity, AnalysisRequest

logger = logging.getLogger(__name__)


class HeuristicsEngine:
    """
    Rule-based fallback engine for when LLMs are unavailable.
    Provides basic security analysis using hardcoded rules.
    """
    
    def __init__(self):
        self.rules = [
            self._check_wildcard_permissions,
            self._check_privilege_escalation,
            self._check_admin_access,
            self._check_sensitive_actions,
            self._check_resource_wildcards,
        ]
    
    async def analyze(self, request: AnalysisRequest) -> Finding:
        """
        Analyze policy using heuristic rules.
        
        Args:
            request: Analysis request
            
        Returns:
            Finding with basic security assessment
        """
        policy = request.policy_document
        context = request.context
        
        # Run all rules and collect findings
        findings = []
        for rule in self.rules:
            try:
                result = rule(policy, context)
                if result:
                    findings.append(result)
            except Exception as e:
                logger.error(f"Heuristic rule failed: {e}")
        
        # Return the highest severity finding, or create a default
        if findings:
            # Sort by severity and risk score
            findings.sort(key=lambda x: (x.severity.value, x.risk_score), reverse=True)
            return findings[0]
        
        # No issues found
        return Finding(
            resource_arn=context.resource_arn,
            title="No Issues Detected",
            description="Heuristic analysis did not identify any obvious security issues with this policy.",
            severity=FindingSeverity.INFORMATIONAL,
            risk_score=10,
            confidence_score=0.6,
            remediation_plan="No remediation required based on heuristic analysis.",
            compliance_frameworks={}
        )
    
    def _check_wildcard_permissions(self, policy: dict, context) -> Optional[Finding]:
        """Check for overly broad wildcard permissions"""
        if 'Statement' not in policy:
            return None
        
        for stmt in policy['Statement']:
            if stmt.get('Effect') != 'Allow':
                continue
            
            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            
            # Ensure lists
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for dangerous wildcards
            if '*' in actions and '*' in resources:
                return Finding(
                    resource_arn=context.resource_arn,
                    title="Wildcard Permissions Detected",
                    description=f"Policy contains wildcard permissions for both actions (*) and resources (*). This grants unrestricted access to all AWS services and resources.",
                    severity=FindingSeverity.CRITICAL,
                    risk_score=95,
                    confidence_score=0.9,
                    remediation_plan="Replace wildcard permissions with specific actions and resources needed for the role's function. Use the principle of least privilege.",
                    remediation_cli=f"aws iam put-role-policy --role-name {context.resource_arn.split('/')[-1]} --policy-name RestrictivePolicy --policy-document file://new-policy.json",
                    compliance_frameworks={"CIS": ["1.16"], "NIST": ["AC-6"]}
                )
        
        return None
    
    def _check_privilege_escalation(self, policy: dict, context) -> Optional[Finding]:
        """Check for privilege escalation risks"""
        dangerous_actions = [
            'iam:CreateRole',
            'iam:AttachRolePolicy',
            'iam:PutRolePolicy',
            'iam:PassRole',
            'sts:AssumeRole'
        ]
        
        if 'Statement' not in policy:
            return None
        
        for stmt in policy['Statement']:
            if stmt.get('Effect') != 'Allow':
                continue
            
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            # Check for privilege escalation actions
            escalation_actions = []
            for action in actions:
                if action in dangerous_actions or action == '*':
                    escalation_actions.append(action)
            
            if escalation_actions:
                return Finding(
                    resource_arn=context.resource_arn,
                    title="Privilege Escalation Risk",
                    description=f"Policy contains actions that could be used for privilege escalation: {', '.join(escalation_actions)}",
                    severity=FindingSeverity.HIGH,
                    risk_score=80,
                    confidence_score=0.8,
                    remediation_plan="Review the necessity of these privileged actions. Consider using more restrictive conditions or separate roles for administrative tasks.",
                    compliance_frameworks={"CIS": ["1.2"], "NIST": ["AC-2"]}
                )
        
        return None
    
    def _check_admin_access(self, policy: dict, context) -> Optional[Finding]:
        """Check for administrative access patterns"""
        admin_policies = [
            'arn:aws:iam::aws:policy/AdministratorAccess',
            'arn:aws:iam::aws:policy/PowerUserAccess'
        ]
        
        # Check managed policy attachments (this would need context from AWS API)
        # For now, check for admin-like statements
        if 'Statement' not in policy:
            return None
        
        for stmt in policy['Statement']:
            if stmt.get('Effect') != 'Allow':
                continue
            
            actions = stmt.get('Action', [])
            resources = stmt.get('Resource', [])
            
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check for broad administrative access
            if ('*' in actions and '*' in resources) or \
               (len(actions) > 20 and '*' in resources):
                
                # Consider context - admin roles might be legitimate
                risk_score = 75
                if 'admin' in context.resource_arn.lower() or \
                   context.tags.get('Role', '').lower() == 'admin':
                    risk_score = 45  # Lower risk if it's intended to be admin
                
                return Finding(
                    resource_arn=context.resource_arn,
                    title="Administrative Access Detected",
                    description="Policy provides broad administrative access across multiple AWS services.",
                    severity=FindingSeverity.MEDIUM if risk_score < 60 else FindingSeverity.HIGH,
                    risk_score=risk_score,
                    confidence_score=0.7,
                    remediation_plan="If administrative access is not required, scope down permissions to only necessary services and actions.",
                    compliance_frameworks={"CIS": ["1.1"], "NIST": ["AC-6"]}
                )
        
        return None
    
    def _check_sensitive_actions(self, policy: dict, context) -> Optional[Finding]:
        """Check for access to sensitive AWS actions"""
        sensitive_actions = [
            'iam:GetUser',
            'iam:ListUsers',
            'iam:GetAccountSummary',
            'organizations:DescribeOrganization',
            'sts:GetCallerIdentity'
        ]
        
        if 'Statement' not in policy:
            return None
        
        found_sensitive = []
        for stmt in policy['Statement']:
            if stmt.get('Effect') != 'Allow':
                continue
            
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            for action in actions:
                if action in sensitive_actions:
                    found_sensitive.append(action)
        
        if found_sensitive:
            return Finding(
                resource_arn=context.resource_arn,
                title="Sensitive Action Access",
                description=f"Policy allows access to sensitive actions: {', '.join(found_sensitive)}",
                severity=FindingSeverity.MEDIUM,
                risk_score=60,
                confidence_score=0.6,
                remediation_plan="Review if access to these sensitive actions is necessary for the role's function.",
                compliance_frameworks={"NIST": ["AC-6"]}
            )
        
        return None
    
    def _check_resource_wildcards(self, policy: dict, context) -> Optional[Finding]:
        """Check for resource-level wildcards"""
        if 'Statement' not in policy:
            return None
        
        wildcard_resources = []
        for stmt in policy['Statement']:
            if stmt.get('Effect') != 'Allow':
                continue
            
            resources = stmt.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            for resource in resources:
                if resource == '*':
                    wildcard_resources.append('All resources (*)')
                elif resource.endswith('/*'):
                    wildcard_resources.append(resource)
        
        if wildcard_resources:
            return Finding(
                resource_arn=context.resource_arn,
                title="Resource Wildcard Usage",
                description=f"Policy uses wildcard resource access: {', '.join(set(wildcard_resources))}",
                severity=FindingSeverity.MEDIUM,
                risk_score=55,
                confidence_score=0.7,
                remediation_plan="Replace wildcard resource access with specific resource ARNs where possible.",
                compliance_frameworks={"CIS": ["1.16"]}
            )
        
        return None


# Singleton instance
heuristics_engine = HeuristicsEngine()
