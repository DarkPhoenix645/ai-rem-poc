# Azure Policy Assignments for AI Foundry

## Overview
Knowledge Base
Microsoft Azure
AI Services
Azure Policy Assignments for AI Foundry
Risk Level:
Medium (should be achieved)
Ensure that Azure Policy assignments are implemented in order to enforce security and compliance standards for Azure AI Services (AI Foundry) resources across your organization.
Security
Cost
optimisation
Microsoft Azure Policy is a powerful service for enforcing organizational standards and assessing cloud compliance at scale. It allows you to define, assign, and manage policies that enforce rules and effects over your cloud resources. This helps ensure consistent security configurations, prevents misconfigurations, and maintains compliance with corporate standards and service level agreements (SLAs). A policy assignment is a policy definition or initiative that's applied to a specific scope, such as a subscription or a resource group. This is especially useful in enterprise environments where multiple teams deploy services and consistent security standards must be maintained across all deployments.
As an example, the Audit and Remediation sections of this guide will use a built-in policy definition named "Azure AI Services resources should restrict network access". By restricting network access using this policy definition, you can ensure that only allowed networks can access the service. This can be achieved by configuring network rules so that only applications from allowed networks can access the Azure AI Foundry resources across your organization. For more AI policy definitions, see
Azure Policy Regulatory Compliance controls for Azure AI services
.
Audit
To determine if the "Azure AI Services resources should restrict network access" policy is assigned to your Azure cloud subscriptions, perform the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to Azure Policy blade available at
https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade
.
03
In the left navigation panel, under
Authoring
, choose
Assignments
to access the list with all the initiative and policy assignments available within your Azure account.
04
On the
Assignments
page, perform the following actions:
For
Scope
, select the Azure subscription that you want to examine.
For
Definition type
, choose
Policy
to display only the policy assignments created for the selected subscription.
Click inside the
Search
box, enter
Azure AI Services resources should restrict network access
, and press Enter to search for the specific policy assignment. If no results are returned, instead the following message is displayed:
No policies found in the given scope
, the selected policy assignment is not implemented within the selected Azure subscription.
Repeat steps no. 1 – 3 for each subscription available in your Microsoft Azure cloud account.
Using Azure CLI
01
Run
account list
command (Windows/macOS/Linux) with custom output filters to list the IDs of the cloud subscriptions available in your Azure cloud account:
az account list
 --query '[*].id'
02
The command output should return the requested subscription identifiers (IDs):
[
 "abcdabcd-1234-abcd-1234-abcdabcdabcd",
 "abcd1234-abcd-1234-abcd-abcd1234abcd"
]
03
Run
policy assignment list
command (Windows/macOS/Linux) with the ID of the Azure subscription that you want to examine as the identifier parameter and custom output filters to list the name and the policy definition ID of each Azure policy assignment, available in the selected subscription:
az policy assignment list
 --scope /subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd
 --output table
 --query '[*].{"name": displayName,"policyDefinitionId": policyDefinitionId}'
04
The command output should return the requested policy information:
Name PolicyDefinitionId
--------------------------------------------------------------------------------------- -----------------------------------------------------------
Linux virtual machines should have Azure Monitor Agent installed /.../policyDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd
Private endpoint should be enabled for PostgreSQL servers /.../policyDefinitions/abcdabcd-1234-abcd-1234-abcd1234abcd
Azure Container Instance container group should use customer-managed key for encryption /.../policyDefinitions/abcd1234-abcd-1234-abcd-1234abcd1234
Check the
Name
column for each Azure policy assignment returned by the
policy assignment list
command output. If the following definition name is not listed in the
Name
column:
Azure AI Services resources should restrict network access
, the
Azure AI Services resources should restrict network access
policy assignment is not implemented within the selected Azure subscription.
05
Repeat steps no. 3 and 4 for each subscription available in your Microsoft Azure cloud account.
Remediation / Resolution
To ensure that only allowed networks can access the Azure AI Foundry resources deployed across your organization, implement the "Azure AI Services resources should restrict network access" policy assignment, by performing the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to Azure Policy blade available at
https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade
.
03
In the left navigation panel, under
Authoring
, choose
Assignments
to access the list with all the initiative and policy assignments available within your Azure account.
04
On the
Assignments
page, choose
Assign policy
, and perform the following actions to assign the required policy:
For
Basics
, provide the following information:
For
Scope
, choose the Azure subscription that you want to use as policy assignment scope. A scope determines what resources or grouping of resources the policy assignment gets enforced on.
(Optional) For
Exclusions
, choose the resource group or the cloud resources that can be excluded based on the selected scope. Exclusions start at one level lower than the level of the selected scope (in this case, the selected subscription). For example, at the subscription scope, you can assign a definition that prevents the creation of AI Foundry instances. You can exclude a resource group from the selected subscription that is intended for administration only.
For
Policy definition
, click on the Browse icon (i.e., ellipsis icon) to open the list of available policy definitions. On the
Available Definitions
panel, select the built-in definition named
Azure AI Services resources should restrict network access
and choose
Add
to add the specified policy definition. This policy ensures that only allowed networks can access the AI Foundry resources. This can be achieved by configuring network rules so that only applications from allowed networks can access the AI Foundry service.
Leave the assignment name unchanged in the
Assignment name
box.
Provide a short description for the new assignment in the
Description
text box.
Ensure that
Policy enforcement
is set to
Enabled
.
Choose
Next
to continue the setup process.
For
Parameters
, specify the required parameters for the selected policy assignment. Choose
Next
to continue the setup.
(Optional) For
Remediation
, perform the following actions to create the required system-sassigned managed identity. Policies with the
deployIfNotExists
and modify effect types need the ability to deploy resources and edit tags on existing resources respectively. To do this, create a new system assigned managed identity:
Select the
Create a Managed Identity
checkbox.
For
Type of Managed Identity
, choose
System assigned managed identity
.
Select the appropriate location from the
System assigned identity location
dropdown list.
Choose
Next
to continue the setup.
(Optional) For
Non-compliance message
, provide a message to help users understand why a resource is not compliant with the policy. Choose
Review + create
to continue the setup.
Choose
Create
to deploy the
Azure AI Services resources should restrict network access
policy assignment to your Azure subscription.
05
Repeat step no. 4 for other subscription available within your Microsoft Azure cloud account.
Using Azure CLI
01
Run
account list
command (Windows/macOS/Linux) with custom output filters to list the IDs of the cloud subscriptions available in your Azure cloud account:
az account list
 --query '[*].id'
02
The command output should return the requested subscription identifiers (IDs):
[
 "abcdabcd-1234-abcd-1234-abcdabcdabcd",
 "abcd1234-abcd-1234-abcd-abcd1234abcd"
]
03
Run
policy assignment create
command (Windows/macOS/Linux) with the ID of the
Azure AI Services resources should restrict network access
policy definition as value for the
--policy
parameter (i.e., 037eea7a-bd0a-46c5-9a66-03aea78705d3), to create a "Not Allowed Resource Types" policy assignment for the selected Azure cloud subscription (scope). In the following command example, the cloud resource type that your organization cannot deploy within the specified scope, defined as value of the
-p
parameter, is Azure Key Vault:
az policy assignment create
 --display-name "Azure AI Services resources should restrict network access"
 --policy "037eea7a-bd0a-46c5-9a66-03aea78705d3"
 --scope /subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd
04
The command output should return the new Azure policy assignment information:
{
 "description": null,
 "displayName": "Azure AI Services resources should restrict network access",
 "enforcementMode": "Default",
 "id": "/subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd/providers/Microsoft.Authorization/policyAssignments/abcdabcdabcdabcdabcd",
 "identity": null,
 "location": null,
 "metadata": {
 "createdBy": "abcd1234-abcd-1234-abcd-abcd1234abcd",
 "createdOn": "2025-09-08T18:36:21.7302231Z",
 "updatedBy": null,
 "updatedOn": null
 },
 "name": "abcdabcdabcdabcdabcd",
 "nonComplianceMessages": null,
 "notScopes": null,
 "parameters": null,
 "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/037eea7a-bd0a-46c5-9a66-03aea78705d3",
 "scope": "/subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd",
 "systemData": {
 "createdAt": "2025-09-08T18:36:21.703625+00:00",
 "createdBy": "ser@domain.com",
 "createdByType": "User",
 "lastModifiedAt": "2025-09-08T18:36:21.703625+00:00",
 "lastModifiedBy": "user@domain.com",
 "lastModifiedByType": "User"
 },
 "type": "Microsoft.Authorization/policyAssignments"
}
05
Repeat steps no. 3 and 4 for other cloud subscription available in your Microsoft Azure account.
References
Azure Official Documentation
Azure Policy Regulatory Compliance controls for Azure AI services
What is Azure Policy?
Azure Policy definition structure basics
Azure Policy built-in policy definitions
Quickstart: Create a policy assignment to identify non-compliant resources using Azure portal
Quickstart: Create a policy assignment to identify non-compliant resources using Azure CLI
Azure Command Line Interface (CLI) Documentation
az account list
az policy assignment list
az policy assignment create
Publication date Sep 10, 2025
Related AIServices rules
Regenerate API Access Keys for Azure AI Foundry Instances (Security)
OpenAI Service Instances with Admin Privileges (Security, reliability, cost-optimisation, operational-excellence, performance-efficiency)
OpenAI Encryption using Customer-Managed Keys (Security)
Use Managed Identities for OpenAI Service Instances (Security, operational-excellence)

## Key Principles
Follow security best practices and compliance requirements.

## Compliance Frameworks
TrendMicro, NIST

## Compliance Controls
Standard security controls apply

## Focus Areas
compliance_violations, resource_wildcards

## Analysis
Regular security assessments help identify potential risks and compliance gaps.

## Certification
Compliant with industry security standards and best practices.

## Source
https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/AIServices/azure-policy-assignments.html

## Full Content
Knowledge Base
Microsoft Azure
AI Services
Azure Policy Assignments for AI Foundry
Risk Level:
Medium (should be achieved)
Ensure that Azure Policy assignments are implemented in order to enforce security and compliance standards for Azure AI Services (AI Foundry) resources across your organization.
Security
Cost
optimisation
Microsoft Azure Policy is a powerful service for enforcing organizational standards and assessing cloud compliance at scale. It allows you to define, assign, and manage policies that enforce rules and effects over your cloud resources. This helps ensure consistent security configurations, prevents misconfigurations, and maintains compliance with corporate standards and service level agreements (SLAs). A policy assignment is a policy definition or initiative that's applied to a specific scope, such as a subscription or a resource group. This is especially useful in enterprise environments where multiple teams deploy services and consistent security standards must be maintained across all deployments.
As an example, the Audit and Remediation sections of this guide will use a built-in policy definition named "Azure AI Services resources should restrict network access". By restricting network access using this policy definition, you can ensure that only allowed networks can access the service. This can be achieved by configuring network rules so that only applications from allowed networks can access the Azure AI Foundry resources across your organization. For more AI policy definitions, see
Azure Policy Regulatory Compliance controls for Azure AI services
.
Audit
To determine if the "Azure AI Services resources should restrict network access" policy is assigned to your Azure cloud subscriptions, perform the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to Azure Policy blade available at
https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade
.
03
In the left navigation panel, under
Authoring
, choose
Assignments
to access the list with all the initiative and policy assignments available within your Azure account.
04
On the
Assignments
page, perform the following actions:
For
Scope
, select the Azure subscription that you want to examine.
For
Definition type
, choose
Policy
to display only the policy assignments created for the selected subscription.
Click inside the
Search
box, enter
Azure AI Services resources should restrict network access
, and press Enter to search for the specific policy assignment. If no results are returned, instead the following message is displayed:
No policies found in the given scope
, the selected policy assignment is not implemented within the selected Azure subscription.
Repeat steps no. 1 – 3 for each subscription available in your Microsoft Azure cloud account.
Using Azure CLI
01
Run
account list
command (Windows/macOS/Linux) with custom output filters to list the IDs of the cloud subscriptions available in your Azure cloud account:
az account list
 --query '[*].id'
02
The command output should return the requested subscription identifiers (IDs):
[
 "abcdabcd-1234-abcd-1234-abcdabcdabcd",
 "abcd1234-abcd-1234-abcd-abcd1234abcd"
]
03
Run
policy assignment list
command (Windows/macOS/Linux) with the ID of the Azure subscription that you want to examine as the identifier parameter and custom output filters to list the name and the policy definition ID of each Azure policy assignment, available in the selected subscription:
az policy assignment list
 --scope /subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd
 --output table
 --query '[*].{"name": displayName,"policyDefinitionId": policyDefinitionId}'
04
The command output should return the requested policy information:
Name PolicyDefinitionId
--------------------------------------------------------------------------------------- -----------------------------------------------------------
Linux virtual machines should have Azure Monitor Agent installed /.../policyDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd
Private endpoint should be enabled for PostgreSQL servers /.../policyDefinitions/abcdabcd-1234-abcd-1234-abcd1234abcd
Azure Container Instance container group should use customer-managed key for encryption /.../policyDefinitions/abcd1234-abcd-1234-abcd-1234abcd1234
Check the
Name
column for each Azure policy assignment returned by the
policy assignment list
command output. If the following definition name is not listed in the
Name
column:
Azure AI Services resources should restrict network access
, the
Azure AI Services resources should restrict network access
policy assignment is not implemented within the selected Azure subscription.
05
Repeat steps no. 3 and 4 for each subscription available in your Microsoft Azure cloud account.
Remediation / Resolution
To ensure that only allowed networks can access the Azure AI Foundry resources deployed across your organization, implement the "Azure AI Services resources should restrict network access" policy assignment, by performing the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to Azure Policy blade available at
https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyMenuBlade
.
03
In the left navigation panel, under
Authoring
, choose
Assignments
to access the list with all the initiative and policy assignments available within your Azure account.
04
On the
Assignments
page, choose
Assign policy
, and perform the following actions to assign the required policy:
For
Basics
, provide the following information:
For
Scope
, choose the Azure subscription that you want to use as policy assignment scope. A scope determines what resources or grouping of resources the policy assignment gets enforced on.
(Optional) For
Exclusions
, choose the resource group or the cloud resources that can be excluded based on the selected scope. Exclusions start at one level lower than the level of the selected scope (in this case, the selected subscription). For example, at the subscription scope, you can assign a definition that prevents the creation of AI Foundry instances. You can exclude a resource group from the selected subscription that is intended for administration only.
For
Policy definition
, click on the Browse icon (i.e., ellipsis icon) to open the list of available policy definitions. On the
Available Definitions
panel, select the built-in definition named
Azure AI Services resources should restrict network access
and choose
Add
to add the specified policy definition. This policy ensures that only allowed networks can access the AI Foundry resources. This can be achieved by configuring network rules so that only applications from allowed networks can access the AI Foundry service.
Leave the assignment name unchanged in the
Assignment name
box.
Provide a short description for the new assignment in the
Description
text box.
Ensure that
Policy enforcement
is set to
Enabled
.
Choose
Next
to continue the setup process.
For
Parameters
, specify the required parameters for the selected policy assignment. Choose
Next
to continue the setup.
(Optional) For
Remediation
, perform the following actions to create the required system-sassigned managed identity. Policies with the
deployIfNotExists
and modify effect types need the ability to deploy resources and edit tags on existing resources respectively. To do this, create a new system assigned managed identity:
Select the
Create a Managed Identity
checkbox.
For
Type of Managed Identity
, choose
System assigned managed identity
.
Select the appropriate location from the
System assigned identity location
dropdown list.
Choose
Next
to continue the setup.
(Optional) For
Non-compliance message
, provide a message to help users understand why a resource is not compliant with the policy. Choose
Review + create
to continue the setup.
Choose
Create
to deploy the
Azure AI Services resources should restrict network access
policy assignment to your Azure subscription.
05
Repeat step no. 4 for other subscription available within your Microsoft Azure cloud account.
Using Azure CLI
01
Run
account list
command (Windows/macOS/Linux) with custom output filters to list the IDs of the cloud subscriptions available in your Azure cloud account:
az account list
 --query '[*].id'
02
The command output should return the requested subscription identifiers (IDs):
[
 "abcdabcd-1234-abcd-1234-abcdabcdabcd",
 "abcd1234-abcd-1234-abcd-abcd1234abcd"
]
03
Run
policy assignment create
command (Windows/macOS/Linux) with the ID of the
Azure AI Services resources should restrict network access
policy definition as value for the
--policy
parameter (i.e., 037eea7a-bd0a-46c5-9a66-03aea78705d3), to create a "Not Allowed Resource Types" policy assignment for the selected Azure cloud subscription (scope). In the following command example, the cloud resource type that your organization cannot deploy within the specified scope, defined as value of the
-p
parameter, is Azure Key Vault:
az policy assignment create
 --display-name "Azure AI Services resources should restrict network access"
 --policy "037eea7a-bd0a-46c5-9a66-03aea78705d3"
 --scope /subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd
04
The command output should return the new Azure policy assignment information:
{
 "description": null,
 "displayName": "Azure AI Services resources should restrict network access",
 "enforcementMode": "Default",
 "id": "/subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd/providers/Microsoft.Authorization/policyAssignments/abcdabcdabcdabcdabcd",
 "identity": null,
 "location": null,
 "metadata": {
 "createdBy": "abcd1234-abcd-1234-abcd-abcd1234abcd",
 "createdOn": "2025-09-08T18:36:21.7302231Z",
 "updatedBy": null,
 "updatedOn": null
 },
 "name": "abcdabcdabcdabcdabcd",
 "nonComplianceMessages": null,
 "notScopes": null,
 "parameters": null,
 "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/037eea7a-bd0a-46c5-9a66-03aea78705d3",
 "scope": "/subscriptions/abcdabcd-1234-abcd-1234-abcdabcdabcd",
 "systemData": {
 "createdAt": "2025-09-08T18:36:21.703625+00:00",
 "createdBy": "ser@domain.com",
 "createdByType": "User",
 "lastModifiedAt": "2025-09-08T18:36:21.703625+00:00",
 "lastModifiedBy": "user@domain.com",
 "lastModifiedByType": "User"
 },
 "type": "Microsoft.Authorization/policyAssignments"
}
05
Repeat steps no. 3 and 4 for other cloud subscription available in your Microsoft Azure account.
References
Azure Official Documentation
Azure Policy Regulatory Compliance controls for Azure AI services
What is Azure Policy?
Azure Policy definition structure basics
Azure Policy built-in policy definitions
Quickstart: Create a policy assignment to identify non-compliant resources using Azure portal
Quickstart: Create a policy assignment to identify non-compliant resources using Azure CLI
Azure Command Line Interface (CLI) Documentation
az account list
az policy assignment list
az policy assignment create
Publication date Sep 10, 2025
Related AIServices rules
Regenerate API Access Keys for Azure AI Foundry Instances (Security)
OpenAI Service Instances with Admin Privileges (Security, reliability, cost-optimisation, operational-excellence, performance-efficiency)
OpenAI Encryption using Customer-Managed Keys (Security)
Use Managed Identities for OpenAI Service Instances (Security, operational-excellence)
