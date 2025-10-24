# Check for AI Foundry Instances with Admin Permissions

## Overview
Knowledge Base
Microsoft Azure
AI Services
Check for AI Foundry Instances with Admin Permissions
Risk Level:
High (not acceptable risk)
Ensure that your Microsoft Azure AI Foundry instances are not configured with privileged administrative permissions in order to promote the Principle of Least Privilege (POLP) and provide your AI instances the minimal amount of access required to perform their tasks.
Security
Reliability
Cost
optimisation
Performance
efficiency
Operational
excellence
In Azure cloud, user-assigned managed identities encompass a broader range of roles including privileged administrator roles. Privileged administrator roles grant extensive access privileges, such as overseeing Azure resources and delegating roles to others. To minimize security risks, the user-assigned identities associated with your Azure AI Foundry instances should not have these admin privileges. Granting admin rights can lead to unintended access, data breaches, and misuse. By limiting permissions to the minimum necessary for the instance's operation, you can adhere to the Principle of Least Privilege (POLP). This approach enhances overall security by reducing the attack surface and potential damage from unauthorized access.
Audit
To determine if your Azure AI Foundry instances are configured with admin privileges, perform the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to
All resources
blade available at
https://portal.azure.com/#browse/all
to access all your Microsoft Azure cloud resources.
03
Choose the Azure subscription that you want to access from the
Subscription equalls all
filter box and choose
Apply
.
04
From the
Type equals all
filter box, select
Type
for
Filter
,
Equals
for
Operator
, and
Azure AI Foundry
for
Value
, then choose
Apply
to list the Azure AI Services (AI Foundry) instances available in the selected subscription.
05
Click on the name (link) of the AI Foundry instance that you want to examine.
06
In the resource navigation panel, under
Resource Management
, choose
Identity
.
07
Select the
User assigned
tab and click on the name (link) of the user-assigned managed identity associated with your instance. If there are no user-assigned managed identities listed on this page, the Audit process ends here. To add user-assigned identities to your AI Foundry instance, follow the instructions outlined on
this
page.
08
In the resource navigation panel, select
Azure role assignments
to view the role assignments for the selected identity.
09
Check the
Role
column to determine if the selected identity has privileged administrator roles such as
Owner
,
Contributor
,
User Access Administrator
, and
Role Based Access Control Administrator
. You can also click on the role name to view the role permissions. If one or more privileged administrator roles are assigned to the user-assigned managed identity associated with your instance, the selected Azure AI Foundry instance is configured with admin privileges.
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
account set
command (Windows/macOS/Linux) with the ID of the Azure cloud subscription that you want to examine as the identifier parameter to set the selected subscription to be the current active subscription (the command does not produce an output):
az account set
 --subscription abcdabcd-1234-abcd-1234-abcdabcdabcd
04
Run
cognitiveservices account list
command (Windows/macOS/Linux) with custom output filters to list the name and the associated resource group for each Azure AI Services (AI Foundry) instance available within the current subscription:
az cognitiveservices account list
 --output table
 --query '[?(kind==`AIServices`)].{name:name, resourceGroup:resourceGroup}'
05
The command output should return the requested AI Foundry instance identifiers:
Name ResourceGroup
------------------------------- ------------------------------
cc-project5-ai-service-instance cloud-shell-storage-westeurope
cc-project5-ai-foundry-instance cloud-shell-storage-westeurope
06
Run
cognitiveservices account identity show
command (Windows/macOS/Linux) with the name of the Azure AI Foundry instance that you want to examine as the identifier parameter and custom output filters to describe the user-assigned managed identities associated with the selected instance:
az cognitiveservices account identity show
 --name cc-project5-ai-service-instance
 --resource-group cloud-shell-storage-westeurope
 --query 'userAssignedIdentities'
07
The command output should return the information available for the associated identities (including the identity full ID and the ID of the associated principal). If the
cognitiveservices account identity show
command does not return an output, there are no user-assigned managed identities configured for your instance and the Audit process ends here. To add user-assigned identities to your AI Foundry instance, follow the instructions outlined on
this
page:
{
 "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tm-project5-ai-user-identity": {
 "clientId": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234"
}
08
Run
role assignment list
command (Windows/macOS/Linux) to describe the role assignments for the principal associated with your user-assigned managed identity. Set
--assignee
parameter value to the
"principalId"
attribute value returned at the previous step:
az role assignment list
 --assignee abcd1234-abcd-1234-abcd-1234abcd1234
 --all
09
The command output should return the role assignments for the selected principal:
[
 {
 "roleDefinitionName": "Owner",
 "roleDefinitionId": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/providers/Microsoft.Authorization/roleDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd",
 "condition": null,
 "conditionVersion": null,
 "createdBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "createdOn": "2025-09-05T08:11:52.463577+00:00",
 "delegatedManagedIdentityResourceId": null,
 "description": null,
 "name": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234",
 "principalName": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalType": "ServicePrincipal",
 "resourceGroup": "cloud-shell-storage-westeurope",
 "scope": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.CognitiveServices/accounts/cc-project5-ai-service-instance",
 "type": "Microsoft.Authorization/roleAssignments",
 "updatedBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "updatedOn": "2025-09-05T08:11:52.463577+00:00"
 },
 {
 "roleDefinitionName": "User Access Administrator",
 "roleDefinitionId": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/providers/Microsoft.Authorization/roleDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd",
 "condition": null,
 "conditionVersion": null,
 "createdBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "createdOn": "2025-09-06T08:00:52.463577+00:00",
 "delegatedManagedIdentityResourceId": null,
 "description": null,
 "name": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234",
 "principalName": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalType": "ServicePrincipal",
 "resourceGroup": "cloud-shell-storage-westeurope",
 "scope": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.CognitiveServices/accounts/cc-project5-ai-service-instance",
 "type": "Microsoft.Authorization/roleAssignments",
 "updatedBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "updatedOn": "2025-09-06T08:00:52.463577+00:00"
 }
]
Check the
"roleDefinitionName"
attribute value for each role assignment returned by the
role assignment list
command output to determine if the associated identity has privileged administrator roles such as
"Owner"
,
"Contributor"
,
"User Access Administrator"
, and
"Role Based Access Control Administrator"
. If one or more privileged administrator roles are assigned to the user-assigned managed identity associated with your instance, the selected Azure AI Foundry instance is configured with admin privileges.
Remediation / Resolution
To ensure that your Microsoft Azure AI Foundry instances are not configured with administrative privileges, perform the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to
All resources
blade available at
https://portal.azure.com/#browse/all
to access all your Microsoft Azure cloud resources.
03
Choose the Azure subscription that you want to access from the
Subscription equalls all
filter box and choose
Apply
.
04
From the
Type equals all
filter box, select
Type
for
Filter
,
Equals
for
Operator
, and
Azure AI Foundry
for
Value
, then choose
Apply
to list the Azure AI Services (AI Foundry) instances available in the selected subscription.
05
Click on the name (link) of the AI Foundry instance that you want to configure.
06
In the resource navigation panel, under
Resource Management
, choose
Identity
.
07
Select the
User assigned
tab and click on the name (link) of the user-assigned managed identity associated with your instance.
08
In the resource navigation panel, select
Azure role assignments
to view the role assignments for the selected identity.
09
Click on the name of the privileged administrator role that you want to remove from your user-assigned managed identity, select the
Assignments
tab, and choose
Remove
to delete the role assignment for the selected managed identity. In the
Remove role assignments
box, choose
Yes
for confirmation.
10
(Optional) To add a new role assigment that follows the Principle of Least Privilege (POLP), choose
Access control (IAM)
from the identity navigation panel, choose
Add
, select
Add role assigment
, and perform the following actions:
For
Role
, select the
Job function roles
tab, and choose the appropriate, non-privileged role that you want to attach. Choose
Next
to continue the assignment process.
For
Members
, select
Managed identity
next to
Assign access to
, choose
Select members
next to
Members
, and select the user-assigned managed identity associated with your AI Foundry instance. Choose
Next
to continue.
For
Review + assign
, review the role assignment information, then choose
Review + assign
to complete the assigment process.
Using Azure CLI
01
Run
role assignment delete
command (OSX/Linux/UNIX) to remove the privileged administrator role from your user-assigned managed identity. As an example, the following command removes the "Owner" role assignment (if the request is successful, the command does not produce an output):
az role assignment delete
 --assignee abcd1234-abcd-1234-abcd-1234abcd1234
 --role "Owner"
02
(Optional) Run
role assignment create
command (OSX/Linux/UNIX) to add a new role assigment that follows the Principle of Least Privilege to your user-assigned managed identity. Use the
--role
parameter to specify the name of the non-privileged role that you want to assign:
az role assignment create
 --assignee abcd1234-abcd-1234-abcd-1234abcd1234
 --role Reader
 --scope "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tm-project5-ai-user-identity"
03
Once the assignment process is completed, the command output should return the information available for the new role assignment:
{
 "roleDefinitionName": "Reader",
 "roleDefinitionId": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/providers/Microsoft.Authorization/roleDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd",
 "condition": null,
 "conditionVersion": null,
 "createdBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "createdOn": "2025-09-05T03:11:52.463577+00:00",
 "delegatedManagedIdentityResourceId": null,
 "description": null,
 "name": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234",
 "principalName": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalType": "ServicePrincipal",
 "resourceGroup": "cloud-shell-storage-westeurope",
 "scope": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tm-project5-ai-user-identity",
 "type": "Microsoft.Authorization/roleAssignments",
 "updatedBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "updatedOn": "2025-09-08T08:11:52.463577+00:00"
}
References
Azure Official Documentation
Best practices for Azure RBAC
Assign Azure roles using the Azure portal
Azure Command Line Interface (CLI) Documentation
az account list
az account set
az cognitiveservices account list
az cognitiveservices account identity show
az role assignment list
az role assignment delete
az role assignment create
Publication date Sep 10, 2025
Related AIServices rules
Disable Public Network Access to OpenAI Service Instances (Security)
Azure Policy Assignments for AI Foundry (Security, cost-optimisation)
Disable Local Authentication in Azure AI Foundry (Security)
Enable Diagnostic Logs for OpenAI Service Instances (Security, reliability, operational-excellence, cost-optimisation, performance-efficiency)

## Key Principles
Follow security best practices and compliance requirements.

## Compliance Frameworks
TrendMicro, NIST

## Compliance Controls
Standard security controls apply

## Focus Areas
least_privilege_violations, compliance_violations, resource_wildcards

## Analysis
Regular security assessments help identify potential risks and compliance gaps.

## Certification
Compliant with industry security standards and best practices.

## Source
https://www.trendmicro.com/cloudoneconformity/knowledge-base/azure/AIServices/check-for-admin-permissions.html

## Full Content
Knowledge Base
Microsoft Azure
AI Services
Check for AI Foundry Instances with Admin Permissions
Risk Level:
High (not acceptable risk)
Ensure that your Microsoft Azure AI Foundry instances are not configured with privileged administrative permissions in order to promote the Principle of Least Privilege (POLP) and provide your AI instances the minimal amount of access required to perform their tasks.
Security
Reliability
Cost
optimisation
Performance
efficiency
Operational
excellence
In Azure cloud, user-assigned managed identities encompass a broader range of roles including privileged administrator roles. Privileged administrator roles grant extensive access privileges, such as overseeing Azure resources and delegating roles to others. To minimize security risks, the user-assigned identities associated with your Azure AI Foundry instances should not have these admin privileges. Granting admin rights can lead to unintended access, data breaches, and misuse. By limiting permissions to the minimum necessary for the instance's operation, you can adhere to the Principle of Least Privilege (POLP). This approach enhances overall security by reducing the attack surface and potential damage from unauthorized access.
Audit
To determine if your Azure AI Foundry instances are configured with admin privileges, perform the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to
All resources
blade available at
https://portal.azure.com/#browse/all
to access all your Microsoft Azure cloud resources.
03
Choose the Azure subscription that you want to access from the
Subscription equalls all
filter box and choose
Apply
.
04
From the
Type equals all
filter box, select
Type
for
Filter
,
Equals
for
Operator
, and
Azure AI Foundry
for
Value
, then choose
Apply
to list the Azure AI Services (AI Foundry) instances available in the selected subscription.
05
Click on the name (link) of the AI Foundry instance that you want to examine.
06
In the resource navigation panel, under
Resource Management
, choose
Identity
.
07
Select the
User assigned
tab and click on the name (link) of the user-assigned managed identity associated with your instance. If there are no user-assigned managed identities listed on this page, the Audit process ends here. To add user-assigned identities to your AI Foundry instance, follow the instructions outlined on
this
page.
08
In the resource navigation panel, select
Azure role assignments
to view the role assignments for the selected identity.
09
Check the
Role
column to determine if the selected identity has privileged administrator roles such as
Owner
,
Contributor
,
User Access Administrator
, and
Role Based Access Control Administrator
. You can also click on the role name to view the role permissions. If one or more privileged administrator roles are assigned to the user-assigned managed identity associated with your instance, the selected Azure AI Foundry instance is configured with admin privileges.
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
account set
command (Windows/macOS/Linux) with the ID of the Azure cloud subscription that you want to examine as the identifier parameter to set the selected subscription to be the current active subscription (the command does not produce an output):
az account set
 --subscription abcdabcd-1234-abcd-1234-abcdabcdabcd
04
Run
cognitiveservices account list
command (Windows/macOS/Linux) with custom output filters to list the name and the associated resource group for each Azure AI Services (AI Foundry) instance available within the current subscription:
az cognitiveservices account list
 --output table
 --query '[?(kind==`AIServices`)].{name:name, resourceGroup:resourceGroup}'
05
The command output should return the requested AI Foundry instance identifiers:
Name ResourceGroup
------------------------------- ------------------------------
cc-project5-ai-service-instance cloud-shell-storage-westeurope
cc-project5-ai-foundry-instance cloud-shell-storage-westeurope
06
Run
cognitiveservices account identity show
command (Windows/macOS/Linux) with the name of the Azure AI Foundry instance that you want to examine as the identifier parameter and custom output filters to describe the user-assigned managed identities associated with the selected instance:
az cognitiveservices account identity show
 --name cc-project5-ai-service-instance
 --resource-group cloud-shell-storage-westeurope
 --query 'userAssignedIdentities'
07
The command output should return the information available for the associated identities (including the identity full ID and the ID of the associated principal). If the
cognitiveservices account identity show
command does not return an output, there are no user-assigned managed identities configured for your instance and the Audit process ends here. To add user-assigned identities to your AI Foundry instance, follow the instructions outlined on
this
page:
{
 "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tm-project5-ai-user-identity": {
 "clientId": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234"
}
08
Run
role assignment list
command (Windows/macOS/Linux) to describe the role assignments for the principal associated with your user-assigned managed identity. Set
--assignee
parameter value to the
"principalId"
attribute value returned at the previous step:
az role assignment list
 --assignee abcd1234-abcd-1234-abcd-1234abcd1234
 --all
09
The command output should return the role assignments for the selected principal:
[
 {
 "roleDefinitionName": "Owner",
 "roleDefinitionId": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/providers/Microsoft.Authorization/roleDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd",
 "condition": null,
 "conditionVersion": null,
 "createdBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "createdOn": "2025-09-05T08:11:52.463577+00:00",
 "delegatedManagedIdentityResourceId": null,
 "description": null,
 "name": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234",
 "principalName": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalType": "ServicePrincipal",
 "resourceGroup": "cloud-shell-storage-westeurope",
 "scope": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.CognitiveServices/accounts/cc-project5-ai-service-instance",
 "type": "Microsoft.Authorization/roleAssignments",
 "updatedBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "updatedOn": "2025-09-05T08:11:52.463577+00:00"
 },
 {
 "roleDefinitionName": "User Access Administrator",
 "roleDefinitionId": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/providers/Microsoft.Authorization/roleDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd",
 "condition": null,
 "conditionVersion": null,
 "createdBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "createdOn": "2025-09-06T08:00:52.463577+00:00",
 "delegatedManagedIdentityResourceId": null,
 "description": null,
 "name": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234",
 "principalName": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalType": "ServicePrincipal",
 "resourceGroup": "cloud-shell-storage-westeurope",
 "scope": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.CognitiveServices/accounts/cc-project5-ai-service-instance",
 "type": "Microsoft.Authorization/roleAssignments",
 "updatedBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "updatedOn": "2025-09-06T08:00:52.463577+00:00"
 }
]
Check the
"roleDefinitionName"
attribute value for each role assignment returned by the
role assignment list
command output to determine if the associated identity has privileged administrator roles such as
"Owner"
,
"Contributor"
,
"User Access Administrator"
, and
"Role Based Access Control Administrator"
. If one or more privileged administrator roles are assigned to the user-assigned managed identity associated with your instance, the selected Azure AI Foundry instance is configured with admin privileges.
Remediation / Resolution
To ensure that your Microsoft Azure AI Foundry instances are not configured with administrative privileges, perform the following operations:
Using Azure Console
01
Sign in to the Microsoft Azure Portal.
02
Navigate to
All resources
blade available at
https://portal.azure.com/#browse/all
to access all your Microsoft Azure cloud resources.
03
Choose the Azure subscription that you want to access from the
Subscription equalls all
filter box and choose
Apply
.
04
From the
Type equals all
filter box, select
Type
for
Filter
,
Equals
for
Operator
, and
Azure AI Foundry
for
Value
, then choose
Apply
to list the Azure AI Services (AI Foundry) instances available in the selected subscription.
05
Click on the name (link) of the AI Foundry instance that you want to configure.
06
In the resource navigation panel, under
Resource Management
, choose
Identity
.
07
Select the
User assigned
tab and click on the name (link) of the user-assigned managed identity associated with your instance.
08
In the resource navigation panel, select
Azure role assignments
to view the role assignments for the selected identity.
09
Click on the name of the privileged administrator role that you want to remove from your user-assigned managed identity, select the
Assignments
tab, and choose
Remove
to delete the role assignment for the selected managed identity. In the
Remove role assignments
box, choose
Yes
for confirmation.
10
(Optional) To add a new role assigment that follows the Principle of Least Privilege (POLP), choose
Access control (IAM)
from the identity navigation panel, choose
Add
, select
Add role assigment
, and perform the following actions:
For
Role
, select the
Job function roles
tab, and choose the appropriate, non-privileged role that you want to attach. Choose
Next
to continue the assignment process.
For
Members
, select
Managed identity
next to
Assign access to
, choose
Select members
next to
Members
, and select the user-assigned managed identity associated with your AI Foundry instance. Choose
Next
to continue.
For
Review + assign
, review the role assignment information, then choose
Review + assign
to complete the assigment process.
Using Azure CLI
01
Run
role assignment delete
command (OSX/Linux/UNIX) to remove the privileged administrator role from your user-assigned managed identity. As an example, the following command removes the "Owner" role assignment (if the request is successful, the command does not produce an output):
az role assignment delete
 --assignee abcd1234-abcd-1234-abcd-1234abcd1234
 --role "Owner"
02
(Optional) Run
role assignment create
command (OSX/Linux/UNIX) to add a new role assigment that follows the Principle of Least Privilege to your user-assigned managed identity. Use the
--role
parameter to specify the name of the non-privileged role that you want to assign:
az role assignment create
 --assignee abcd1234-abcd-1234-abcd-1234abcd1234
 --role Reader
 --scope "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tm-project5-ai-user-identity"
03
Once the assignment process is completed, the command output should return the information available for the new role assignment:
{
 "roleDefinitionName": "Reader",
 "roleDefinitionId": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/providers/Microsoft.Authorization/roleDefinitions/1234abcd-1234-abcd-1234-abcd1234abcd",
 "condition": null,
 "conditionVersion": null,
 "createdBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "createdOn": "2025-09-05T03:11:52.463577+00:00",
 "delegatedManagedIdentityResourceId": null,
 "description": null,
 "name": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalId": "abcd1234-abcd-1234-abcd-1234abcd1234",
 "principalName": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "principalType": "ServicePrincipal",
 "resourceGroup": "cloud-shell-storage-westeurope",
 "scope": "/subscriptions/1234abcd-1234-abcd-1234-abcd1234abcd/resourceGroups/cloud-shell-storage-westeurope/providers/Microsoft.ManagedIdentity/userAssignedIdentities/tm-project5-ai-user-identity",
 "type": "Microsoft.Authorization/roleAssignments",
 "updatedBy": "1234abcd-1234-abcd-1234-abcd1234abcd",
 "updatedOn": "2025-09-08T08:11:52.463577+00:00"
}
References
Azure Official Documentation
Best practices for Azure RBAC
Assign Azure roles using the Azure portal
Azure Command Line Interface (CLI) Documentation
az account list
az account set
az cognitiveservices account list
az cognitiveservices account identity show
az role assignment list
az role assignment delete
az role assignment create
Publication date Sep 10, 2025
Related AIServices rules
Disable Public Network Access to OpenAI Service Instances (Security)
Azure Policy Assignments for AI Foundry (Security, cost-optimisation)
Disable Local Authentication in Azure AI Foundry (Security)
Enable Diagnostic Logs for OpenAI Service Instances (Security, reliability, operational-excellence, cost-optimisation, performance-efficiency)
