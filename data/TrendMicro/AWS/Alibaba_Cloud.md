# Alibaba Cloud

## Overview
Knowledge Base
Alibaba Cloud
Get Started
Get Pricing
Contact Us
Trend Vision One™ has over 1100+ cloud infrastructure configuration best practices for your Alibaba Cloud,
Amazon Web Services
,
Microsoft® Azure
, and
Google Cloud™
environments. Here is our growing list of Alibaba cloud security, configuration and compliance rules with clear instructions on how to perform the updates – made either through the Alibaba Cloud console or via the Alibaba Cloud Command Line Interface (CLI).
Please note:
Alibaba Cloud is currently available only in Trend Vision One™ and not in Trend Cloud One™ – Conformity.
Trend Vision One™ provides real-time monitoring and auto-remediation for the security, compliance and governance of your cloud infrastructure. Leaving you to grow and scale your business with confidence.
Alibaba Cloud ACK
Cluster Check
Ensure that Cluster Check is triggered periodically for your ACK clusters.
Disable Basic Authentication for ACK Clusters
Ensure that basic authentication is disabled for ACK clusters.
Disable Kubernetes Dashboard for ACK Clusters
Ensure that Kubernetes Dashboard is disabled for ACK clusters.
Disable Public Access to Kubernetes API Server
Ensure that your Kubernetes API server is not publicly accessible.
ENI Multiple IP Mode
Ensure that ACK clusters are configured to use the ENI multiple IP mode.
Enable Cloud Monitor for ACK Clusters
Ensure that Cloud Monitor service is enabled for your ACK clusters.
Enable Cluster Auditing with Simple Log Service
Ensure that cluster auditing with Simple Log Service is enabled for your ACK clusters.
Enable RBAC Authorization for ACK Clusters
Ensure that Role-Based Access Control (RBAC) authorization is enabled for your ACK clusters.
Enable Support for Network Policies
Ensure that ACK clusters are using network policies.
Alibaba Cloud ActionTrail
Enable Global Service (Multi-Region) Logging
Ensure that Global Service Logging is enabled for ActionTrail trails.
Ensure the OSS bucket used to store ActionTrail logs is not publicly accessible
Ensure that your ActionTrail trail buckets are not publicly accessible.
Alibaba Cloud ECS
Apply Latest OS Patches
Ensure that the latest OS patches for ECS instances are applied.
Check for Unrestricted RDP Access
Ensure that no security groups allow unrestricted ingress access on TCP port 3389 (RDP).
Check for Unrestricted SSH Access
Ensure that no security groups allow unrestricted ingress access on TCP port 22 (SSH).
Enable Encryption for Unattached Disks
Ensure that data encryption is enabled for all unattached ECS data disks.
Enable Encryption for VM Instance Disks
Ensure that data encryption is enabled for virtual machine (VM) instance disks.
Enable Endpoint Protection
Ensure that the latest OS patches for ECS instances are applied.
Alibaba Cloud OSS
Enable Access Logging for OSS Buckets
Ensure OSS Bucket Access Logging is enabled for security and access audits.
Enable Secure Transfer for OSS Buckets
Ensure that OSS buckets enforce SSL to secure data in transit.
Enable Server-Side Encryption with Customer Managed Key
Ensure that Server-Side Encryption is using customer-managed keys for OSS data encryption.
Enable Server-Side Encryption with Service Managed Key
Ensure that Server-Side Encryption with service managed key is enabled.
Limit Network Access to Selected Networks
Ensure that OSS bucket access is limited to selected networks only.
OSS Bucket Public Access
Ensure that OSS buckets are not configured to allow public and/or anonymous access.
Object URL Signature Validity Period
Ensure that the shared URL signature is set to expire within 3600 seconds (1 hour).
Publicly Accessible OSS Objects
Ensure that there are no publicly accessible objects in OSS buckets.
Use HTTPS for Object URL Signature
Ensure that the object URL signature is allowed only over HTTPS.
Alibaba Cloud RAM
Configure Password Retry Constraint Policy for RAM Users
Ensure that RAM user password policy is configured to limit the number of login attempts.
Disable Console Access for RAM Users Inactive for 90 days
Ensure that console access is disabled for inactive Resource Access Management (RAM) users.
Enable MFA for Root Account
Ensure that Multi-Factor Authentication (MFA) is enabled for your Alibaba Cloud account.
Ensure RAM User has no attached policies
Ensure that RAM users have no attached policies, and are getting their access permissions only via RAM groups.
Ensure RAM password policy requires at least one number
Ensure that RAM password policy requires at least one number.
Ensure RAM password policy requires at least one uppercase letter
Ensure that RAM password policy requires at least one uppercase letter.
Ensure RAM password policy requires minimum length of 14 or greater
Ensure that RAM password policy requires minimum 14 characters for passwords.
MFA For RAM Users With Console Password
Ensure that Multi-Factor Authentication (MFA) is enabled for all RAM users with console access.
RAM Password Policy Enforces Password Expiration
Ensure that password policy enforces password expiration within 90 days or less.
RAM Password Policy Prevents Password Reuse
Ensure that RAM user password policy prevents password reuse.
RAM Password Policy Requires at Least One Symbol
Ensure that RAM password policy requires at least one symbol.
RAM Password Policy with at Least One Lowercase Letter
Ensure that RAM password policy requires at least one lowercase letter.
RAM Policies With Full Administrative Privileges
Ensure that RAM policies with full "*:*" administrative privileges are not created.
RAM User Access Keys Rotation
Ensure that RAM user access keys are rotated on a periodic basis to follow security best practices.
Root Account Access Keys Existence
Ensure that your Alibaba Cloud root account is not using access keys as a security best practice.
Root Account Usage
Ensure that your Alibaba Cloud root account usage is minimized.
Alibaba Cloud RDS
Disable Public Access
Ensure that RDS database instances are not publicly accessible.
Enable "log_connections" Parameter for PostgreSQL Database Instances
Enable that "log_connections" parameter is enabled for RDS database instances.
Enable "log_disconnections" Parameter for PostgreSQL Database Instances
Enable that "log_disconnections" parameter is enabled for RDS database instances.
Enable "log_duration" Parameter for PostgreSQL Database Instances
Ensure that "log_duration" parameter is enabled for RDS database instances.
Enable Encryption in Transit
Ensure that RDS database instances are configured to enforce SSL for all incoming connections.
Enable SQL Auditing for MySQL Database Instances
Ensure that SQL auditing is enabled for applicable MySQL database instances.
Enable SQL Auditing for PostgreSQL Database Instances
Ensure that SQL auditing is enabled for applicable PostgreSQL database instances.
Enable SQL Auditing for RDS Database Instances
Ensure that SQL auditing is enabled for RDS applicable database instances.
Enable SQL Auditing for SQL Server Database Instances
Ensure that SQL auditing is enabled for applicable SQL Server database instances.
Enable Transparent Data Encryption
Ensure that Transparent Data Encryption is enabled for RDS database instances.
Enable Transparent Data Encryption with Customer Managed Keys
Ensure that Transparent Data Encryption (TDE) is using custom keys for TDE protector.
SQL Audit Logs Retention Period
Ensure that SQL database audit retention period is greater than or equal to 6 months.
Alibaba Cloud SLS
Check for Sufficient Log Retention Period
Ensure that the SLS Logstore log retention period is set for 365 days or greater.
Config Assessment Authorization
Ensure that Config Assessment is authorized to access other cloud resources.
Create Alert for Account Login Failures
Ensure that account login failures are being monitored using alerts.
Create Alert for Cloud Firewall Control Policy Changes
Ensure that Cloud Firewall control policy changes are being monitored using alerts.
Create Alert for KMS Key Configuration Changes
Ensure that KMS key configuration changes are being monitored using alerts.
Create Alert for OSS Bucket Authority Changes
Ensure that OSS bucket authority changes are being monitored using alerts.
Create Alert for OSS Bucket Permission Changes
Ensure that OSS bucket permission changes are being monitored using alerts.
Create Alert for RAM Policy Changes
Ensure that RAM policy changes are being monitored using alerts.
Create Alert for RDS Instance Configuration Changes
Ensure that RDS instance configuration changes are being monitored using alerts.
Create Alert for Root Account Frequent Logins
Ensure that root account login attempts are being monitored using alerts.
Create Alert for Security Group Configuration Changes
Ensure that security group configuration changes are being monitored using alerts.
Create Alert for Single-Factor Management Console Logins
Ensure that single-factor Management Console logins are being monitored using alerts.
Create Alert for Unauthorized API Calls
Ensure that unauthorized API calls are being monitored using alerts.
Create Alert for VPC Configuration Changes
Ensure that VPC configuration changes are being monitored using alerts.
Create Alert for VPC Network Route Changes
Ensure that VPC network route changes are being monitored using alerts.
Enable Asset Fingerprints Data Collection
Ensure that automatic collection of server fingerprints is enabled in the Security Center settings.
Enable Audit Logs for Multiple Cloud Services
Ensure that audit logging is enabled for multiple cloud services using the Log Audit Service.
Enable Cluster Integration with Simple Log Service
Ensure that ACK cluster integration with Simple Log Service is enabled.
Enable Log Analysis for Anti-DDoS Instances
Ensure that Log Analysis is enabled for the Anti-DDoS instances.
Enable Log Analysis for Cloud Firewall
Ensure that security log analysis is enabled for the Cloud Firewall service.
Enable Log Analysis in Security Center
Ensure that Log Analysis is enabled within the Security Center settings.
Enable Malicious Behavior Defense
Ensure that Malicious Behavior Defense is enabled within your Alibaba Cloud account.
Enable Simple Log Service for Web Application Firewall
Ensure that Simple Log Service is enabled for Web Application Firewall (WAF).
Enable Webshell Protection
Ensure that Webshell Protection is enabled within your Alibaba Cloud account.
Flow Log Enabled and Configured
Ensure that the Flow Log feature is enabled and properly configured.
Alibaba Cloud Security Center
Enable Scheduled Vulnerability Scan
Ensure that scheduled vulnerability scan is enabled on all servers.
Enable Security Center Notifications
Ensure that Security Center notifications are enabled for all high risk items.
Install Security Center Agent
Ensure that Security Center agent is installed on all hosts.
Security Center Plan
Ensure that your Security Center plan is set to Advanced or Enterprise Edition.
Alibaba Cloud VPC
Check Security Groups for Fine Grained Rules
Ensure that security groups are configured with fine grained rules.
Enable VPC Flow Log
Ensure that Flow Log is enabled for your Virtual Private Clouds (VPCs).
Prevent the Use of Legacy Networks
Ensure that ECS instances are not configured to use legacy networks.
Restrict Network Access to Remote Console Services
Ensure that the network access to remote console services is restricted.
VPC Peering Routing Tables
Ensure that your VPC peering routing tables have the minimum access levels required.

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
https://www.trendmicro.com/cloudoneconformity/knowledge-base/alibaba-cloud/

## Full Content
Knowledge Base
Alibaba Cloud
Get Started
Get Pricing
Contact Us
Trend Vision One™ has over 1100+ cloud infrastructure configuration best practices for your Alibaba Cloud,
Amazon Web Services
,
Microsoft® Azure
, and
Google Cloud™
environments. Here is our growing list of Alibaba cloud security, configuration and compliance rules with clear instructions on how to perform the updates – made either through the Alibaba Cloud console or via the Alibaba Cloud Command Line Interface (CLI).
Please note:
Alibaba Cloud is currently available only in Trend Vision One™ and not in Trend Cloud One™ – Conformity.
Trend Vision One™ provides real-time monitoring and auto-remediation for the security, compliance and governance of your cloud infrastructure. Leaving you to grow and scale your business with confidence.
Alibaba Cloud ACK
Cluster Check
Ensure that Cluster Check is triggered periodically for your ACK clusters.
Disable Basic Authentication for ACK Clusters
Ensure that basic authentication is disabled for ACK clusters.
Disable Kubernetes Dashboard for ACK Clusters
Ensure that Kubernetes Dashboard is disabled for ACK clusters.
Disable Public Access to Kubernetes API Server
Ensure that your Kubernetes API server is not publicly accessible.
ENI Multiple IP Mode
Ensure that ACK clusters are configured to use the ENI multiple IP mode.
Enable Cloud Monitor for ACK Clusters
Ensure that Cloud Monitor service is enabled for your ACK clusters.
Enable Cluster Auditing with Simple Log Service
Ensure that cluster auditing with Simple Log Service is enabled for your ACK clusters.
Enable RBAC Authorization for ACK Clusters
Ensure that Role-Based Access Control (RBAC) authorization is enabled for your ACK clusters.
Enable Support for Network Policies
Ensure that ACK clusters are using network policies.
Alibaba Cloud ActionTrail
Enable Global Service (Multi-Region) Logging
Ensure that Global Service Logging is enabled for ActionTrail trails.
Ensure the OSS bucket used to store ActionTrail logs is not publicly accessible
Ensure that your ActionTrail trail buckets are not publicly accessible.
Alibaba Cloud ECS
Apply Latest OS Patches
Ensure that the latest OS patches for ECS instances are applied.
Check for Unrestricted RDP Access
Ensure that no security groups allow unrestricted ingress access on TCP port 3389 (RDP).
Check for Unrestricted SSH Access
Ensure that no security groups allow unrestricted ingress access on TCP port 22 (SSH).
Enable Encryption for Unattached Disks
Ensure that data encryption is enabled for all unattached ECS data disks.
Enable Encryption for VM Instance Disks
Ensure that data encryption is enabled for virtual machine (VM) instance disks.
Enable Endpoint Protection
Ensure that the latest OS patches for ECS instances are applied.
Alibaba Cloud OSS
Enable Access Logging for OSS Buckets
Ensure OSS Bucket Access Logging is enabled for security and access audits.
Enable Secure Transfer for OSS Buckets
Ensure that OSS buckets enforce SSL to secure data in transit.
Enable Server-Side Encryption with Customer Managed Key
Ensure that Server-Side Encryption is using customer-managed keys for OSS data encryption.
Enable Server-Side Encryption with Service Managed Key
Ensure that Server-Side Encryption with service managed key is enabled.
Limit Network Access to Selected Networks
Ensure that OSS bucket access is limited to selected networks only.
OSS Bucket Public Access
Ensure that OSS buckets are not configured to allow public and/or anonymous access.
Object URL Signature Validity Period
Ensure that the shared URL signature is set to expire within 3600 seconds (1 hour).
Publicly Accessible OSS Objects
Ensure that there are no publicly accessible objects in OSS buckets.
Use HTTPS for Object URL Signature
Ensure that the object URL signature is allowed only over HTTPS.
Alibaba Cloud RAM
Configure Password Retry Constraint Policy for RAM Users
Ensure that RAM user password policy is configured to limit the number of login attempts.
Disable Console Access for RAM Users Inactive for 90 days
Ensure that console access is disabled for inactive Resource Access Management (RAM) users.
Enable MFA for Root Account
Ensure that Multi-Factor Authentication (MFA) is enabled for your Alibaba Cloud account.
Ensure RAM User has no attached policies
Ensure that RAM users have no attached policies, and are getting their access permissions only via RAM groups.
Ensure RAM password policy requires at least one number
Ensure that RAM password policy requires at least one number.
Ensure RAM password policy requires at least one uppercase letter
Ensure that RAM password policy requires at least one uppercase letter.
Ensure RAM password policy requires minimum length of 14 or greater
Ensure that RAM password policy requires minimum 14 characters for passwords.
MFA For RAM Users With Console Password
Ensure that Multi-Factor Authentication (MFA) is enabled for all RAM users with console access.
RAM Password Policy Enforces Password Expiration
Ensure that password policy enforces password expiration within 90 days or less.
RAM Password Policy Prevents Password Reuse
Ensure that RAM user password policy prevents password reuse.
RAM Password Policy Requires at Least One Symbol
Ensure that RAM password policy requires at least one symbol.
RAM Password Policy with at Least One Lowercase Letter
Ensure that RAM password policy requires at least one lowercase letter.
RAM Policies With Full Administrative Privileges
Ensure that RAM policies with full "*:*" administrative privileges are not created.
RAM User Access Keys Rotation
Ensure that RAM user access keys are rotated on a periodic basis to follow security best practices.
Root Account Access Keys Existence
Ensure that your Alibaba Cloud root account is not using access keys as a security best practice.
Root Account Usage
Ensure that your Alibaba Cloud root account usage is minimized.
Alibaba Cloud RDS
Disable Public Access
Ensure that RDS database instances are not publicly accessible.
Enable "log_connections" Parameter for PostgreSQL Database Instances
Enable that "log_connections" parameter is enabled for RDS database instances.
Enable "log_disconnections" Parameter for PostgreSQL Database Instances
Enable that "log_disconnections" parameter is enabled for RDS database instances.
Enable "log_duration" Parameter for PostgreSQL Database Instances
Ensure that "log_duration" parameter is enabled for RDS database instances.
Enable Encryption in Transit
Ensure that RDS database instances are configured to enforce SSL for all incoming connections.
Enable SQL Auditing for MySQL Database Instances
Ensure that SQL auditing is enabled for applicable MySQL database instances.
Enable SQL Auditing for PostgreSQL Database Instances
Ensure that SQL auditing is enabled for applicable PostgreSQL database instances.
Enable SQL Auditing for RDS Database Instances
Ensure that SQL auditing is enabled for RDS applicable database instances.
Enable SQL Auditing for SQL Server Database Instances
Ensure that SQL auditing is enabled for applicable SQL Server database instances.
Enable Transparent Data Encryption
Ensure that Transparent Data Encryption is enabled for RDS database instances.
Enable Transparent Data Encryption with Customer Managed Keys
Ensure that Transparent Data Encryption (TDE) is using custom keys for TDE protector.
SQL Audit Logs Retention Period
Ensure that SQL database audit retention period is greater than or equal to 6 months.
Alibaba Cloud SLS
Check for Sufficient Log Retention Period
Ensure that the SLS Logstore log retention period is set for 365 days or greater.
Config Assessment Authorization
Ensure that Config Assessment is authorized to access other cloud resources.
Create Alert for Account Login Failures
Ensure that account login failures are being monitored using alerts.
Create Alert for Cloud Firewall Control Policy Changes
Ensure that Cloud Firewall control policy changes are being monitored using alerts.
Create Alert for KMS Key Configuration Changes
Ensure that KMS key configuration changes are being monitored using alerts.
Create Alert for OSS Bucket Authority Changes
Ensure that OSS bucket authority changes are being monitored using alerts.
Create Alert for OSS Bucket Permission Changes
Ensure that OSS bucket permission changes are being monitored using alerts.
Create Alert for RAM Policy Changes
Ensure that RAM policy changes are being monitored using alerts.
Create Alert for RDS Instance Configuration Changes
Ensure that RDS instance configuration changes are being monitored using alerts.
Create Alert for Root Account Frequent Logins
Ensure that root account login attempts are being monitored using alerts.
Create Alert for Security Group Configuration Changes
Ensure that security group configuration changes are being monitored using alerts.
Create Alert for Single-Factor Management Console Logins
Ensure that single-factor Management Console logins are being monitored using alerts.
Create Alert for Unauthorized API Calls
Ensure that unauthorized API calls are being monitored using alerts.
Create Alert for VPC Configuration Changes
Ensure that VPC configuration changes are being monitored using alerts.
Create Alert for VPC Network Route Changes
Ensure that VPC network route changes are being monitored using alerts.
Enable Asset Fingerprints Data Collection
Ensure that automatic collection of server fingerprints is enabled in the Security Center settings.
Enable Audit Logs for Multiple Cloud Services
Ensure that audit logging is enabled for multiple cloud services using the Log Audit Service.
Enable Cluster Integration with Simple Log Service
Ensure that ACK cluster integration with Simple Log Service is enabled.
Enable Log Analysis for Anti-DDoS Instances
Ensure that Log Analysis is enabled for the Anti-DDoS instances.
Enable Log Analysis for Cloud Firewall
Ensure that security log analysis is enabled for the Cloud Firewall service.
Enable Log Analysis in Security Center
Ensure that Log Analysis is enabled within the Security Center settings.
Enable Malicious Behavior Defense
Ensure that Malicious Behavior Defense is enabled within your Alibaba Cloud account.
Enable Simple Log Service for Web Application Firewall
Ensure that Simple Log Service is enabled for Web Application Firewall (WAF).
Enable Webshell Protection
Ensure that Webshell Protection is enabled within your Alibaba Cloud account.
Flow Log Enabled and Configured
Ensure that the Flow Log feature is enabled and properly configured.
Alibaba Cloud Security Center
Enable Scheduled Vulnerability Scan
Ensure that scheduled vulnerability scan is enabled on all servers.
Enable Security Center Notifications
Ensure that Security Center notifications are enabled for all high risk items.
Install Security Center Agent
Ensure that Security Center agent is installed on all hosts.
Security Center Plan
Ensure that your Security Center plan is set to Advanced or Enterprise Edition.
Alibaba Cloud VPC
Check Security Groups for Fine Grained Rules
Ensure that security groups are configured with fine grained rules.
Enable VPC Flow Log
Ensure that Flow Log is enabled for your Virtual Private Clouds (VPCs).
Prevent the Use of Legacy Networks
Ensure that ECS instances are not configured to use legacy networks.
Restrict Network Access to Remote Console Services
Ensure that the network access to remote console services is restricted.
VPC Peering Routing Tables
Ensure that your VPC peering routing tables have the minimum access levels required.
