# AWS

## Overview
Knowledge Base
Amazon Web Services
Get Started
Get Pricing
Contact Us
Amazon Web Services best practice rules
Trend Vision One™ has over 1100+ cloud infrastructure configuration best practices for your
Alibaba Cloud
, Amazon Web Services™,
Microsoft® Azure
, and
Google Cloud™
environments. Here is our growing list of AWS security, configuration and compliance rules with clear instructions on how to perform the updates – made either through the AWS console or via the AWS Command Line Interface (CLI).
Trend Vision One™ provides real-time monitoring and auto-remediation for the security, compliance and governance of your cloud infrastructure. Leaving you to grow and scale your business with confidence.
AWS Certificate Manager
ACM Certificate Expired
Ensure expired SSL/TLS certificates are removed from AWS Certificate Manager (ACM).
AWS ACM Certificates Renewal (30 days before expiration)
Ensure Amazon Certificate Manager (ACM) certificates are renewed before their expiration.
AWS ACM Certificates Renewal (45 days before expiration)
Ensure Amazon Certificate Manager (ACM) certificates are renewed before their expiration.
AWS ACM Certificates Renewal (7 days before expiration)
Ensure Amazon Certificate Manager (ACM) certificates are renewed before their expiration.
AWS ACM Certificates Validity
Ensure expired SSL/TLS certificates are removed from AWS Certificate Manager (ACM).
AWS ACM Certificates with Wildcard Domain Names
Ensure that wildcard certificates issued by Amazon Certificate Manager (ACM) or imported to ACM are not in use.
Amazon API Gateway
API Gateway Integrated With AWS WAF
Use AWS WAF to protect Amazon API Gateway APIs from common web exploits.
APIs CloudWatch Logs
Ensure that AWS CloudWatch logs are enabled for all your APIs created with Amazon API Gateway service in order to track and analyze execution behavior at the API stage level.
APIs Detailed CloudWatch Metrics
Ensure that detailed CloudWatch metrics are enabled for all APIs created with AWS API Gateway service in order to monitor API stages caching, latency and detected errors at a more granular level and set alarms accordingly.
Check for Unknown Cross Account API Access
Ensure that Amazon API Gateway APIs do not allow unknown cross-account access.
Check the Minimum TLS Version Configured for API Gateway Domains
Ensure that Amazon API Gateway domains are configured with the latest version of TLS protocol.
Client Certificate
Use client-side SSL certificates for HTTP backend authentication within AWS API Gateway.
Content Encoding
Ensure Content Encoding is enabled for your APIs.
Enable API Cache
Ensure that REST APIs created with Amazon API Gateway have response caching enabled.
Enable Access Logs for API Gateway V2 API Stages
Ensure that access logging is enabled for all Amazon API Gateway V2 API stages.
Enable Control Access to REST APIs using Keys or Tokens
Ensure that access to your API Gateway REST APIs is controlled using keys or tokens.
Enable Encryption for API Cache
Ensure that stage-level cache encryption is enabled for your Amazon API Gateway APIs.
Limit REST API Access by IP Address
Ensure that the access to your REST APIs is allowed to trusted IP addresses only.
Private Endpoint
Ensure Amazon API Gateway APIs are only accessible through private API endpoints.
Rotate Expiring SSL Client Certificates
Ensure that SSL certificates associated with API Gateway REST APIs are rotated periodically.
Tracing Enabled
Ensure that tracing is enabled for all stages in all APIs created with AWS API Gateway service in order to analyze latencies in APIs and their backend services.
Amazon AccessAnalyzer
IAM Access Analyzer Findings
Ensure that IAM Access Analyzer findings are reviewed and resolved to maintain access security to your AWS resources.
Amazon AppFlow
Enable Data Encryption with KMS Customer Master Keys
Ensure that Amazon AppFlow flows are encrypted with KMS Customer Master Keys (CMKs).
AWS App Mesh
Enable Access Logging for App Mesh Virtual Gateways
Ensure that Access Logging is enabled for your Amazon App Mesh virtual gateways.
Enable Health Checks for App Mesh Virtual Gateways
Ensure that Amazon App Mesh virtual gateways are using health checks.
Enforce TLS for App Mesh Virtual Gateways
Enforce TLS by default for your Amazon App Mesh virtual gateways.
Restrict External Traffic
Ensure that Amazon App Mesh proxies are only forwarding traffic between each other.
Amazon Athena
Enable Encryption for AWS Athena Query Results
Ensure that AWS Athena query results stored in Amazon S3 are encrypted at rest.
AWS Auto Scaling
App-Tier Auto Scaling Group associated ELB
Ensure that each app-tier Auto Scaling Group (ASG) has an associated Elastic Load Balancer (ELB) in order to maintain the availability of the EC2 compute resources in the event of a failure and provide an evenly distributed application load.
Auto Scaling Group Cooldown Period
Ensure Amazon Auto Scaling Groups are utilizing cooldown periods.
Auto Scaling Group Health Check
Ensure ELB health check is enabled if Elastic Load Balancing is being used for an Auto Scaling group. Ensure EC2 health check is enabled if Elastic Load Balancing isn't being used for an Auto Scaling group
Auto Scaling Group Notifications
Ensure notifications are enabled for ASGs to receive additional information about scaling operations.
Auto Scaling Group Referencing Missing ELB
Ensure Amazon Auto Scaling Groups are utilizing active Elastic Load Balancers.
Auto Scaling Group associated ELB
Ensure that each Auto Scaling Group (ASG) has an associated Elastic Load Balancer (ELB) in order to maintain the availability of the EC2 compute resources in the event of a failure and provide an evenly distributed application load.
CloudWatch Logs Agent for App-Tier Auto Scaling Group In Use
Ensure an agent for AWS CloudWatch Logs is installed within Auto Scaling Group for app tier.
CloudWatch Logs Agent for Web-Tier Auto Scaling Group In Use
Ensure an agent for AWS CloudWatch Logs is installed within Auto Scaling Group for web tier.
Configure Metadata Response Hop Limit
Configure the metadata response hop limit for EC2 instances running within the Auto Scaling Group.
Configure Multiple Instance Types Across Multiple AZs
Ensure that your Auto Scaling Groups are using multiple instance types across multiple Availability Zones.
Disable Public IP Association in ASG Launch Templates
Ensure that your Auto Scaling Group (ASG) instances are not using public IP addresses.
Empty Auto Scaling Group
Identify and remove empty AWS Auto Scaling Groups (ASGs).
IAM Roles for App-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for app tier is configured to use a customer created app-tier IAM role.
IAM Roles for Web-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for web tier is configured to use a customer created web-tier IAM role.
Launch Configuration Referencing Missing AMI
Ensure AWS Launch Configurations are utilizing active Amazon Machine Images.
Launch Configuration Referencing Missing Security Groups
Ensure AWS Launch Configurations are utilizing active Security Groups.
Multi-AZ Auto Scaling Groups
Ensure AWS Auto Scaling Groups utilize multiple Availability Zones to improve environment reliability.
Same Availability Zones In ASG And ELB
Ensure AWS Availability Zones used for Auto Scaling Groups and for their Elastic Load Balancers are the same.
Suspended Auto Scaling Groups
Ensure there are no Amazon Auto Scaling Groups with suspended processes.
Unused Launch Configuration
Identify and remove unused AWS Auto Scaling Launch Configuration templates.
Use Approved AMIs for App-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for app tier is configured to use an approved Amazon Machine Image.
Use Approved AMIs for Web-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for web tier is configured to use an approved Amazon Machine Image.
Use Launch Templates for Auto Scaling Groups
Ensure that your Auto Scaling Groups (ASGs) are utilizing launch templates.
Web-Tier Auto Scaling Group associated ELB
Ensure that each web-tier Auto Scaling Group (ASG) has an associated Elastic Load Balancer (ELB) in order to maintain the availability of the EC2 compute resources in the event of a failure and provide an evenly distributed application load.
AWS Backup
AWS Backup Service Lifecycle Configuration
Ensure Amazon Backup plans have a compliant lifecycle configuration enabled.
Check for Protected Amazon Backup Resource Types
Ensure that the appropriate resource types are protected by Amazon Backup within your AWS account.
Configure AWS Backup Vault Access Policy
Prevent the deletion of backups using the AWS Backup vault access policy.
Enable Alert Notifications for Failed Backup Jobs
Ensure that email notifications for unsuccessful backup jobs are enabled.
Use AWS Backup Service in Use for Amazon RDS
Ensure that Amazon Backup service is used to manage AWS RDS database snapshots.
Use KMS Customer Master Keys for AWS Backup
Ensure that your backups are encrypted at rest using KMS Customer Master Keys (CMKs).
Amazon Bedrock
Amazon Bedrock Service Role Policy Too Permissive
Ensure that policies attached to Amazon Bedrock service roles adhere to the Principle of Least Privilege.
Check for Long-Term API Keys
To prevent credential exposure, use short-term Amazon Bedrock API keys instead of long-term API keys.
Check for Missing Amazon Bedrock Agent Service Role
Ensure that Amazon Bedrock agents are referencing active (available) service roles.
Check for Missing Model Customization Job Security Groups
Ensure that Bedrock model customization jobs are referencing active (available) VPC security groups.
Configure Data Deletion Policy for Knowledge Base Data
Ensure that the vector store data is retained when the knowledge base data sources are deleted.
Configure Permissions Boundaries for IAM Identities used by Amazon Bedrock
For enhanced security, ensure that permissions boundaries are set for IAM identities used by Amazon Bedrock.
Configure Prompt Attack Strength for Amazon Bedrock Guardrails
Ensure that prompt attack strength is set to HIGH for Amazon Bedrock guardrails.
Configure Sensitive Information Filters for Amazon Bedrock Guardrails
Ensure that sensitive information filters are configured for Amazon Bedrock guardrails.
Cross-Service Confused Deputy Prevention
Ensure that policies attached to Amazon Bedrock service roles are configured to prevent cross-service impersonation.
Enable Model Invocation Logging
Ensure that model invocation logging is enabled in the Amazon Bedrock account level settings.
Protect Model Customization Jobs using a VPC
Ensure that Bedrock model customization jobs are protected by a Virtual Private Cloud (VPC).
Use Customer-Managed Keys to Encrypt Agent Sessions
Ensure that agent session data is encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Amazon Bedrock Guardrails
Ensure that Bedrock guardrails are encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Amazon Bedrock Studio Workspaces
Ensure that Bedrock Studio workspaces are encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Custom Models
Ensure that AWS Bedrock custom models are encrypted with Amazon KMS Customer-Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Knowledge Base Transient Data
Ensure that knowledge base transient data is encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Guardrails to Protect Agent Sessions
Ensure that Bedrock agent sessions are associated with guardrails for protection.
AWS Budgets
Budget Overrun (Deprecated)
Cost of '[Limit details eg Service: Lambda]' overruns the budget limit
Budget Overrun Forecast (Deprecated)
Cost of '[Limit details eg Service: Lambda]' is estimated to overrun the budget limit.
Cost Fluctuation (Deprecated)
Cost of '[Limit details eg Service: Lambda]' in the current period has fluctuated beyond the defined percentage limit of the previous period.
Cost Fluctuation Forecast (Deprecated)
Cost of '[Limit details eg Service: Lambda]' in the current period is forecasted to fluctuate beyond the defined percentage limit of the previous period.
Current Contact Details
Ensure valid contact information for all your Amazon Web Services accounts.
Detailed billing
Ensure Detailed Billing is enabled for your Amazon Web Services account.
AWS Cloud​Formation
AWS CloudFormation Deletion Policy in Use
Ensure a deletion policy is used for your Amazon CloudFormation stacks.
AWS CloudFormation Drift Detection
Ensure that Amazon CloudFormation stacks have not been drifted.
CloudFormation In Use
Ensure CloudFormation service is in use for defining your cloud architectures on Amazon Web Services
CloudFormation Stack Failed Status
Ensure AWS CloudFormation stacks aren't in 'Failed' mode for more than 6 hours.
CloudFormation Stack Notification
Ensure CloudFormation stacks are integrated with SNS to receive notifications about stack events.
CloudFormation Stack Policy
Ensure CloudFormation stack policies are set to prevent accidental updates to stack resources.
CloudFormation Stack Termination Protection
Ensure Termination Protection feature is enabled for your AWS CloudFormation stacks.
CloudFormation Stack With IAM Role
Ensure that IAM role associated with CloudFormation stacks adheres to the principle of least privilege in order avoid unwanted privilege escalation.
Amazon CloudFront
CloudFront Compress Objects Automatically
Ensure CloudFront distributions are configured to automatically compress content.
CloudFront Geo Restriction
Ensure Geo Restriction is enabled for CloudFront CDN distributions.
CloudFront In Use
Ensure CloudFront global content delivery network (CDN) service is in use.
CloudFront Insecure Origin SSL Protocols
Ensure CloudFront origins don't use insecure SSL protocols.
CloudFront Integrated With WAF
Ensure CloudFront is integrated with WAF to protect web applications from exploit attempts that can compromise security or place unnecessary load on your application.
CloudFront Logging Enabled
Ensure CloudFront logging is enabled.
CloudFront Security Policy
Ensure AWS CloudFront distributions are using improved security policies for HTTPS connections.
CloudFront Traffic To Origin Unencrypted
Ensure traffic between a CloudFront distribution and the origin is encrypted.
CloudFront Viewer Protocol Policy
Ensure CloudFront Viewer Protocol Policy enforces encryption.
Configure Default Root Object
Ensure that CloudFront distributions are configured to use a default root object.
Enable Origin Access Control for Distributions with S3 Origin
Ensure that CloudFront distributions are using an origin access control configuration for their origin S3 buckets.
Enable Origin Failover
Ensure that CloudFront distributions are using the Origin Failover feature to maintain high availability.
Enable Origin Shield
Ensure that Amazon CloudFront distributions are using the Origin Shield feature.
Enable Real-Time Logging
Ensure that CloudFront distributions are using the Real-Time Logging feature.
FieldLevel Encryption
Enable Field-Level Encryption for CloudFront Distributions.
Missing S3 Bucket
Ensure that CloudFront distributions do not point to non-existent S3 origins.
Use CloudFront Content Distribution Network
Use Amazon CloudFront Content Distribution Network for secure web content delivery.
Use Custom SSL/TLS Certificates
Ensure that CloudFront distributions are configured to use a custom SSL/TLS certificate.
Use SNI to Serve HTTPS Requests
Ensure that CloudFront distributions are configured to use Server Name Indication (SNI).
AWS CloudTrail
AWS CloudTrail Configuration Changes
CloudTrail configuration changes have been detected within your Amazon Web Services account.
Avoid Duplicate Entries in Amazon CloudTrail Logs
Ensure that AWS CloudTrail trails aren't duplicating global service events in their aggregated log files
Check for Missing SNS Topic within Trail Configuration
Ensure that your CloudTrail trails are using active Amazon SNS topics.
CloudTrail Bucket MFA Delete Enabled
Ensure CloudTrail logging bucket has a MFA-Delete policy to prevent deletion of logs without an MFA token
CloudTrail Data Events
Ensure CloudTrail trails are configured to log Data events.
CloudTrail Delivery Failing
Ensure Amazon CloudTrail trail log files are delivered as expected.
CloudTrail Enabled
Ensure CloudTrail is enabled in all regions.
CloudTrail Global Services Enabled
Ensure CloudTrail records events for global services such as IAM or AWS STS.
CloudTrail Integrated With CloudWatch
Ensure CloudTrail trails are integrated with CloudWatch Logs.
CloudTrail Log File Integrity Validation
Ensure CloudTrail log file validation is enabled
CloudTrail Logs Encrypted
Ensure CloudTrail logs are encrypted at rest using KMS CMKs.
CloudTrail Management Events
Ensure management events are included into AWS CloudTrail trails configuration.
CloudTrail S3 Bucket
Ensure that AWS CloudTrail trail uses the designated Amazon S3 bucket.
CloudTrail S3 Bucket Logging Enabled
Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket.
Enable Object Lock for CloudTrail S3 Buckets
Ensure that the CloudTrail buckets are using Object Lock for data protection and compliance.
Publicly Accessible CloudTrail Buckets
Ensure that your CloudTrail trail buckets are not publicly accessible.
Amazon CloudWatch
Billing Alarm
Ensure your AWS costs are being monitored using a CloudWatch billing alarm.
Configure ALARM Actions for CloudWatch Alarms
Ensure that CloudWatch alarms have at least one action configured for the ALARM state.
Enable Actions for CloudWatch Alarms
Ensure that Amazon CloudWatch alarm actions are activated (enabled).
Amazon CloudWatch Events
AWS CloudWatch Events In Use
Ensure CloudWatch Events is in use to help you respond to operational changes within your AWS resources.
Event Bus Exposed
Ensure that your AWS CloudWatch event bus is not exposed to everyone.
EventBus Cross Account Access
Ensure that AWS CloudWatch event buses do not allow unknown cross-account access for delivery of events.
Amazon CloudWatch Logs
AWS Config Changes Alarm
Ensure AWS Config configuration changes are being monitored using CloudWatch alarms.
AWS Console Sign In Without MFA
Monitor for AWS Console Sign-In Requests Without MFA
AWS Organizations Changes Alarm
Ensure Amazon Organizations changes are being monitored using AWS CloudWatch alarms.
Authorization Failures Alarm
Ensure a log metric filter and alarm exist for unauthorized API calls.
CMK Disabled or Scheduled for Deletion Alarm
Ensure AWS CMK configuration changes are being monitored using CloudWatch alarms.
CloudTrail Changes Alarm
Ensure all AWS CloudTrail configuration changes are being monitored using CloudWatch alarms.
Console Sign-in Failures Alarm
Ensure your AWS Console authentication process is being monitored using CloudWatch alarms.
Create CloudWatch Alarm for VPC Flow Logs Metric Filter
Ensure that a CloudWatch alarm is created for the VPC Flow Logs metric filter and an alarm action is configured.
EC2 Instance Changes Alarm
Ensure AWS EC2 instance changes are being monitored using CloudWatch alarms.
EC2 Large Instance Changes Alarm
Ensure AWS EC2 large instance changes are being monitored using CloudWatch alarms.
IAM Policy Changes Alarm
Ensure AWS IAM policy configuration changes are being monitored using CloudWatch alarms.
Internet Gateway Changes Alarm
Ensure AWS VPC Customer/Internet Gateway configuration changes are being monitored using CloudWatch alarms.
Metric Filter for VPC Flow Logs CloudWatch Log Group
Ensure that a log metric filter for the CloudWatch group assigned to the VPC Flow Logs is created.
Network ACL Changes Alarm
Ensure AWS Network ACLs configuration changes are being monitored using CloudWatch alarms.
Root Account Usage Alarm
Ensure Root Account Usage is being monitored using CloudWatch alarms.
Route Table Changes Alarm
Ensure AWS Route Tables configuration changes are being monitored using CloudWatch alarms.
S3 Bucket Changes Alarm
Ensure AWS S3 Buckets configuration changes are being monitored using CloudWatch alarms.
Security Group Changes Alarm
Ensure AWS security groups configuration changes are being monitored using CloudWatch alarms.
VPC Changes Alarm
Ensure AWS VPCs configuration changes are being monitored using CloudWatch alarms.
AWS CodeBuild
Amazon Comprehend
Enable Encryption for AWS Comprehend Analysis Job Results
Ensure that AWS Comprehend analysis job results stored in Amazon S3 are encrypted at rest.
AWS Compute Optimizer
Compute Optimizer Auto Scaling Group Findings
Ensure that your Amazon EC2 Auto Scaling groups are optimized for better performance and cost savings.
Compute Optimizer EC2 Instance Findings
Ensure that your Amazon EC2 instances are optimized for better cost and performance.
Compute Optimizer Lambda Function Findings
Ensure that your Amazon Lambda functions are optimized for better performance and cost.
AWS Config
AWS Config Configuration Changes
AWS Config service configuration changes have been detected within your Amazon Web Services account.
AWS Config Enabled
Ensure AWS Config is enabled in all regions to get the optimal visibility of the activity on your account.
AWS Config Global Resources
Ensure Global resources are included into AWS Config service configuration.
AWS Config Referencing Missing S3 Bucket
Ensure AWS Config service is using an active S3 bucket to store configuration changes files.
Config Delivery Failing
Ensure Amazon Config log files are delivered as expected.
AWS ConfigService
AWS Custom Rule
Ensure that all evaluation results returned for your AWS Config rules are compliant.
AWS Cost Explorer
Cost Anomaly Detection Findings
Ensure that unusual AWS spend is analyzed and mitigated using Amazon Cost Anomaly Detection.
Cost Anomaly Detection Monitor in Use
Ensure that a Cost Anomaly Detection monitor is running within your AWS cloud account.
Amazon DynamoDB Accelerator
Cluster Encryption
Ensure DAX clusters enforce Server-Side Encryption.
Amazon Data Lifecycle Manager
Use AWS DLM to Automate EBS Snapshot Lifecycle
Use Amazon Data Lifecycle Manager (DLM) to automate EBS volume snapshots management.
AWS Database Migration Service
DMS Auto Minor Version Upgrade
Ensure that Amazon DMS replication instances have Auto Minor Version Upgrade feature enabled.
DMS Multi-AZ
Ensure that Amazon DMS replication instances have the Multi-AZ feature enabled
DMS Replication Instances Encrypted with KMS CMKs
Ensure that Amazon DMS replication instances are encrypted with KMS Customer Master Keys (CMKs).
Publicly Accessible DMS Replication Instances
Ensure that AWS DMS replication instances are not publicly accessible and prone to security risks.
Amazon DocumentDB
DocumentDB Clusters Encrypted with KMS CMKs
Ensure AWS DocumentDB clusters are encrypted with KMS Customer Master Keys.
DocumentDB Encryption Enabled
Enable encryption at rest for AWS DocumentDB clusters.
DocumentDB Sufficient Backup Retention Period
Ensure that Amazon DocumentDB clusters have set a minimum backup retention period.
Enable Amazon DocumentDB Deletion Protection
Ensure that Deletion Protection feature is enabled for your DocumentDB database clusters.
Enable DocumentDB Profiler
Ensure that the Profiler feature is enabled for your DocumentDB database clusters.
Log Exports
Enable AWS DocumentDB Log Exports.
Rotate SSL/TLS Certificates for DocumentDB Cluster Instances
Ensure that SSL/TLS certificates for DocumentDB database instances are rotated according to the AWS schedule.
Amazon DynamoDB
Configure DynamoDB Table Class for Cost Optimization
Use Amazon DynamoDB Standard-IA table class for cost optimization.
DynamoDB Backup and Restore
Ensure on-demand backup and restore functionality is in use for AWS DynamoDB tables.
DynamoDB Continuous Backups
Enable DynamoDB Continuous Backups
Enable CloudWatch Contributor Insights
Ensure that CloudWatch Contributor Insights is enabled for Amazon DynamoDB tables.
Enable Deletion Protection
Ensure that Deletion Protection feature is enabled for your Amazon DynamoDB tables.
Enable Encryption at Rest with Amazon KMS Keys
Use KMS keys for encryption at rest in Amazon DynamoDB.
Enable Time To Live (TTL)
Ensure that Time To Live (TTL) is enabled for your Amazon DynamoDB tables.
Log DynamoDB Changes using Kinesis Data Streams
Ensure that Amazon DynamoDB changes are logged using Kinesis Data Streams.
Sufficient Backup Retention Period
Ensure that DynamoDB tables have a sufficient backup retention period configured for compliance purposes.
Unused Table
Identify and remove any unused AWS DynamoDB tables to optimize AWS costs.
Amazon Elastic Block Store (EBS)
Amazon EBS Public Snapshots
Ensure that your Amazon EBS volume snapshots are not accessible to all AWS accounts.
App-Tier EBS Encrypted
Ensure app-tier Amazon Elastic Block Store (EBS) volumes are encrypted.
EBS Encrypted
Ensure EBS volumes are encrypted to meet security and encryption compliance requirements. Encryption is a key mechanism for you to ensure that you are in full control over who has access to your data.
EBS Encrypted With KMS Customer Master Keys
Ensure EBS volumes are encrypted with CMKs to have full control over encrypting and decrypting data.
EBS General Purpose SSD
Ensure EC2 instances are using General Purpose SSD (gp2) EBS volumes instead of Provisioned IOPS SSD (io1) volumes to optimize AWS EBS costs.
EBS Snapshot Encrypted
Ensure Amazon EBS snapshots are encrypted to meet security and compliance requirements.
EBS Volume Naming Conventions
Ensure EBS volumes are using proper naming conventions to follow AWS tagging best practices.
EBS Volumes Attached To Stopped EC2 Instances
Identify Amazon EBS volumes attached to stopped EC2 instances (i.e. unused EBS volumes).
EBS Volumes Recent Snapshots
Ensure AWS Elastic Block Store (EBS) volumes have recent snapshots available for point-in-time recovery.
EBS Volumes Too Old Snapshots
Identify and remove old AWS Elastic Block Store (EBS) volume snapshots for cost optimization.
Enable Encryption by Default for EBS Volumes
Ensure that your new Amazon EBS volumes are always encrypted in the specified AWS region.
Idle EBS Volume
Identify idle AWS EBS volumes and delete them in order to optimize your AWS costs.
Unused EBS Volumes
Identify and remove any unused Elastic Block Store volumes to improve cost optimization and security.
Use Customer Master Keys for EBS Default Encryption
Ensure that your new EBS volumes are always encrypted with KMS Customer Master Keys.
Web-Tier EBS Encrypted
Ensure web-tier Amazon Elastic Block Store (EBS) volumes are encrypted.
Amazon EC2
AMI Naming Conventions
Follow proper naming conventions for Amazon Machine Images.
AWS AMI Encryption
Ensure that your existing AMIs are encrypted to meet security and compliance requirements.
Allowed AMIs Feature in Use
Ensure that Allowed AMIs feature is enabled in Amazon EC2.
App-Tier EC2 Instance Using IAM Roles
Ensure that your app-tier EC2 instances are using IAM roles to grant permissions to applications running on these instances.
App-Tier Publicly Shared AMI
Ensure app-tier AMIs aren't publicly shared to avoid exposing sensitive data.
Approved/Golden AMIs
Ensure all EC2 instances are launched from your approved AMIs.
Blocklisted AMIs
Ensure no EC2 instance is launched from any blocklisted AMIs
Check for EC2 Instances with Blocklisted Instance Types
Ensure there is no EC2 instance with the instance type blocklisted, available in your AWS account.
Check for Unrestricted Memcached Access
Ensure that no security group allows unrestricted inbound access on TCP/UDP port 11211 (Memcached).
Check for Unrestricted Redis Access
Ensure that no security group allows unrestricted inbound access on TCP port 6379 (Redis).
Default Security Group Unrestricted
Ensure the default security group of every VPC restricts all traffic.
Default Security Groups In Use
Ensure default security groups aren't in use. Instead create unique security groups to better adhere to the principle of least privilege.
Descriptions for Security Group Rules
Ensure AWS EC2 security group rules have descriptive text for organization and documentation.
Disable Public IP Address Assignment for EC2 Instances
Ensure that Amazon EC2 instances are not using public IP addresses.
EC2 AMI Too Old
Ensure EC2 Amazon Machine Images (AMIs) aren't too old
EC2 Desired Instance Type
Ensure all EC2 instances are of a given instance type.
EC2 Hibernation
Enable hibernation as an additional stop behavior for your EC2 instances backed by Amazon EBS in order to reduce the time it takes for these instances to return to service at restart.
EC2 Instance Counts
Ensure fewer EC2 instances than provided count in your account
EC2 Instance Dedicated Tenancy
Ensure dedicated EC2 instances are regularly reviewed
EC2 Instance Detailed Monitoring
Ensure that detailed monitoring is enabled for the AWS EC2 instances that you need to monitor closely.
EC2 Instance Generation
Ensure you always use the latest generation of EC2 instances to get better performance with lower cost.
EC2 Instance In VPC
Ensure EC2 instances are launched using the EC2-VPC platform instead of EC2-Classic outdated platform.
EC2 Instance Naming Conventions
Follow proper naming conventions for EC2 instances.
EC2 Instance Not In Public Subnet
Ensure that no backend EC2 instances are provisioned in public subnets.
EC2 Instance Scheduled Events
Identify any AWS EC2 instances that have scheduled events and take action to resolve them.
EC2 Instance Security Group Rules Counts
Determine if there is a large number of security group rules applied to an instance.
EC2 Instance Tenancy
Ensure EC2 instances have desired tenancy for compliance and regulatory requirements.
EC2 Instance Termination Protection
Ensure termination protection safety feature is enabled for ec2 instances that aren't part of ASGs
EC2 Instance Too Old
Ensure EC2 instances aren't too old.
EC2 Instance Using IAM Roles
Ensure IAM instance roles are used for AWS resource access from instances.
EC2 Instances Scanned by Amazon Inspector Classic
Ensure that all Amazon EC2 instances are successfully scanned by an Inspector Classic assessment run.
EC2 Instances with Multiple Elastic Network Interfaces
Ensure that Amazon EC2 instances are not using multiple ENIs.
EC2 Instances with Public IP Addresses or Available in Public Subnets
Ensure no backend EC2 instances are running in public subnets or having public IP addresses.
EC2 Reserved Instance Payment Failed
Ensure EC2 Reserved Instances purchases haven't failed.
EC2 Reserved Instance Payment Pending
Ensure EC2 Reserved Instances purchases aren't pending
EC2 Reserved Instance Recent Purchases
Ensure EC2 Reserved Instances purchases are regularly reviewed.
EC2-Classic Elastic IP Address Limit
Determine if the number of allocated EC2-Classic EIPs per region is close to Elastic IP Address Limit.
EC2-VPC Elastic IP Address Limit
Determine if the number of allocated EC2-VPC EIPs per region is close to Elastic IP Address Limit.
Enable Capacity Rebalancing
Ensure that Capacity Rebalancing is enabled for your Amazon Auto Scaling Groups.
Idle EC2 Instance
Identify any Amazon EC2 instances that appear to be idle and stop or terminate them to help lower the cost of your monthly AWS bill.
Instance In Auto Scaling Group
Ensure every EC2 instance is launched inside an Auto Scaling Group (ASG) in order to follow AWS reliability and security best practices.
Overutilized AWS EC2 Instances
Identify any Amazon EC2 instances that appear to be overutilized and upgrade (resize) them in order to help your EC2-hosted applications to handle better the workload and improve the response time.
Publicly Shared AMI
Ensure AMIs aren't publicly shared to avoid exposing sensitive data.
Require IMDSv2 for EC2 Instances
Ensure that all the Amazon EC2 instances require the use of Instance Metadata Service Version 2 (IMDSv2).
Reserved Instance Lease Expiration In The Next 30 Days
Ensure Amazon EC2 Reserved Instances (RI) are renewed before expiration.
Reserved Instance Lease Expiration In The Next 7 Days
Ensure Amazon EC2 Reserved Instances (RI) are renewed before expiration.
Security Group Excessive Counts
Determine if there is an excessive number of security groups per region
Security Group Large Counts
Determine if there is a large number of security groups per region
Security Group Name Prefixed With 'launch-wizard'
Ensure no security group name is prefixed with 'launch-wizard'.
Security Group Naming Conventions
Follow proper naming conventions for security groups
Security Group Port Range
Ensure no security group opens range of ports.
Security Group Rules Counts
Determine if there is a large number of rules in a security group.
SecurityGroup RFC 1918
Ensure no security group contains RFC 1918 CIDRs
Unassociated IP Addresses
Identify and remove any unassociated Elastic IP (EIP) and Carrier IP addresses for cost optimization.
Underutilized EC2 Instance
Identify underutilized EC2 instances and downsize them in order to optimize your AWS costs
Unrestricted CIFS Access
Ensure no security group allows unrestricted inbound access to UDP port 445 (CIFS).
Unrestricted DNS Access
Ensure no security group allows unrestricted ingress access to port 53.
Unrestricted FTP Access
Ensure no security group allows unrestricted inbound access to TCP ports 20 and 21 (FTP).
Unrestricted HTTP Access
Ensure no security group allows unrestricted inbound access to TCP port 80 (HTTP).
Unrestricted HTTPS Access
Ensure no security group allows unrestricted inbound access to TCP port 443 (HTTPS).
Unrestricted ICMP Access
Ensure no security group allows unrestricted inbound access to ICMP.
Unrestricted MongoDB Access
Ensure no security group allows unrestricted ingress access to MongoDB port 27017
Unrestricted MsSQL Access
Ensure no security group allows unrestricted ingress access to port 1433.
Unrestricted MySQL Access
Ensure no security group allows unrestricted ingress access to port 3306.
Unrestricted NetBIOS Access
Ensure no security group allows unrestricted inbound access to port UDP/137, UDP/138, and TPC/139 (NetBIOS).
Unrestricted OpenSearch Access
Ensure no security group allows unrestricted inbound access to TCP port 9200 (OpenSearch).
Unrestricted Oracle Access
Ensure no security group allows unrestricted ingress access to port 1521.
Unrestricted PostgreSQL Access
Ensure no security group allows unrestricted ingress access to port 5432.
Unrestricted RDP Access
Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389.
Unrestricted RPC Access
Ensure no security group allows unrestricted inbound access to TCP port 135 (RPC).
Unrestricted SMTP Access
- Ensure no security group allows unrestricted inbound access to TCP port 25 (SMTP).
Unrestricted SSH Access
Ensure no security groups allow ingress from 0.0.0.0/0 to port 22.
Unrestricted Security Group Egress
Ensure no security group contains any 0.0.0.0/0 egress rules
Unrestricted Security Group Ingress on Uncommon Ports
Ensure no security group contains any 0.0.0.0/0 ingress rules.
Unrestricted Telnet Access
Ensure no security group allows unrestricted inbound access to TCP port 23 (Telnet).
Unused AMI
Identify unused Amazon Machine Images (AMI), and delete them to help lower the cost of your monthly AWS bill.
Unused AWS EC2 Key Pairs
Ensure unused AWS EC2 key pairs are decommissioned to follow AWS security best practices.
Unused EC2 Reserved Instances
Ensure that your Amazon EC2 Reserved Instances are being fully utilized.
Unused Elastic Network Interfaces
Identify and delete any unused Elastic Network Interfaces
Web-Tier EC2 Instance Using IAM Roles
Ensure web-tier IAM instance roles are used for AWS resource access from instances.
Web-Tier Publicly Shared AMI
Ensure web-tier AMIs aren't publicly shared to avoid exposing sensitive data.
vCPU-Based EC2 Instance Limit
Ensure that your EC2 instances do not reach the limit set by AWS for the number of vCPUs.
Amazon Elastic Container Registry
ECR Repository Exposed
Ensure that AWS Elastic Container Registry (ECR) repositories are not exposed to everyone.
Enable Automated Scanning for Amazon ECR Container Images
Ensure that each Amazon ECR container image is automatically scanned for vulnerabilities.
Enable Cross-Region Replication
Ensure that Cross-Region Replication feature is enabled for your Amazon ECR container images.
Lifecycle Policy in Use
Ensure that Amazon ECR image repositories are using lifecycle policies for cost optimization.
Repository Cross Account Access
Ensure that Amazon ECR repositories do not allow unknown cross account access.
Amazon Elastic Container Service (ECS)
Amazon ECS Task Log Driver in Use
Ensure that a log driver has been defined for each active Amazon ECS task definition.
Check for Amazon ECS Service Placement Strategy
Ensure that your Amazon ECS cluster services are using optimal placement strategies.
Check for ECS Container Instance Agent Version
Ensure that your Amazon ECS instances are using the latest ECS container agent version.
Check for Fargate Platform Version
Ensure that your Amazon ECS cluster services are using the latest Fargate platform version.
Enable CloudWatch Container Insights
Ensure that CloudWatch Container Insights feature is enabled for your AWS ECS clusters.
Monitor Amazon ECS Configuration Changes
Amazon Elastic Container Service (ECS) configuration changes have been detected in your AWS account.
Amazon Elastic File System (EFS)
AWS KMS Customer Master Keys for EFS Encryption
Ensure EFS file systems are encrypted with KMS Customer Master Keys (CMKs) in order to have full control over data encryption and decryption.
EFS Encryption Enabled
Ensure encryption is enabled for AWS EFS file systems to protect your data at rest.
Amazon Elastic Kubernetes Service (EKS)
Check for the CoreDNS Add-On Version
Ensure that the CoreDNS add-on version matches the EKS cluster's Kubernetes version.
Disable Remote Access to EKS Cluster Node Groups
Ensure that remote access to EKS cluster node groups is disabled.
EKS Cluster Endpoint Public Access
Ensure that AWS EKS cluster endpoint access isn't public and prone to security risks.
EKS Cluster Node Group IAM Role Policies
Ensure that EKS Cluster node groups are using appropriate permissions.
EKS Security Groups
Ensure that AWS EKS security groups are configured to allow incoming traffic only on TCP port 443.
Enable CloudTrail Logging for Kubernetes API Calls
Ensure that all Kubernetes API calls are logged using Amazon CloudTrail.
Enable Cluster Access Management API
Ensure that Cluster Access Management API is enabled for Amazon EKS clusters.
Enable Envelope Encryption for EKS Kubernetes Secrets
Ensure that envelope encryption of Kubernetes secrets using Amazon KMS is enabled.
Enable Support for Network Policies
Ensure that EKS clusters are using network policies for proper segmentation and security.
Kubernetes Cluster Logging
Ensure that EKS control plane logging is enabled for your Amazon EKS clusters.
Kubernetes Cluster Version
Ensure that the latest version of Kubernetes is installed on your Amazon EKS clusters.
Monitor Amazon EKS Configuration Changes
Amazon EKS configuration changes have been detected within your Amazon Web Services account.
Use AWS-managed policy to Manage Networking Resources
Ensure that EKS cluster node groups implement the "AmazonEKS_CNI_Policy" managed policy.
Use AWS-managed policy to access Amazon ECR Repositories
Ensure that EKS cluster node groups implement the "AmazonEC2ContainerRegistryReadOnly" managed policy.
Use AWS-managed policy to manage AWS resources
Ensure that Amazon EKS clusters implement the "AmazonEKSClusterPolicy" managed policy.
Use OIDC Provider for Authenticating Kubernetes API Calls
Ensure that Amazon EKS clusters are using an OpenID Connect (OIDC) provider.
Elastic Load Balancing
App-Tier ELB Listener Security
Ensure app-tier ELB listener uses a secure HTTPS or SSL protocol.
App-Tier ELB Security Policy
Ensure app-tier ELBs use the latest predefined security policies.
App-Tier ELBs Health Check
Ensure app tier Elastic Load Balancer has application layer health check configured.
Classic Load Balancer
Ensure HTTP/HTTPS applications are using Application Load Balancer instead of Classic Load Balancer for cost and web traffic distribution optimization.
Configure HTTP Desync Mitigation Mode for Classic Load Balancers
Ensure that the suitable Desync Mitigation mode is configured for your Classic Load Balancers.
ELB Access Log
Ensure ELB access logging is enabled for security, troubleshooting, and statistical analysis purposes
ELB Connection Draining Enabled
Ensure connection draining is enabled for all load balancers.
ELB Cross-Zone Load Balancing Enabled
Ensure Cross-Zone Load Balancing is enabled for all load balancers. Also select at least two subnets in different availability zones to provide higher availability.
ELB Insecure SSL Ciphers
Ensure ELBs don't use insecure SSL ciphers.
ELB Insecure SSL Protocols
Ensure ELBs don't use insecure SSL protocols.
ELB Instances Distribution Across AZs
Ensure even distribution of backend instances registered to an ELB across Availability Zones.
ELB Listener Security
Ensure ELB listener uses a secure HTTPS or SSL protocol.
ELB Minimum Number Of EC2 Instances
Ensure there is a minimum number of two healthy backend instances associated with each ELB.
ELB Security Group
Check your Elastic Load Balancer (ELB) security layer for at least one valid security group that restricts access only to the ports defined in the load balancer listener's configuration
ELB Security Policy
Ensure ELBs use the latest predefined security policies.
Idle Elastic Load Balancer
Identify idle Elastic Load Balancers (ELBs) and terminate them in order to optimize AWS costs.
Internet Facing ELBs
Ensure Amazon internet-facing ELBs/ALBs are regularly reviewed for security purposes.
Unused Elastic Load Balancers
Identify unused Elastic Load Balancers, and delete them to help lower the cost of your monthly AWS bill.
Web-Tier ELB Listener Security
Ensure web-tier ELB listener uses a secure HTTPS or SSL protocol.
Web-Tier ELB Security Policy
Ensure web-tier ELBs use the latest predefined security policies.
Web-Tier ELBs Health Check
Ensure web tier Elastic Load Balancer has application layer health check configured.
Elastic Load Balancing V2
Configure HTTP Desync Mitigation Mode for Application Load Balancers
Ensure that the suitable Desync Mitigation mode is configured for your Application Load Balancers.
Configure Multiple Availability Zones for Gateway Load Balancers
Ensure that Amazon Gateway Load Balancers are using Multi-AZ configurations.
Drop Invalid Header Fields for Application Load Balancers
Ensure that Drop Invalid Header Fields feature is enabled for your Application Load Balancers to remove non-standard headers.
ELBv2 ALB Listener Security
Ensure ELBv2 ALBs are using a secure protocol.
ELBv2 ALB Security Group
Ensure ELBv2 load balancers have secure and valid security groups.
ELBv2 ALB Security Policy
Ensure that Amazon ALBs are using the latest predefined security policy for their SSL negotiation configuration in order to follow security best practices and protect their front-end connections against SSL/TLS vulnerabilities.
ELBv2 Access Log
Ensure that Amazon ALBs have Access Logging feature enabled for security, troubleshooting and statistical analysis purposes.
ELBv2 Elastic Load Balancing Deletion Protection
Ensure ELBv2 Load Balancers have Deletion Protection feature enabled in order to protect them from being accidentally deleted.
ELBv2 Minimum Number of EC2 Target Instances
Ensure there is a minimum number of two healthy target instances associated with each AWS ELBv2 load balancer.
ELBv2 NLB Listener Security
Ensure that your AWS Network Load Balancer listeners are using a secure protocol such as TLS.
Enable Amazon WAF Integration for Application Load Balancers
Use Amazon WAF to protect Application Load Balancers from common web exploits.
Enable Cross-Zone Load Balancing
Ensure fault tolerance for your Amazon Gateway Load Balancers by enabling Cross-Zone Load Balancing.
Enable Deletion Protection
Ensure that Deletion Protection is enabled for Amazon Gateway Load Balancers.
Enable HTTP to HTTPS Redirect for Application Load Balancers
Ensure that your Application Load Balancers have a rule that redirects HTTP traffic to HTTPS.
Enable Least Outstanding Requests Algorithm
Ensure that Least Outstanding Requests (LOR) algorithm is enabled for your AWS Application Load Balancers (ALBs).
Enable Support for HTTP/2
Ensure that HTTP/2 support is enabled for Amazon Application Load Balancers (ALBs).
Enable Support for gRPC Protocol
Ensure that support for gRPC protocol is enabled for Application Load Balancers (ALBs).
Enable TLS ALPN Policy for Network Load Balancers
Ensure that your AWS Network Load Balancers are using TLS ALPN policies.
Internet Facing ELBv2 Load Balancers
Ensure Amazon internet-facing ELBv2 Load Balancers are regularly reviewed for security purposes.
Network Load Balancer Security Policy
Ensure Amazon Network Load Balancers (NLBs) are using the latest recommended predefined security policy for TLS negotiation configuration.
Unused ELBv2 Load Balancers
Identify unused ELBv2 Elastic Load Balancers, and delete them to help lower the cost of your monthly AWS bill.
Amazon EMR
AWS EMR Instance Type Generation
Ensure AWS EMR clusters are using the latest generation of instances for performance and cost optimization.
Block Public Access to Amazon EMR Clusters
Enable the Block Public Access feature for Amazon EMR clusters in the specified AWS region.
Cluster in VPC
Ensure that your Amazon Elastic MapReduce clusters are provisioned using the AWS EC2-VPC platform instead of EC2-Classic platform.
EMR Cluster Logging
Ensure AWS Elastic MapReduce clusters capture detailed log data to Amazon S3.
EMR Desired Instance Type
Ensure that all your Amazon EMR cluster instances are of given instance types.
EMR In-Transit and At-Rest Encryption
Ensure that your AWS Elastic MapReduce clusters are encrypted in order to meet security and compliance requirements.
EMR Instances Counts
Ensure fewer Amazon EMR cluster instances than the provided limit in your AWS account.
Use Customer Master Keys for EMR Log Files Encryption
Ensure that Amazon EMR log files are encrypted with KMS Customer Master Keys (CMKs).
Amazon ElastiCache
Configure Preferred Maintenance Window for ElastiCache Clusters
Ensure there is a preferred maintenance window configured for your Amazon ElastiCache clusters.
ElastiCache Cluster Default Port
Ensure that AWS ElastiCache clusters aren't using their default endpoint ports.
ElastiCache Cluster In VPC
Ensure Amazon ElastiCache clusters are deployed into a Virtual Private Cloud.
ElastiCache Desired Node Type
Ensure that all your Amazon ElastiCache cluster cache nodes are of given types.
ElastiCache Engine Version
Ensure that your Amazon ElastiCache clusters are using the stable latest version of Redis/Memcached cache engine.
ElastiCache Instance Generation
Ensure ElastiCache clusters are using the latest generation of nodes for cost and performance improvements.
ElastiCache Nodes Counts
Ensure your AWS account hasn't reached the limit set for the number of ElastiCache cluster nodes.
ElastiCache Redis In-Transit and At-Rest Encryption
Ensure that your AWS ElastiCache Redis clusters are encrypted in order to meet security and compliance requirements.
ElastiCache Redis Multi-AZ
Ensure Amazon ElastiCache Redis clusters have the Multi-AZ feature enabled.
ElastiCache Reserved Cache Node Coverage
Ensure that your Amazon ElastiCache usage is covered by ElastiCache cluster node reservations.
ElastiCache Reserved Cache Node Lease Expiration In The Next 30 Days
Ensure Amazon ElastiCache Reserved Cache Nodes (RCN) are renewed before expiration.
ElastiCache Reserved Cache Node Lease Expiration In The Next 7 Days
Ensure Amazon ElastiCache Reserved Cache Nodes (RCN) are renewed before expiration.
ElastiCache Reserved Cache Node Payment Failed
Ensure AWS ElastiCache Reserved Node purchases have not failed.
ElastiCache Reserved Cache Node Payment Pending
Ensure AWS ElastiCache Reserved Node purchases are not pending.
ElastiCache Reserved Cache Node Recent Purchases
Ensure ElastiCache Reserved Cache Node purchases are regularly reviewed for cost optimization (informational).
ElastiCache Reserved Cache Nodes Expiration
Ensure that Amazon ElastiCache Reserved Nodes are renewed before expiration.
Enable Automatic Backups
Ensure that automatic backups are enabled for Amazon ElastiCache Redis cache clusters.
Enable Event Notifications
Ensure that event notifications via Amazon SNS are enabled for Amazon ElastiCache clusters.
Idle AWS ElastiCache Nodes
Identify any idle AWS ElastiCache nodes and terminate them in order to optimize your AWS costs.
Sufficient Backup Retention Period
Ensure that Redis cache clusters have a sufficient backup retention period configured for compliance purposes.
Unused ElastiCache Reserved Cache Nodes
Ensure that your ElastiCache Reserved Cache Nodes are being utilized.
AWS Elastic Beanstalk
Elastic Beanstalk Enhanced Health Reporting
Ensure Enhanced Health Reporting is enabled for your AWS Elastic Beanstalk environment(s).
Elastic Beanstalk Managed Platform Updates
Ensure managed platform updates are enabled for your AWS Elastic Beanstalk environment(s).
Elastic Beanstalk Persistent Logs
Ensure persistent logs are enabled for your Amazon Elastic Beanstalk environment(s).
Enable AWS X-Ray Daemon
Ensure that X-Ray tracing is enabled for your Amazon Elastic Beanstalk environments.
Enable Access Logs
Ensure that access logging is enabled for your Elastic Beanstalk environment load balancer.
Enable Elastic Beanstalk Environment Notifications
Enable alert notifications for important events triggered within your Amazon Elastic Beanstalk environment.
Enforce HTTPS
Enforce HTTPS for Amazon Elastic Beanstalk environment load balancers.
Amazon Opensearch Service
AWS OpenSearch Slow Logs
Ensure that your AWS OpenSearch domains publish slow logs to AWS CloudWatch Logs.
Check for IP-Based Access
Ensure that only approved IP addresses can access your Amazon OpenSearch domains.
Cluster Status
Ensure that your Amazon OpenSearch clusters are healthy (Green).
Enable Audit Logs
Ensure that audit logging is enabled for all your Amazon OpenSearch domains.
Enable In-Transit Encryption
Ensure that in-transit encryption is enabled for your Amazon OpenSearch domains.
Encryption At Rest
Ensure that your Amazon OpenSearch domains are encrypted in order to meet security and compliance requirements.
Idle OpenSearch Domains
Identify idle Amazon OpenSearch domains and delete them in order to optimize AWS costs.
OpenSearch Accessible Only From Safelisted IP Addresses
Ensure only safelisted IP addresses can access your Amazon OpenSearch domains.
OpenSearch Cross Account Access
Ensure Amazon OpenSearch clusters don't allow unknown cross account access.
OpenSearch Dedicated Master Enabled
Ensure Amazon OpenSearch clusters are using dedicated master nodes to increase the production environment stability.
OpenSearch Desired Instance Type(s)
Ensure that Amazon OpenSearch cluster instances are of given instance type.
OpenSearch Domain Exposed
Ensure Amazon OpenSearch domains aren't exposed to everyone.
OpenSearch Domain In VPC
Ensure that your Amazon OpenSearch domains are accessible only from AWS VPCs.
OpenSearch Domains Encrypted with KMS CMKs
Ensure that your OpenSearch domains are encrypted using KMS Customer-Managed Keys.
OpenSearch Free Storage Space
Identify OpenSearch clusters with low free storage space and scale them to optimize their performance.
OpenSearch General Purpose SSD
Ensure OpenSearch nodes are using General Purpose SSD storage instead of Provisioned IOPS SSD storage to optimize the service costs.
OpenSearch Node To Node Encryption
Ensure that your Amazon OpenSearch clusters are using node to node encryption in order to meet security and compliance requirements.
OpenSearch Reserved Instance Coverage
Ensure that your Amazon OpenSearch usage is covered by RI reservations in order to optimize AWS costs.
OpenSearch Reserved Instance Lease Expiration In The Next 30 Days
Ensure Amazon OpenSearch Reserved Instances are renewed before expiration.
OpenSearch Reserved Instance Lease Expiration In The Next 7 Days
Ensure that Amazon OpenSearch Reserved Instances are renewed before expiration.
OpenSearch Version
Ensure that the latest version of OpenSearch engine is used for your OpenSearch domains.
OpenSearch Zone Awareness Enabled
Ensure high availability for your Amazon OpenSearch clusters by enabling the Zone Awareness feature.
Reserved Instance Payment Pending Purchases
Ensure that none of your Amazon OpenSearch Reserved Instance purchases are pending.
Reserved Instance Purchase State
Ensure that none of your Amazon OpenSearch Reserved Instance purchases have been failed.
Review Reserved Instance Purchases
Ensure that OpenSearch Reserved Instance purchases are regularly reviewed for cost optimization (informational).
TLS Security Policy Version
Ensure that your OpenSearch domains are using the latest version of the TLS security policy.
Total Number of OpenSearch Cluster Nodes
Ensure there are fewer OpenSearch cluster nodes than the established limit
Amazon FSx
Use KMS Customer Master Keys for FSx Windows File Server File Systems
Ensure AWS FSx for Windows File Server file systems data is encrypted using AWS KMS CMKs.
Amazon Kinesis Data Firehose
Enable Firehose Delivery Stream Server-Side Encryption
Ensure that Kinesis Data Firehose delivery streams enforce Server-Side Encryption, ideally using Customer-managed Customer Master Keys.
Firehose Delivery Stream Destination Encryption
Ensure that Firehose delivery stream data records are encrypted at destination.
AWS Glue
CloudWatch Logs Encryption Mode
Ensure that at-rest encryption is enabled when writing Amazon Glue logs to CloudWatch Logs.
Glue Data Catalog Encrypted With KMS Customer Master Keys
Ensure that Amazon Glue Data Catalogs enforce data-at-rest encryption using KMS CMKs.
Glue Data Catalog Encryption At Rest
Ensure that Amazon Glue Data Catalog objects and connection passwords are encrypted.
Job Bookmark Encryption Mode
Ensure that encryption at rest is enabled for Amazon Glue job bookmarks.
S3 Encryption Mode
Ensure that at-rest encryption is enabled when writing AWS Glue data to Amazon S3.
Amazon Guard​Duty
AWS GuardDuty Configuration Changes
GuardDuty configuration changes have been detected within your Amazon Web Services account.
Enable Malware Protection for Amazon EC2
Ensure that Amazon GuardDuty detectors are configured to use Malware Protection for EC2.
Enable Malware Protection for Amazon S3
Ensure that Amazon GuardDuty detectors are configured to use Malware Protection for S3.
Enable S3 Protection
Ensure that Amazon GuardDuty detectors are configured to use S3 Protection.
GuardDuty Enabled
Ensure Amazon GuardDuty is enabled to help you protect your AWS accounts and workloads against security threats.
GuardDuty Findings
Ensure that Amazon GuardDuty findings are highlighted, audited and resolved.
AWS Health
Health Events
Provides real-time insights into the state of your AWS environment and infrastructure.
AWS Identity and Access Management (IAM)
AWS Account Root User Activity
Monitor AWS Account Root User Activity
AWS IAM Server Certificate Size
Ensure that all your SSL/TLS certificates are using either 2048 or 4096 bit RSA keys instead of 1024-bit keys.
AWS Multi-Account Centralized Management
Set up, organize and manage your AWS accounts for optimal security and manageability.
Access Keys During Initial IAM User Setup
Ensure no access keys are created during IAM user initial setup with AWS Management Console.
Access Keys Rotated 30 Days
Ensure AWS IAM access keys are rotated on a periodic basis as a security best practice (30 Days).
Access Keys Rotated 45 Days
Ensure AWS IAM access keys are rotated on a periodic basis as a security best practice (45 Days).
Access Keys Rotated 90 Days
Ensure AWS IAM access keys are rotated on a periodic basis as a security best practice (90 Days).
Account Alternate Contacts
Ensure alternate contacts are set to improve the security of your AWS account.
Account Security Challenge Questions
Ensure security challenge questions are enabled and configured to improve the security of your AWS account.
Allow IAM Users to Change Their Own Password
Ensure that all IAM users are allowed to change their own console password.
Amazon EC2 Purchase Restriction
Restrict unintended IAM users from purchasing Amazon EC2 Reserved Instances and/or Savings Plans.
Approved ECS Execute Command Access
Ensure that all access to the ECS Execute Command action is approved
Attach Policy to IAM Roles Associated with App-Tier EC2 Instances
Ensure IAM policy for EC2 IAM roles for app tier is configured.
Attach Policy to IAM Roles Associated with Web-Tier EC2 Instances
Ensure IAM policy for EC2 IAM roles for web tier is configured.
Canary Access Token
Detects when a canary token access key has been used
Check for IAM User Group Membership
Ensure that all Amazon IAM users have group memberships.
Check for IAM Users with Compromised Credentials
Identify IAM users with compromised credentials by checking for the presence of "AWSCompromisedKeyQuarantine" policies.
Check for Individual IAM Users
Ensure there is at least one IAM user used to access your AWS cloud account.
Check for Overly Permissive IAM Group Policies
Ensure that Amazon IAM policies attached to IAM groups aren't too permissive.
Check for Untrusted Cross-Account IAM Roles
Ensure that AWS IAM roles cannot be used by untrusted accounts via cross-account access feature.
Check that only safelisted IAM Users exist
Ensure that only safelisted IAM Users exist within your AWS account.
Credentials Last Used
Ensure that unused AWS IAM credentials are decommissioned to follow security best practices.
Cross-Account Access Lacks External ID and MFA
Ensure cross-account access roles are using Multi-Factor Authentication (MFA) or External IDs.
Enable MFA for IAM Users with Console Password
Ensure that Multi-Factor Authentication (MFA) is enabled for all Amazon IAM users with console access.
Enforce Infrastructure as Code using IAM Policies
Enforce Infrastructure as Code by controlling access for requests made on your behalf.
Expired SSL/TLS Certificate
Ensure expired SSL/TLS certificates are removed from AWS IAM.
Hardware MFA for AWS Root Account
Ensure hardware MFA is enabled for the 'root' account.
IAM Access Analyzer in Use
Ensure that IAM Access Analyzer feature is enabled to maintain access security to your AWS resources.
IAM Configuration Changes
AWS IAM configuration changes have been detected within your Amazon Web Services account.
IAM CreateLoginProfile detected
AWS IAM 'CreateLoginProfile' call has been detected within your Amazon Web Services account.
IAM Group With Inline Policies
Ensure IAM groups don't have inline policies attached.
IAM Groups with Administrative Privileges
Ensure there are no IAM groups with administrative permissions available in your AWS cloud account.
IAM Master and IAM Manager Roles (Deprecated)
Ensure that IAM Master and IAM Manager roles are active in your AWS cloud account.
IAM Password Policy
Ensure that your AWS cloud account has a strong IAM password policy in use.
IAM Policies With Full Administrative Privileges
Ensure IAM policies that allow full '*:*' administrative privileges aren't created.
IAM Policies with Effect Allow and NotAction
Ensure that IAM policies do not use "Effect": "Allow" in combination with "NotAction" element to follow IAM security best practices.
IAM Role Policy Too Permissive
Ensure that the access policies attached to your IAM roles adhere to the principle of least privilege.
IAM Roles Should Not be Assumed by Multiple Services
Ensure that Amazon IAM roles can only be assumed by a single, trusted service.
IAM Support Role
Ensure there is an active IAM Support Role available within your AWS cloud account.
IAM User Password Expiry 30 Days
Ensure AWS Identity and Access Management (IAM) user passwords are reset before expiration (30 Days).
IAM User Password Expiry 45 Days
Ensure AWS Identity and Access Management (IAM) user passwords are reset before expiration (45 Days).
IAM User Password Expiry 7 Days
Ensure AWS Identity and Access Management (IAM) user passwords are reset before expiration (7 Days).
IAM User Policies
Ensure AWS IAM policies are attached to groups instead of users as an IAM best practice.
IAM User with Password and Access Keys
Ensure that IAM users have either API access or console access in order to follow IAM security best practices.
IAM Users Unauthorized to Edit Access Policies
Ensure AWS IAM users that are not authorized to edit IAM access policies are decommissioned..
IAM Users with Administrative Privileges
Ensure there are no IAM users with administrative permissions available in your AWS cloud account.
Inactive IAM Console User
Ensure no AWS IAM users have been inactive for a long (specified) period of time.
MFA Device Deactivated
A Multi-Factor Authentication (MFA) device deactivation for an IAM user has been detected.
Pre-Heartbleed Server Certificates
Ensure that your server certificates are not vulnerable to Heartbleed security bug.
Prevent IAM Role Chaining
Ensure that IAM Role Chaining is not used within your AWS environment.
Receive Permissions via IAM Groups Only
Ensure that IAM users receive permissions only through IAM groups.
Root Account Access Keys Present
Ensure that your AWS root account is not using access keys as a security best practice.
Root Account Active Signing Certificates
Ensure that your AWS root account user is not using X.509 certificates to validate API requests.
Root Account Credentials Usage
Ensure that root account credentials have not been used recently to access your AWS account.
Root MFA Enabled
Ensure that Multi-Factor Authentication (MFA) is enabled for your AWS root account.
SSH Public Keys Rotated 30 Days
Ensure AWS IAM SSH public keys are rotated on a periodic basis as a security best practice.
SSH Public Keys Rotated 45 Days
Ensure IAM SSH public keys are rotated on a periodic basis to adhere to AWS security best practices.
SSH Public Keys Rotated 90 Days
Ensure IAM SSH public keys are rotated on a periodic basis to adhere to AWS security best practices.
SSL/TLS Certificate Expiry 30 Days
Ensure SSL/TLS certificates are renewed before their expiration.
SSL/TLS Certificate Expiry 45 Days
Ensure SSL/TLS certificates are renewed before their expiration.
SSL/TLS Certificate Expiry 7 Days
Ensure SSL/TLS certificates are renewed before their expiration.
Sign-In Events
AWS sign-in events for IAM and federated users have been detected.
Unapproved IAM Policy in Use
Ensure there are no unapproved AWS Identity and Access Management (IAM) policies in use.
Unnecessary Access Keys
Ensure there is a maximum of one active access key pair available for any single IAM user.
Unnecessary IAM Users
Require your human users to use temporary credentials instead of long-term credentials when accessing AWS cloud.
Unnecessary SSH Public Keys
Ensure there is a maximum of one active SSH public keys assigned to any single IAM user.
Unused IAM Group
Ensure all IAM groups have at least one user.
Unused IAM User
Ensure unused IAM users are removed from AWS account to follow security best practice.
Valid IAM Identity Providers
Ensure valid IAM Identity Providers are used within your AWS account for secure user authentication and authorization.
Amazon Inspector
Amazon Inspector Findings
Ensure that Amazon Inspector Findings are analyzed and resolved.
Check for Amazon Inspector Exclusions
Ensure there are no exclusions found by Amazon Inspector assessment runs.
Days since last Amazon Inspector run
Ensure that Amazon Inspector runs occur every n days.
Amazon Inspector 2
Check for Amazon Inspector v2 Findings
Ensure that Amazon Inspector v2 findings are analyzed and resolved.
Enable Amazon Inspector 2
Ensure that Amazon Inspector 2 is enabled for your AWS cloud environment.
AWS Key Management Service
App-Tier KMS Customer Master Key (CMK) In Use
Ensure a customer created Customer Master Key (CMK) is created for the app tier.
Database-Tier KMS Customer Master Key (CMK) In Use
Ensure a customer created Customer Master Key (CMK) is created for the database tier.
Existence of Specific AWS KMS CMKs
Ensure that specific Amazon KMS CMKs are available for use in your AWS account.
KMS Cross Account Access
Ensure Amazon KMS master keys don't allow unknown cross account access.
KMS Customer Master Key (CMK) In Use
Ensure KMS Customer Master Key (CMK) is in use to have full control over encrypting and decrypting data.
KMS Customer Master Key Pending Deletion
Identify and recover any KMS Customer Master Keys (CMK) scheduled for deletion.
Key Exposed
Ensure Amazon KMS master keys aren't exposed to everyone.
Key Rotation Enabled
Ensure that automatic rotation for Customer Managed Keys (CMKs) is enabled.
Monitor AWS KMS Configuration Changes
Key Management Service (KMS) configuration changes have been detected within your AWS account.
Unused Customer Master Key
Identify unused customer master keys, and delete them to help lower the cost of your monthly AWS bill.
Web-Tier KMS Customer Master Key (CMK) In Use
Ensure a customer created Customer Master Key (CMK) is created for the web tier.
Amazon Kinesis
Kinesis Server Side Encryption
Ensure Amazon Kinesis streams enforce Server-Side Encryption (SSE).
Kinesis Stream Encrypted With CMK
Ensure AWS Kinesis streams are encrypted with KMS Customer Master Keys for complete control over data encryption and decryption.
Kinesis Stream Shard Level Metrics
Ensure enhanced monitoring is enabled for your AWS Kinesis streams using shard-level metrics.
AWS Lambda
Check Lambda Function URL Not in Use
Check your Amazon Lambda functions are not using function URLs.
Check for Missing Execution Role
Ensure that Amazon Lambda functions are referencing active execution roles.
Enable Code Signing
Ensure that Code Signing is enabled for Amazon Lambda functions.
Enable Dead Letter Queue for Lambda Functions
Ensure there is a Dead Letter Queue configured for each Lambda function available in your AWS account.
Enable Encryption at Rest for Environment Variables using Customer Master Keys
Ensure that Lambda environment variables are encrypted at rest with Customer Master Keys (CMKs) to gain full control over data encryption/decryption
Enable Encryption in Transit for Environment Variables
Ensure that encryption in transit is enabled for the Lambda environment variables that store sensitive information.
Enable Encryption in Transit for Environment Variables
Ensure that encryption in transit is enabled for the Lambda environment variables that store sensitive information.
Enable Enhanced Monitoring for Lambda Functions
Ensure that your Amazon Lambda functions are configured to use enhanced monitoring.
Enable IAM Authentication for Lambda Function URLs
Ensure that IAM authorization is enabled for your Lambda function URLs.
Enable and Configure Provisioned Concurrency
Ensure that your Amazon Lambda functions are configured to use provisioned concurrency.
Enable and Configure Reserved Concurrency
Ensure that your Amazon Lambda functions are configured to use reserved concurrency.
Function Exposed
Ensure that your Amazon Lambda functions aren't exposed to everyone.
Function in Private Subnet
Ensure that your Amazon Lambda functions are configured to use private subnets.
Lambda Cross Account Access
Ensure AWS Lambda functions don't allow unknown cross account access via permission policies.
Lambda Function Execution Roles with Inline Policies
Ensure that IAM execution roles configured for Lambda functions are not using inline policies.
Lambda Function With Admin Privileges
Ensure no Lambda function available in your AWS account has admin privileges.
Lambda Functions Should not Share Roles that Contain Admin Privileges
Ensure that Amazon Lambda functions don't share roles that have admin privileges.
Lambda Using Latest Runtime Environment
Ensure that the latest version of the runtime environment is used for your AWS Lambda functions.
Lambda Using Supported Runtime Environment
Ensure the AWS Lambda function runtime version is currently supported.
Tracing Enabled
Ensure that tracing (Lambda support for Amazon X-Ray service) is enabled for your AWS Lambda functions.
Use AWS-Managed Policies for Lambda Function Execution Roles
Ensure that IAM execution roles configured for Lambda functions are using AWS-managed policies.
Use Customer-Managed Policies for Lambda Function Execution Roles
Ensure that IAM execution roles configured for Lambda functions are using customer-managed policies.
Using An IAM Role For More Than One Lambda Function
Ensure that Lambda functions don't share the same IAM execution role.
VPC Access for AWS Lambda Functions
Ensure that your Amazon Lambda functions have access to VPC-only resources.
Amazon MQ
MQ Auto Minor Version Upgrade
Ensure Auto Minor Version Upgrade is enabled for MQ to automatically receive minor engine upgrades during the maintenance window.
MQ Deployment Mode
Ensure MQ brokers are using the active/standby deployment mode for high availability.
MQ Desired Broker Instance Type
Ensure that all your Amazon MQ broker instances are of a given type.
MQ Engine Version
Ensure that the latest version of Apache ActiveMQ engine is used for your AWS MQ brokers.
MQ Log Exports
Ensure that your Amazon MQ brokers have Log Exports feature enabled.
MQ Network of Brokers
Ensure that Amazon MQ brokers are using the network of brokers configuration.
Publicly Accessible MQ Brokers
Ensure AWS MQ brokers aren't publicly accessible in order to avoid exposing sensitive data and minimize security risks.
Amazon Managed Streaming for Apache Kafka
Enable Apache Kafka Latest Security Features
Ensure access to the latest security features in Amazon MSK clusters.
Enable Enhanced Monitoring for Apache Kafka Brokers
Ensure that enhanced monitoring of Apache Kafka brokers using Amazon CloudWatch is enabled.
Enable In-Transit Encryption
Ensure that in-transit encryption is enabled for Amazon MSK clusters to protect against eavesdropping.
Enable MSK Cluster Encryption at Rest using CMK
Ensure that your Amazon MSK clusters are encrypted using KMS Customer Master Keys.
Enable Mutual TLS Authentication for Kafka Clients
Ensure that only trusted clients can connect to your Amazon MSK clusters using TLS certificates.
Publicly Accessible Clusters
Ensure that Amazon MSK clusters are not publicly accessible and prone to security risks.
Unrestricted Access to Apache Kafka Brokers
Ensure that unrestricted access to the Apache Kafka brokers is disabled.
Amazon Macie
Amazon Macie In Use
Ensure AWS Macie is in use to protect your sensitive and business-critical data.
AWS Macie v2
Amazon Macie Discovery Jobs
Ensure that Amazon Macie data discovery jobs are created and configured within each AWS region.
Amazon Macie Findings
Ensure that Amazon Macie security findings are highlighted, analyzed, and resolved.
Amazon Macie Sensitive Data Repository
Ensure that a data repository bucket is defined for Amazon Macie within each AWS region.
Compliance and Certifications
Amazon Neptune
IAM Database Authentication for Neptune
Ensure IAM Database Authentication feature is enabled for Amazon Neptune clusters.
Neptune Auto Minor Version Upgrade
Ensure Amazon Neptune instances have Auto Minor Version Upgrade feature enabled.
Neptune Database Backup Retention Period
Ensure AWS Neptune clusters have a sufficient backup retention period set for compliance purposes.
Neptune Database Encrypted With KMS Customer Master Keys
Ensure that AWS Neptune instances enforce data-at-rest encryption using KMS CMKs.
Neptune Database Encryption Enabled
Ensure that Amazon Neptune graph database instances are encrypted.
Neptune Desired Instance Type
Ensure that all your Amazon Neptune database instances are of a given type.
Neptune Multi-AZ
Ensure that Amazon Neptune database clusters have the Multi-AZ feature enabled.
AWS Network Firewall
AWS Network Firewall in Use
Ensure that your Amazon VPCs are using AWS Network Firewall.
Enable Deletion Protection for Network Firewalls
Ensure that Deletion Protection feature is enabled for your VPC network firewalls.
AWS Organizations
AWS Organizations Configuration Changes
AWS Organizations configuration changes have been detected within your Amazon Web Services account(s).
AWS Organizations In Use
Ensure Amazon Organizations is in use to consolidate all your AWS accounts into an organization.
Enable All Features
Ensure AWS Organizations All Features is enabled for fine-grained control over which services and actions the member accounts of an organization can access.
Enable Resource Control Policies (RCPs) for AWS Organizations
Ensure that Resource Control Policies (RCPs) are enabled for AWS Organizations.
Amazon Relational Database Service
Amazon RDS Configuration Changes
Amazon Relational Database Service (RDS) configuration changes have been detected in your AWS account.
Amazon RDS Public Snapshots
Ensure that your Amazon RDS database snapshots are not accessible to all AWS accounts.
Aurora Database Cluster Activity Streams
Ensure that Amazon Aurora clusters are configured to use database activity streams.
Aurora Database Instance Accessibility
Ensure that all database instances within an Amazon Aurora cluster have the same accessibility.
Backtrack
Enable Amazon Aurora Backtrack.
Cluster Deletion Protection
Enable AWS RDS Cluster Deletion Protection.
DB Instance Generation
Ensure you always use the latest generation of DB instances to get better performance with lower cost.
Enable AWS RDS Transport Encryption
Ensure AWS RDS SQL Server and Postgre instances have Transport Encryption feature enabled.
Enable Aurora Cluster Copy Tags to Snapshots
Ensure that Amazon Aurora clusters have Copy Tags to Snapshots feature enabled.
Enable Deletion Protection for Aurora Serverless Clusters
Ensure that the Deletion Protection feature is enabled for your Aurora Serverless clusters.
Enable Instance Storage AutoScaling
Ensure that the Storage AutoScaling feature is enabled to support unpredictable database workload.
Enable RDS Snapshot Encryption
Ensure that AWS RDS snapshots are encrypted to meet security and compliance requirements.
Enable Serverless Log Exports
Ensure Log Exports feature is enabled for your Amazon Aurora Serverless databases.
IAM Database Authentication
Enable IAM Database Authentication.
Idle RDS Instance
Identify idle AWS RDS database instances and terminate them to optimize AWS costs.
Instance Deletion Protection
Enable AWS RDS Instance Deletion Protection.
Instance Level Events Subscriptions
Enable Event Subscriptions for Instance Level Events.
Log Exports
Enable AWS RDS Log Exports.
Overutilized AWS RDS Instances
Identify overutilized RDS instances and upgrade them in order to optimize database workload and response time.
Performance Insights
Enable AWS RDS Performance Insights.
RDS Auto Minor Version Upgrade
Ensure Auto Minor Version Upgrade is enabled for RDS to automatically receive minor engine upgrades during the maintenance window.
RDS Automated Backups Enabled
Ensure automated backups are enabled for RDS instances. This feature of Amazon RDS enables point-in-time recovery of your database instance.
RDS Copy Tags to Snapshots
Enable RDS Copy Tags to Snapshots.
RDS Default Port
Ensure Amazon RDS database instances aren't using the default ports.
RDS Desired Instance Type
Ensure fewer Amazon RDS instances than the established limit in your AWS account.
RDS Encrypted With KMS Customer Master Keys
Ensure RDS instances are encrypted with CMKs to have full control over encrypting and decrypting data.
RDS Encryption Enabled
Ensure encryption is setup for RDS instances to fulfill compliance requirements for data-at-rest encryption.
RDS Event Notifications
Enable event notifications for RDS.
RDS Free Storage Space
Identify RDS instances with low free storage space and scale them in order to optimize their performance.
RDS General Purpose SSD
Ensure RDS instances are using General Purpose SSD storage instead of Provisioned IOPS SSD storage to optimize the RDS service costs.
RDS Instance Counts
Ensure fewer Amazon RDS instances than the established limit in your AWS account.
RDS Instance Not In Public Subnet
Ensure that no AWS RDS database instances are provisioned inside VPC public subnets.
RDS Master Username
Ensure AWS RDS instances are using secure and unique master usernames for their databases.
RDS Multi-AZ
Ensure RDS instances are launched into Multi-AZ.
RDS Publicly Accessible
Ensure RDS instances aren't public facing to minimise security risks.
RDS Reserved DB Instance Lease Expiration In The Next 30 Days
Ensure Amazon RDS Reserved Instances (RI) are renewed before expiration.
RDS Reserved DB Instance Lease Expiration In The Next 7 Days
Ensure Amazon RDS Reserved Instances (RI) are renewed before expiration.
RDS Reserved DB Instance Payment Failed
Ensure AWS RDS Reserved Instance purchases have not failed.
RDS Reserved DB Instance Payment Pending
Ensure Amazon RDS Reserved Instance purchases are not pending.
RDS Reserved DB Instance Recent Purchases
Ensure RDS Reserved Instance purchases are regularly reviewed for cost optimization (informational).
RDS Sufficient Backup Retention Period
Ensure RDS instances have sufficient backup retention period for compliance purposes.
Rotate SSL/TLS Certificates for Database Instances
Ensure that SSL/TLS certificates for RDS database instances are rotated according to the AWS schedule.
Security Groups Events Subscriptions
Enable Event Subscriptions for DB Security Groups Events.
Underutilized RDS Instance
Identify underutilized RDS instances and downsize them in order to optimize your AWS costs.
Unrestricted DB Security Group
Ensure there aren’t any unrestricted DB security groups assigned to your RDS instances.
Unused RDS Reserved Instances
Ensure that your Amazon RDS Reserved Instances are being fully utilized.
Use AWS Backup Service in Use for Amazon RDS
Ensure that Amazon Backup service is used to manage AWS RDS database snapshots.
Conformity Real-Time Threat monitoring
AWS IAM User Created
An AWS Identity and Access Management (IAM) user creation event has been detected.
AWS IAM user has signed in without MFA
Amazon Web Services IAM user authentication without MFA has been detected.
AWS Root user has signed in without MFA
Conformity user authentication without MFA has been detected.
Monitor Unintended AWS API Calls
Unintended AWS API calls have been detected within your Amazon Web Services account.
Root has signed in
Amazon Web Services account authentication using root credentials has been detected.
User activity in blocklisted regions
AWS User/API activity has been detected within blocklisted Amazon Web Services region(s).
User has failed signing in to AWS
Monitor AWS IAM user's failed signing attempts.
Users signed in to AWS from a safelisted IP Address
Amazon Web Services root/IAM user authentication from a blocklisted IP address has been detected.
Users signed in to AWS from an approved country
Amazon Web Services root/IAM user authentication from a non-approved country has been detected.
VPC Network Configuration Changes
Networking configuration changes have been detected within your Amazon Web Services account.
Amazon Redshift
Configure Preferred Maintenance Window
Ensure there is a preferred maintenance window configured for your Amazon Redshift clusters.
Deferred Maintenance
Enable Deferred Maintenance for Redshift Clusters.
Enable Cluster Relocation
Ensure that relocation is enabled and configured for your Amazon Redshift clusters.
Enable Cross-Region Snapshots
Ensure that cross-region snapshots are enabled for your Amazon Redshift clusters.
Enable Enhanced VPC Routing
Ensure that Enhanced VPC Routing is enabled for your Amazon Redshift clusters.
Enable Redshift User Activity Logging
Ensure that user activity logging is enabled for your Amazon Redshift clusters.
Idle Redshift Cluster
Identify idle AWS Redshift clusters and terminate them in order to optimize AWS costs.
Redshift Automated Snapshot Retention Period
Ensure that retention period is enabled for Amazon Redshift automated snapshots.
Redshift Cluster Allow Version Upgrade
Ensure Version Upgrade is enabled for Redshift clusters to automatically receive upgrades during the maintenance window.
Redshift Cluster Audit Logging Enabled
Ensure audit logging is enabled for Redshift clusters for security and troubleshooting purposes.
Redshift Cluster Default Master Username
Ensure AWS Redshift database clusters are not using "awsuser" (default master user name) for database access.
Redshift Cluster Default Port
Ensure Amazon Redshift clusters are not using port 5439 (default port) for database access.
Redshift Cluster Encrypted
Ensure database encryption is enabled for AWS Redshift clusters to protect your data at rest.
Redshift Cluster Encrypted With KMS Customer Master Keys
Ensure Redshift clusters are encrypted with KMS customer master keys (CMKs) in order to have full control over data encryption and decryption.
Redshift Cluster In VPC
Ensure Redshift clusters are launched in VPC.
Redshift Cluster Publicly Accessible
Ensure Redshift clusters are not publicly accessible to minimise security risks.
Redshift Desired Node Type
Ensure that your AWS Redshift cluster nodes are of given types.
Redshift Disk Space Usage
Identify AWS Redshift clusters with high disk usage and scale them to increase their storage capacity.
Redshift Instance Generation
Ensure Redshift clusters are using the latest generation of nodes for performance improvements.
Redshift Nodes Counts
Ensure that your AWS account has not reached the limit set for the number of Redshift cluster nodes.
Redshift Parameter Group Require SSL
Ensure AWS Redshift non-default parameter groups require SSL to secure data in transit.
Redshift Reserved Node Coverage
Ensure that your Amazon Redshift usage is covered by RI reservations in order to optimize costs.
Redshift Reserved Node Lease Expiration In The Next 30 Days
Ensure Amazon Redshift Reserved Nodes (RN) are renewed before expiration.
Redshift Reserved Node Lease Expiration In The Next 7 Days
Ensure Amazon Redshift Reserved Nodes (RN) are renewed before expiration.
Redshift Reserved Node Payment Failed
Ensure that none of your AWS Redshift Reserved Node purchases have been failed.
Redshift Reserved Node Payment Pending
Ensure that none of your AWS Redshift Reserved Node (RN) purchases are pending.
Redshift Reserved Node Recent Purchases
Ensure Redshift Reserved Node purchases are regularly reviewed for cost optimization (informational).
Sufficient Cross-Region Snapshot Retention Period
Ensure that Redshift clusters have a sufficient retention period configured for cross-region snapshots.
Underutilized Redshift Cluster
Identify underutilized Redshift clusters and downsize them in order to optimize AWS costs.
Unused Redshift Reserved Nodes
Ensure that your Amazon Redshift Reserved Nodes are being utilized.
AWS Resource Groups
Tags
Use tags metadata for identifying and organizing your AWS resources by purpose, owner, environment, or other criteria
Amazon Route 53
Amazon Route 53 Configuration Changes
Route 53 configuration changes have been detected within your Amazon Web Services account.
Enable DNSSEC Signing for Route 53 Hosted Zones
Ensure that DNSSEC signing is enabled for your Amazon Route 53 Hosted Zones.
Enable Query Logging for Route 53 Hosted Zones
Ensure that DNS query logging is enabled for your Amazon Route 53 hosted zones.
Privacy Protection
Ensure that Route 53 domains have Privacy Protection enabled.
Remove AWS Route 53 Dangling DNS Records
Ensure dangling DNS records are removed from your AWS Route 53 hosted zones to avoid domain/subdomain takeover.
Route 53 Domain Auto Renew
Ensure Route 53 domains are set to auto renew.
Route 53 Domain Expired
Ensure expired AWS Route 53 domains names are restored.
Route 53 Domain Expiry 30 Days
Ensure AWS Route 53 domain names are renewed before their expiration.
Route 53 Domain Expiry 45 Days
Ensure AWS Route 53 domain names are renewed before their expiration (45 days before expiration).
Route 53 Domain Expiry 7 Days
Ensure AWS Route 53 domain names are renewed before their expiration.
Route 53 Domain Transfer Lock
Ensure Route 53 domains have the transfer lock set to prevent an unauthorized transfer to another registrar.
Route 53 In Use
Ensure AWS Route 53 DNS service is in use for highly efficient DNS management.
Sender Policy Framework In Use
Ensure that Sender Policy Framework (SPF) is used to stop spammers from spoofing your AWS Route 53 domain.
Amazon Route 53 Domains
Amazon Route 53 Domains Configuration Changes
Route 53 Domains configuration changes have been detected within your Amazon Web Services account.
Amazon S3
Amazon Macie Finding Statistics for S3
Capture summary statistics about Amazon Macie security findings on a per-S3 bucket basis.
Configure Different S3 Bucket for Server Access Logging Storage
Ensure that Amazon S3 Server Access Logging uses a different bucket for storing access logs.
Configure S3 Object Ownership
Ensure that S3 Object Ownership is configured to allow you to take ownership of S3 objects.
DNS Compliant S3 Bucket Names
Ensure that Amazon S3 buckets always use DNS-compliant bucket names.
Deny S3 Log Delivery Group Write Permission on the Source Bucket
Ensure that the S3 Log Delivery Group write permissions are denied for the S3 source bucket.
Enable S3 Block Public Access for AWS Accounts
Ensure that Amazon S3 public access is blocked at the AWS account level for data protection.
Enable S3 Block Public Access for S3 Buckets
Ensure that Amazon S3 public access is blocked at the S3 bucket level for data protection.
Enable S3 Bucket Keys
Ensure that Amazon S3 buckets are using S3 bucket keys to optimize service costs.
S3 Bucket Authenticated Users 'FULL_CONTROL' Access
Ensure that S3 buckets do not allow FULL_CONTROL access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'READ' Access
Ensure that S3 buckets do not allow READ access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'READ_ACP' Access
Ensure that S3 buckets do not allow READ_ACP access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'WRITE' Access
Ensure that S3 buckets do not allow WRITE access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'WRITE_ACP' Access
Ensure that S3 buckets do not allow WRITE_ACP access to AWS authenticated users via ACLs.
S3 Bucket Default Encryption (Deprecated)
Ensure that encryption at rest is enabled for your Amazon S3 buckets and their data.
S3 Bucket Logging Enabled
Ensure S3 bucket access logging is enabled for security and access audits.
S3 Bucket MFA Delete Enabled
Ensure S3 buckets have an MFA-Delete policy to prevent deletion of files without an MFA token.
S3 Bucket Public 'FULL_CONTROL' Access
Ensure that your Amazon S3 buckets are not publicly exposed to the Internet.
S3 Bucket Public 'READ' Access
Ensure that S3 buckets do not allow public READ access via Access Control Lists (ACLs).
S3 Bucket Public 'READ_ACP' Access
Ensure that S3 buckets do not allow public READ_ACP access via Access Control Lists (ACLs).
S3 Bucket Public 'WRITE' ACL Access
Ensure S3 buckets don’t allow public WRITE ACL access
S3 Bucket Public 'WRITE_ACP' Access
Ensure that S3 buckets do not allow public WRITE_ACP access via Access Control Lists (ACLs).
S3 Bucket Public Access Via Policy
Ensure that Amazon S3 buckets do not allow public access via bucket policies.
S3 Bucket Versioning Enabled
Ensure S3 bucket versioning is enabled for additional level of data protection.
S3 Buckets Encrypted with Customer-Provided CMKs
Ensure that Amazon S3 buckets are encrypted with customer-provided KMS CMKs.
S3 Buckets Lifecycle Configuration
Ensure that AWS S3 buckets utilize lifecycle configurations to manage S3 objects during their lifetime.
S3 Buckets with Website Hosting Configuration Enabled
Ensure that the S3 buckets with website configuration are regularly reviewed (informational).
S3 Configuration Changes
AWS S3 configuration changes have been detected within your Amazon Web Services account.
S3 Cross Account Access
Ensure that S3 buckets do not allow unknown cross-account access via bucket policies.
S3 Object Lock
Ensure that S3 buckets use Object Lock for data protection and/or regulatory compliance.
S3 Transfer Acceleration
Ensure that S3 buckets use the Transfer Acceleration feature for faster data transfers.
Secure Transport
Ensure AWS S3 buckets enforce SSL to secure data in transit.
Server Side Encryption
Ensure AWS S3 buckets enforce Server-Side Encryption (SSE)
Amazon Simple Email Service
DKIM Enabled
Ensure DKIM signing is enabled in AWS SES to protect email senders and receivers against phishing.
Exposed SES Identities
Ensure that your AWS SES identities (domains and/or email addresses) are not exposed to everyone.
Identify Cross-Account Access
Ensure that AWS SES identities (domains and/or email addresses) do not allow unknown cross-account access via authorization policies.
Identity Verification Status
Ensure AWS SES identities (email addresses and/or domains) are verified.
Amazon Simple Notification Service (SNS)
AWS SNS Appropriate Subscribers
Ensure appropriate subscribers to all your AWS Simple Notification Service (SNS) topics.
SNS Cross Account Access
Ensure Amazon SNS topics don't allow unknown cross account access.
SNS Topic Accessible For Publishing
Ensure SNS topics don't allow 'Everyone' to publish.
SNS Topic Accessible For Subscription
Ensure SNS topics don't allow 'Everyone' to subscribe.
SNS Topic Encrypted
Enable Server-Side Encryption for AWS SNS Topics.
SNS Topic Encrypted With KMS Customer Master Keys
Ensure that Amazon SNS topics are encrypted with KMS Customer Master Keys.
SNS Topic Exposed
Ensure SNS topics aren't exposed to everyone.
Amazon Simple Queue Service
Queue Server Side Encryption
Ensure Amazon SQS queues enforce Server-Side Encryption (SSE).
Queue Unprocessed Messages
Ensure SQS queues aren't holding a high number of unprocessed messages due to unresponsive or incapacitated consumers.
SQS Cross Account Access
Ensure SQS queues don't allow unknown cross account access.
SQS Dead Letter Queue
Ensure Dead Letter Queue (DLQ) is configured for SQS queue.
SQS Encrypted With KMS Customer Master Keys
Ensure SQS queues are encrypted with KMS CMKs to gain full control over data encryption and decryption
SQS Queue Exposed
Ensure SQS queues aren't exposed to everyone.
AWS Systems Manager
Check for SSM Managed Instances
Ensure that all EC2 instances are managed by AWS Systems Manager (SSM) service.
SSM Parameter Encryption
Ensure that Amazon SSM parameters that hold sensitive configuration data are encrypted.
SSM Session Length
Ensure that all active sessions in the Session manager do not exceed a set period of time.
Amazon SageMaker
Amazon SageMaker Notebook Instance In VPC
Ensure that Amazon SageMaker notebook instances are deployed into a VPC.
Check for Missing Execution Role
Ensure that SageMaker notebook instances are referencing active execution roles.
Disable Direct Internet Access for Notebook Instances
Ensure that direct internet access is disabled for SageMaker Studio notebook instances.
Disable Root Access for SageMaker Notebook Instances
Ensure that root access is disabled for Amazon SageMaker notebook instances.
Enable Data Capture for SageMaker Endpoints
Ensure that SageMaker endpoints are configured to capture log data useful for training, debugging, and monitoring.
Enable Inter-Container Traffic Encryption
Ensure that inter-container traffic encryption is enabled for your SageMaker training jobs.
Enable Network Isolation for SageMaker Models
Ensure that network isolation is enabled for your SageMaker models to prevent unauthorized access.
Enable Network Isolation for SageMaker Training Jobs
Ensure that network isolation is enabled for your SageMaker training jobs to prevent unauthorized access.
Enable SageMaker Notebook Instance Data Encryption (Deprecated)
Ensure that data available on Amazon SageMaker notebook instances is encrypted.
Enable VPC Only for SageMaker Domains
Enable and configure "VPC Only" mode for added security control of your SageMaker notebooks.
Endpoints Encrypted With KMS Customer Managed Keys
Ensure that SageMaker endpoints are using Amazon KMS Customer Managed Keys (CMKs) for data encryption.
Notebook Data Encrypted With KMS Customer Managed Keys
Ensure SageMaker notebook instance storage volumes are encrypted with Amazon KMS Customer Managed Keys (CMKs).
Notebook in VPC Only Mode Can Access Required Resources
Ensure that SageMaker notebook instances deployed into a VPC can access required resources.
Output and Storage Volume Data Encrypted With KMS Customer Managed Keys
Ensure that training job volume and output data is encrypted with Amazon KMS Customer Managed Keys (CMKs).
SageMaker HyperPod Clusters Encrypted with KMS Customer Managed Keys
Ensure that SageMaker HyperPod cluster storage volumes are encrypted with Amazon KMS Customer Managed Keys (CMKs).
AWS Secrets Manager
Secret Encrypted With KMS Customer Master Keys
Ensure that AWS Secrets Manager service enforces data-at-rest encryption using KMS CMKs.
Secret Rotation Enabled
Ensure that automatic rotation is enabled for your Amazon Secrets Manager secrets.
Secret Rotation Interval
Ensure that Amazon Secrets Manager automatic rotation interval is properly configured.
Secrets Manager In Use
Ensure that AWS Secrets Manager is in use for secure and efficient credentials management.
AWS Security Hub
AWS Security Hub Findings
Ensure that Amazon Security Hub findings are analyzed and resolved.
AWS Security Hub Insights
Ensure that Amazon Security Hub insights are regularly reviewed (informational).
Detect AWS Security Hub Configuration Changes
Security Hub service configuration changes have been detected within your Amazon Web Services account.
Review Enabled Security Hub Standards
Ensure that enabled Amazon Security Hub standards are reviewed (informational).
Security Hub Enabled
Ensure that Amazon Security Hub service is enabled for your AWS accounts.
Service Quotas
Enable Alerts for Supported Service Quotas
Ensure that Amazon CloudWatch alarms are configured for supported AWS service quotas
AWS Shield
Shield Advanced In Use
Use AWS Shield Advanced to protect your web applications against DDoS attacks.
AWS Storage Gateway
Use KMS Customer Master Keys for AWS Storage Gateway File Shares
Ensure that your Amazon Storage Gateway file share data is encrypted using KMS Customer Master Keys (CMKs).
Use KMS Customer Master Keys for AWS Storage Gateway Tapes
Ensure that your Amazon Storage Gateway virtual tapes are encrypted using KMS Customer Master Keys.
Use KMS Customer Master Keys for AWS Storage Gateway Volumes
Ensure that your Amazon Storage Gateway volumes data is encrypted using KMS Customer Master Keys (CMKs).
AWS Support
Support Plan
Ensure appropriate support level is enabled for necessary AWS accounts (e.g. production accounts).
AWS Transfer
Enable AWS Transfer for SFTP Logging Activity
Ensure that AWS CloudWatch logging is enabled for Amazon Transfer for SFTP user activity.
Use AWS PrivateLink for Transfer for SFTP Server Endpoints
Ensure that Amazon Transfer for SFTP servers are using AWS PrivateLink for their endpoints.
AWS Trusted Advisor
Exposed IAM Access Keys
Ensure exposed IAM access keys are invalidated to protect your AWS resources from unauthorized access.
Trusted Advisor Checks
Ensure that Amazon Trusted Advisor checks are examined and resolved..
Trusted Advisor Service Limits
Monitor AWS Service Limits to ensure that the allocation of resources is not reaching the limit.
Amazon Virtual Private Cloud (VPC)
AWS VPC Peering Connections Route Tables Access
Ensure that the Amazon VPC peering connection configuration is compliant with the desired routing policy.
AWS VPN Tunnel State
Ensure the state of your AWS Virtual Private Network (VPN) tunnels is UP
Ineffective Network ACL DENY Rules
Ensure that Amazon Network ACL DENY rules are effective within the VPC configuration.
Managed NAT Gateway in Use
Ensure that the Managed NAT Gateway service is enabled for high availability (HA).
Specific Gateway Attached To Specific VPC
Ensure that a specific Internet/NAT gateway is attached to a specific VPC.
Unrestricted Inbound Traffic on Remote Server Administration Ports
Ensure that no Network ACL (NACL) allows unrestricted inbound traffic on TCP ports 22 and 3389.
Unrestricted Network ACL Inbound Traffic
Ensure that no Network ACL (NACL) allows inbound/ingress traffic from all ports.
Unrestricted Network ACL Outbound Traffic
Ensure that no Network ACL (NACL) allows outbound/egress traffic to all ports.
Unused VPC Internet Gateways
Ensure unused VPC Internet Gateways and Egress-Only Internet Gateways are removed to follow best practices.
Unused Virtual Private Gateways
Ensure unused Virtual Private Gateways (VGWs) are removed to follow best practices.
VPC Endpoint Cross Account Access
Ensure Amazon VPC endpoints don't allow unknown cross account access.
VPC Endpoint Exposed
Ensure Amazon VPC endpoints aren't exposed to everyone.
VPC Endpoints In Use
Ensure that VPC endpoints are being used to connect your VPC to another AWS cloud service.
VPC Flow Logs Enabled
Ensure VPC flow logging is enabled in all VPCs.
VPC Naming Conventions
Follow proper naming conventions for Virtual Private Clouds.
VPC Peering Connections To Accounts Outside AWS Organization
Ensure VPC peering communication is only between AWS accounts, members of the same AWS Organization.
VPN Tunnel Redundancy
Ensure AWS VPNs have always two tunnels active in order to enable redundancy.
AWS WAF - Web Application Firewall
AWS WAFv2 In Use
Ensure that AWS WAFv2 is in use to protect your web applications from common web exploits.
AWS Web Application Firewall In Use
Ensure AWS WAF is in use to protect your web applications from common web exploits.
Enable Logging for Web Access Control Lists
Ensure that logging is enabled for Amazon WAF Web Access Control Lists.
AWS Well-Architected
AWS Well-Architected Tool Findings
Ensure that the high and medium risk issues identified in a workload by the AWS Well-Architected Tool are highlighted, audited, and resolved.
AWS Well-Architected Tool in Use
Ensure AWS Well-Architected Tool is in use to help you build and maintain secure, efficient, high-performing and resilient cloud application architectures.
AWS WorkDocs
Enable MFA for Microsoft Entra Connector Directories
Ensure that Multi-Factor Authentication (MFA) is enabled for Microsoft Entra Connector directories in Amazon WorkDocs.
Amazon WorkSpaces
Unused WorkSpaces
Ensure that your Amazon WorkSpaces service instances are being utilized.
WorkSpaces Desired Bundle Type
Ensure your AWS account has not reached the limit set for the number of WorkSpaces instances.
WorkSpaces Instances Counts
Ensure your AWS account has not reached the limit set for the number of WorkSpaces instances.
WorkSpaces Operational State
Ensure that your Amazon WorkSpaces instances are healthy.
WorkSpaces Storage Encryption
Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirement.
AWS X-Ray
X-Ray Data Encrypted With KMS Customer Master Keys
Ensure Amazon X-Ray encrypts traces and related data at rest using KMS CMKs.

## Key Principles
Follow security best practices and compliance requirements.

## Compliance Frameworks
AWS, TrendMicro, NIST

## Compliance Controls
Standard security controls apply

## Focus Areas
least_privilege_violations, privilege_escalation_risks, compliance_violations, resource_wildcards

## Analysis
Regular security assessments help identify potential risks and compliance gaps.

## Certification
Compliant with industry security standards and best practices.

## Source
https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/

## Full Content
Knowledge Base
Amazon Web Services
Get Started
Get Pricing
Contact Us
Amazon Web Services best practice rules
Trend Vision One™ has over 1100+ cloud infrastructure configuration best practices for your
Alibaba Cloud
, Amazon Web Services™,
Microsoft® Azure
, and
Google Cloud™
environments. Here is our growing list of AWS security, configuration and compliance rules with clear instructions on how to perform the updates – made either through the AWS console or via the AWS Command Line Interface (CLI).
Trend Vision One™ provides real-time monitoring and auto-remediation for the security, compliance and governance of your cloud infrastructure. Leaving you to grow and scale your business with confidence.
AWS Certificate Manager
ACM Certificate Expired
Ensure expired SSL/TLS certificates are removed from AWS Certificate Manager (ACM).
AWS ACM Certificates Renewal (30 days before expiration)
Ensure Amazon Certificate Manager (ACM) certificates are renewed before their expiration.
AWS ACM Certificates Renewal (45 days before expiration)
Ensure Amazon Certificate Manager (ACM) certificates are renewed before their expiration.
AWS ACM Certificates Renewal (7 days before expiration)
Ensure Amazon Certificate Manager (ACM) certificates are renewed before their expiration.
AWS ACM Certificates Validity
Ensure expired SSL/TLS certificates are removed from AWS Certificate Manager (ACM).
AWS ACM Certificates with Wildcard Domain Names
Ensure that wildcard certificates issued by Amazon Certificate Manager (ACM) or imported to ACM are not in use.
Amazon API Gateway
API Gateway Integrated With AWS WAF
Use AWS WAF to protect Amazon API Gateway APIs from common web exploits.
APIs CloudWatch Logs
Ensure that AWS CloudWatch logs are enabled for all your APIs created with Amazon API Gateway service in order to track and analyze execution behavior at the API stage level.
APIs Detailed CloudWatch Metrics
Ensure that detailed CloudWatch metrics are enabled for all APIs created with AWS API Gateway service in order to monitor API stages caching, latency and detected errors at a more granular level and set alarms accordingly.
Check for Unknown Cross Account API Access
Ensure that Amazon API Gateway APIs do not allow unknown cross-account access.
Check the Minimum TLS Version Configured for API Gateway Domains
Ensure that Amazon API Gateway domains are configured with the latest version of TLS protocol.
Client Certificate
Use client-side SSL certificates for HTTP backend authentication within AWS API Gateway.
Content Encoding
Ensure Content Encoding is enabled for your APIs.
Enable API Cache
Ensure that REST APIs created with Amazon API Gateway have response caching enabled.
Enable Access Logs for API Gateway V2 API Stages
Ensure that access logging is enabled for all Amazon API Gateway V2 API stages.
Enable Control Access to REST APIs using Keys or Tokens
Ensure that access to your API Gateway REST APIs is controlled using keys or tokens.
Enable Encryption for API Cache
Ensure that stage-level cache encryption is enabled for your Amazon API Gateway APIs.
Limit REST API Access by IP Address
Ensure that the access to your REST APIs is allowed to trusted IP addresses only.
Private Endpoint
Ensure Amazon API Gateway APIs are only accessible through private API endpoints.
Rotate Expiring SSL Client Certificates
Ensure that SSL certificates associated with API Gateway REST APIs are rotated periodically.
Tracing Enabled
Ensure that tracing is enabled for all stages in all APIs created with AWS API Gateway service in order to analyze latencies in APIs and their backend services.
Amazon AccessAnalyzer
IAM Access Analyzer Findings
Ensure that IAM Access Analyzer findings are reviewed and resolved to maintain access security to your AWS resources.
Amazon AppFlow
Enable Data Encryption with KMS Customer Master Keys
Ensure that Amazon AppFlow flows are encrypted with KMS Customer Master Keys (CMKs).
AWS App Mesh
Enable Access Logging for App Mesh Virtual Gateways
Ensure that Access Logging is enabled for your Amazon App Mesh virtual gateways.
Enable Health Checks for App Mesh Virtual Gateways
Ensure that Amazon App Mesh virtual gateways are using health checks.
Enforce TLS for App Mesh Virtual Gateways
Enforce TLS by default for your Amazon App Mesh virtual gateways.
Restrict External Traffic
Ensure that Amazon App Mesh proxies are only forwarding traffic between each other.
Amazon Athena
Enable Encryption for AWS Athena Query Results
Ensure that AWS Athena query results stored in Amazon S3 are encrypted at rest.
AWS Auto Scaling
App-Tier Auto Scaling Group associated ELB
Ensure that each app-tier Auto Scaling Group (ASG) has an associated Elastic Load Balancer (ELB) in order to maintain the availability of the EC2 compute resources in the event of a failure and provide an evenly distributed application load.
Auto Scaling Group Cooldown Period
Ensure Amazon Auto Scaling Groups are utilizing cooldown periods.
Auto Scaling Group Health Check
Ensure ELB health check is enabled if Elastic Load Balancing is being used for an Auto Scaling group. Ensure EC2 health check is enabled if Elastic Load Balancing isn't being used for an Auto Scaling group
Auto Scaling Group Notifications
Ensure notifications are enabled for ASGs to receive additional information about scaling operations.
Auto Scaling Group Referencing Missing ELB
Ensure Amazon Auto Scaling Groups are utilizing active Elastic Load Balancers.
Auto Scaling Group associated ELB
Ensure that each Auto Scaling Group (ASG) has an associated Elastic Load Balancer (ELB) in order to maintain the availability of the EC2 compute resources in the event of a failure and provide an evenly distributed application load.
CloudWatch Logs Agent for App-Tier Auto Scaling Group In Use
Ensure an agent for AWS CloudWatch Logs is installed within Auto Scaling Group for app tier.
CloudWatch Logs Agent for Web-Tier Auto Scaling Group In Use
Ensure an agent for AWS CloudWatch Logs is installed within Auto Scaling Group for web tier.
Configure Metadata Response Hop Limit
Configure the metadata response hop limit for EC2 instances running within the Auto Scaling Group.
Configure Multiple Instance Types Across Multiple AZs
Ensure that your Auto Scaling Groups are using multiple instance types across multiple Availability Zones.
Disable Public IP Association in ASG Launch Templates
Ensure that your Auto Scaling Group (ASG) instances are not using public IP addresses.
Empty Auto Scaling Group
Identify and remove empty AWS Auto Scaling Groups (ASGs).
IAM Roles for App-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for app tier is configured to use a customer created app-tier IAM role.
IAM Roles for Web-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for web tier is configured to use a customer created web-tier IAM role.
Launch Configuration Referencing Missing AMI
Ensure AWS Launch Configurations are utilizing active Amazon Machine Images.
Launch Configuration Referencing Missing Security Groups
Ensure AWS Launch Configurations are utilizing active Security Groups.
Multi-AZ Auto Scaling Groups
Ensure AWS Auto Scaling Groups utilize multiple Availability Zones to improve environment reliability.
Same Availability Zones In ASG And ELB
Ensure AWS Availability Zones used for Auto Scaling Groups and for their Elastic Load Balancers are the same.
Suspended Auto Scaling Groups
Ensure there are no Amazon Auto Scaling Groups with suspended processes.
Unused Launch Configuration
Identify and remove unused AWS Auto Scaling Launch Configuration templates.
Use Approved AMIs for App-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for app tier is configured to use an approved Amazon Machine Image.
Use Approved AMIs for Web-Tier ASG Launch Configurations
Ensure Auto Scaling Group launch configuration for web tier is configured to use an approved Amazon Machine Image.
Use Launch Templates for Auto Scaling Groups
Ensure that your Auto Scaling Groups (ASGs) are utilizing launch templates.
Web-Tier Auto Scaling Group associated ELB
Ensure that each web-tier Auto Scaling Group (ASG) has an associated Elastic Load Balancer (ELB) in order to maintain the availability of the EC2 compute resources in the event of a failure and provide an evenly distributed application load.
AWS Backup
AWS Backup Service Lifecycle Configuration
Ensure Amazon Backup plans have a compliant lifecycle configuration enabled.
Check for Protected Amazon Backup Resource Types
Ensure that the appropriate resource types are protected by Amazon Backup within your AWS account.
Configure AWS Backup Vault Access Policy
Prevent the deletion of backups using the AWS Backup vault access policy.
Enable Alert Notifications for Failed Backup Jobs
Ensure that email notifications for unsuccessful backup jobs are enabled.
Use AWS Backup Service in Use for Amazon RDS
Ensure that Amazon Backup service is used to manage AWS RDS database snapshots.
Use KMS Customer Master Keys for AWS Backup
Ensure that your backups are encrypted at rest using KMS Customer Master Keys (CMKs).
Amazon Bedrock
Amazon Bedrock Service Role Policy Too Permissive
Ensure that policies attached to Amazon Bedrock service roles adhere to the Principle of Least Privilege.
Check for Long-Term API Keys
To prevent credential exposure, use short-term Amazon Bedrock API keys instead of long-term API keys.
Check for Missing Amazon Bedrock Agent Service Role
Ensure that Amazon Bedrock agents are referencing active (available) service roles.
Check for Missing Model Customization Job Security Groups
Ensure that Bedrock model customization jobs are referencing active (available) VPC security groups.
Configure Data Deletion Policy for Knowledge Base Data
Ensure that the vector store data is retained when the knowledge base data sources are deleted.
Configure Permissions Boundaries for IAM Identities used by Amazon Bedrock
For enhanced security, ensure that permissions boundaries are set for IAM identities used by Amazon Bedrock.
Configure Prompt Attack Strength for Amazon Bedrock Guardrails
Ensure that prompt attack strength is set to HIGH for Amazon Bedrock guardrails.
Configure Sensitive Information Filters for Amazon Bedrock Guardrails
Ensure that sensitive information filters are configured for Amazon Bedrock guardrails.
Cross-Service Confused Deputy Prevention
Ensure that policies attached to Amazon Bedrock service roles are configured to prevent cross-service impersonation.
Enable Model Invocation Logging
Ensure that model invocation logging is enabled in the Amazon Bedrock account level settings.
Protect Model Customization Jobs using a VPC
Ensure that Bedrock model customization jobs are protected by a Virtual Private Cloud (VPC).
Use Customer-Managed Keys to Encrypt Agent Sessions
Ensure that agent session data is encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Amazon Bedrock Guardrails
Ensure that Bedrock guardrails are encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Amazon Bedrock Studio Workspaces
Ensure that Bedrock Studio workspaces are encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Custom Models
Ensure that AWS Bedrock custom models are encrypted with Amazon KMS Customer-Managed Keys (CMKs).
Use Customer-Managed Keys to Encrypt Knowledge Base Transient Data
Ensure that knowledge base transient data is encrypted with Amazon KMS Customer Managed Keys (CMKs).
Use Guardrails to Protect Agent Sessions
Ensure that Bedrock agent sessions are associated with guardrails for protection.
AWS Budgets
Budget Overrun (Deprecated)
Cost of '[Limit details eg Service: Lambda]' overruns the budget limit
Budget Overrun Forecast (Deprecated)
Cost of '[Limit details eg Service: Lambda]' is estimated to overrun the budget limit.
Cost Fluctuation (Deprecated)
Cost of '[Limit details eg Service: Lambda]' in the current period has fluctuated beyond the defined percentage limit of the previous period.
Cost Fluctuation Forecast (Deprecated)
Cost of '[Limit details eg Service: Lambda]' in the current period is forecasted to fluctuate beyond the defined percentage limit of the previous period.
Current Contact Details
Ensure valid contact information for all your Amazon Web Services accounts.
Detailed billing
Ensure Detailed Billing is enabled for your Amazon Web Services account.
AWS Cloud​Formation
AWS CloudFormation Deletion Policy in Use
Ensure a deletion policy is used for your Amazon CloudFormation stacks.
AWS CloudFormation Drift Detection
Ensure that Amazon CloudFormation stacks have not been drifted.
CloudFormation In Use
Ensure CloudFormation service is in use for defining your cloud architectures on Amazon Web Services
CloudFormation Stack Failed Status
Ensure AWS CloudFormation stacks aren't in 'Failed' mode for more than 6 hours.
CloudFormation Stack Notification
Ensure CloudFormation stacks are integrated with SNS to receive notifications about stack events.
CloudFormation Stack Policy
Ensure CloudFormation stack policies are set to prevent accidental updates to stack resources.
CloudFormation Stack Termination Protection
Ensure Termination Protection feature is enabled for your AWS CloudFormation stacks.
CloudFormation Stack With IAM Role
Ensure that IAM role associated with CloudFormation stacks adheres to the principle of least privilege in order avoid unwanted privilege escalation.
Amazon CloudFront
CloudFront Compress Objects Automatically
Ensure CloudFront distributions are configured to automatically compress content.
CloudFront Geo Restriction
Ensure Geo Restriction is enabled for CloudFront CDN distributions.
CloudFront In Use
Ensure CloudFront global content delivery network (CDN) service is in use.
CloudFront Insecure Origin SSL Protocols
Ensure CloudFront origins don't use insecure SSL protocols.
CloudFront Integrated With WAF
Ensure CloudFront is integrated with WAF to protect web applications from exploit attempts that can compromise security or place unnecessary load on your application.
CloudFront Logging Enabled
Ensure CloudFront logging is enabled.
CloudFront Security Policy
Ensure AWS CloudFront distributions are using improved security policies for HTTPS connections.
CloudFront Traffic To Origin Unencrypted
Ensure traffic between a CloudFront distribution and the origin is encrypted.
CloudFront Viewer Protocol Policy
Ensure CloudFront Viewer Protocol Policy enforces encryption.
Configure Default Root Object
Ensure that CloudFront distributions are configured to use a default root object.
Enable Origin Access Control for Distributions with S3 Origin
Ensure that CloudFront distributions are using an origin access control configuration for their origin S3 buckets.
Enable Origin Failover
Ensure that CloudFront distributions are using the Origin Failover feature to maintain high availability.
Enable Origin Shield
Ensure that Amazon CloudFront distributions are using the Origin Shield feature.
Enable Real-Time Logging
Ensure that CloudFront distributions are using the Real-Time Logging feature.
FieldLevel Encryption
Enable Field-Level Encryption for CloudFront Distributions.
Missing S3 Bucket
Ensure that CloudFront distributions do not point to non-existent S3 origins.
Use CloudFront Content Distribution Network
Use Amazon CloudFront Content Distribution Network for secure web content delivery.
Use Custom SSL/TLS Certificates
Ensure that CloudFront distributions are configured to use a custom SSL/TLS certificate.
Use SNI to Serve HTTPS Requests
Ensure that CloudFront distributions are configured to use Server Name Indication (SNI).
AWS CloudTrail
AWS CloudTrail Configuration Changes
CloudTrail configuration changes have been detected within your Amazon Web Services account.
Avoid Duplicate Entries in Amazon CloudTrail Logs
Ensure that AWS CloudTrail trails aren't duplicating global service events in their aggregated log files
Check for Missing SNS Topic within Trail Configuration
Ensure that your CloudTrail trails are using active Amazon SNS topics.
CloudTrail Bucket MFA Delete Enabled
Ensure CloudTrail logging bucket has a MFA-Delete policy to prevent deletion of logs without an MFA token
CloudTrail Data Events
Ensure CloudTrail trails are configured to log Data events.
CloudTrail Delivery Failing
Ensure Amazon CloudTrail trail log files are delivered as expected.
CloudTrail Enabled
Ensure CloudTrail is enabled in all regions.
CloudTrail Global Services Enabled
Ensure CloudTrail records events for global services such as IAM or AWS STS.
CloudTrail Integrated With CloudWatch
Ensure CloudTrail trails are integrated with CloudWatch Logs.
CloudTrail Log File Integrity Validation
Ensure CloudTrail log file validation is enabled
CloudTrail Logs Encrypted
Ensure CloudTrail logs are encrypted at rest using KMS CMKs.
CloudTrail Management Events
Ensure management events are included into AWS CloudTrail trails configuration.
CloudTrail S3 Bucket
Ensure that AWS CloudTrail trail uses the designated Amazon S3 bucket.
CloudTrail S3 Bucket Logging Enabled
Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket.
Enable Object Lock for CloudTrail S3 Buckets
Ensure that the CloudTrail buckets are using Object Lock for data protection and compliance.
Publicly Accessible CloudTrail Buckets
Ensure that your CloudTrail trail buckets are not publicly accessible.
Amazon CloudWatch
Billing Alarm
Ensure your AWS costs are being monitored using a CloudWatch billing alarm.
Configure ALARM Actions for CloudWatch Alarms
Ensure that CloudWatch alarms have at least one action configured for the ALARM state.
Enable Actions for CloudWatch Alarms
Ensure that Amazon CloudWatch alarm actions are activated (enabled).
Amazon CloudWatch Events
AWS CloudWatch Events In Use
Ensure CloudWatch Events is in use to help you respond to operational changes within your AWS resources.
Event Bus Exposed
Ensure that your AWS CloudWatch event bus is not exposed to everyone.
EventBus Cross Account Access
Ensure that AWS CloudWatch event buses do not allow unknown cross-account access for delivery of events.
Amazon CloudWatch Logs
AWS Config Changes Alarm
Ensure AWS Config configuration changes are being monitored using CloudWatch alarms.
AWS Console Sign In Without MFA
Monitor for AWS Console Sign-In Requests Without MFA
AWS Organizations Changes Alarm
Ensure Amazon Organizations changes are being monitored using AWS CloudWatch alarms.
Authorization Failures Alarm
Ensure a log metric filter and alarm exist for unauthorized API calls.
CMK Disabled or Scheduled for Deletion Alarm
Ensure AWS CMK configuration changes are being monitored using CloudWatch alarms.
CloudTrail Changes Alarm
Ensure all AWS CloudTrail configuration changes are being monitored using CloudWatch alarms.
Console Sign-in Failures Alarm
Ensure your AWS Console authentication process is being monitored using CloudWatch alarms.
Create CloudWatch Alarm for VPC Flow Logs Metric Filter
Ensure that a CloudWatch alarm is created for the VPC Flow Logs metric filter and an alarm action is configured.
EC2 Instance Changes Alarm
Ensure AWS EC2 instance changes are being monitored using CloudWatch alarms.
EC2 Large Instance Changes Alarm
Ensure AWS EC2 large instance changes are being monitored using CloudWatch alarms.
IAM Policy Changes Alarm
Ensure AWS IAM policy configuration changes are being monitored using CloudWatch alarms.
Internet Gateway Changes Alarm
Ensure AWS VPC Customer/Internet Gateway configuration changes are being monitored using CloudWatch alarms.
Metric Filter for VPC Flow Logs CloudWatch Log Group
Ensure that a log metric filter for the CloudWatch group assigned to the VPC Flow Logs is created.
Network ACL Changes Alarm
Ensure AWS Network ACLs configuration changes are being monitored using CloudWatch alarms.
Root Account Usage Alarm
Ensure Root Account Usage is being monitored using CloudWatch alarms.
Route Table Changes Alarm
Ensure AWS Route Tables configuration changes are being monitored using CloudWatch alarms.
S3 Bucket Changes Alarm
Ensure AWS S3 Buckets configuration changes are being monitored using CloudWatch alarms.
Security Group Changes Alarm
Ensure AWS security groups configuration changes are being monitored using CloudWatch alarms.
VPC Changes Alarm
Ensure AWS VPCs configuration changes are being monitored using CloudWatch alarms.
AWS CodeBuild
Amazon Comprehend
Enable Encryption for AWS Comprehend Analysis Job Results
Ensure that AWS Comprehend analysis job results stored in Amazon S3 are encrypted at rest.
AWS Compute Optimizer
Compute Optimizer Auto Scaling Group Findings
Ensure that your Amazon EC2 Auto Scaling groups are optimized for better performance and cost savings.
Compute Optimizer EC2 Instance Findings
Ensure that your Amazon EC2 instances are optimized for better cost and performance.
Compute Optimizer Lambda Function Findings
Ensure that your Amazon Lambda functions are optimized for better performance and cost.
AWS Config
AWS Config Configuration Changes
AWS Config service configuration changes have been detected within your Amazon Web Services account.
AWS Config Enabled
Ensure AWS Config is enabled in all regions to get the optimal visibility of the activity on your account.
AWS Config Global Resources
Ensure Global resources are included into AWS Config service configuration.
AWS Config Referencing Missing S3 Bucket
Ensure AWS Config service is using an active S3 bucket to store configuration changes files.
Config Delivery Failing
Ensure Amazon Config log files are delivered as expected.
AWS ConfigService
AWS Custom Rule
Ensure that all evaluation results returned for your AWS Config rules are compliant.
AWS Cost Explorer
Cost Anomaly Detection Findings
Ensure that unusual AWS spend is analyzed and mitigated using Amazon Cost Anomaly Detection.
Cost Anomaly Detection Monitor in Use
Ensure that a Cost Anomaly Detection monitor is running within your AWS cloud account.
Amazon DynamoDB Accelerator
Cluster Encryption
Ensure DAX clusters enforce Server-Side Encryption.
Amazon Data Lifecycle Manager
Use AWS DLM to Automate EBS Snapshot Lifecycle
Use Amazon Data Lifecycle Manager (DLM) to automate EBS volume snapshots management.
AWS Database Migration Service
DMS Auto Minor Version Upgrade
Ensure that Amazon DMS replication instances have Auto Minor Version Upgrade feature enabled.
DMS Multi-AZ
Ensure that Amazon DMS replication instances have the Multi-AZ feature enabled
DMS Replication Instances Encrypted with KMS CMKs
Ensure that Amazon DMS replication instances are encrypted with KMS Customer Master Keys (CMKs).
Publicly Accessible DMS Replication Instances
Ensure that AWS DMS replication instances are not publicly accessible and prone to security risks.
Amazon DocumentDB
DocumentDB Clusters Encrypted with KMS CMKs
Ensure AWS DocumentDB clusters are encrypted with KMS Customer Master Keys.
DocumentDB Encryption Enabled
Enable encryption at rest for AWS DocumentDB clusters.
DocumentDB Sufficient Backup Retention Period
Ensure that Amazon DocumentDB clusters have set a minimum backup retention period.
Enable Amazon DocumentDB Deletion Protection
Ensure that Deletion Protection feature is enabled for your DocumentDB database clusters.
Enable DocumentDB Profiler
Ensure that the Profiler feature is enabled for your DocumentDB database clusters.
Log Exports
Enable AWS DocumentDB Log Exports.
Rotate SSL/TLS Certificates for DocumentDB Cluster Instances
Ensure that SSL/TLS certificates for DocumentDB database instances are rotated according to the AWS schedule.
Amazon DynamoDB
Configure DynamoDB Table Class for Cost Optimization
Use Amazon DynamoDB Standard-IA table class for cost optimization.
DynamoDB Backup and Restore
Ensure on-demand backup and restore functionality is in use for AWS DynamoDB tables.
DynamoDB Continuous Backups
Enable DynamoDB Continuous Backups
Enable CloudWatch Contributor Insights
Ensure that CloudWatch Contributor Insights is enabled for Amazon DynamoDB tables.
Enable Deletion Protection
Ensure that Deletion Protection feature is enabled for your Amazon DynamoDB tables.
Enable Encryption at Rest with Amazon KMS Keys
Use KMS keys for encryption at rest in Amazon DynamoDB.
Enable Time To Live (TTL)
Ensure that Time To Live (TTL) is enabled for your Amazon DynamoDB tables.
Log DynamoDB Changes using Kinesis Data Streams
Ensure that Amazon DynamoDB changes are logged using Kinesis Data Streams.
Sufficient Backup Retention Period
Ensure that DynamoDB tables have a sufficient backup retention period configured for compliance purposes.
Unused Table
Identify and remove any unused AWS DynamoDB tables to optimize AWS costs.
Amazon Elastic Block Store (EBS)
Amazon EBS Public Snapshots
Ensure that your Amazon EBS volume snapshots are not accessible to all AWS accounts.
App-Tier EBS Encrypted
Ensure app-tier Amazon Elastic Block Store (EBS) volumes are encrypted.
EBS Encrypted
Ensure EBS volumes are encrypted to meet security and encryption compliance requirements. Encryption is a key mechanism for you to ensure that you are in full control over who has access to your data.
EBS Encrypted With KMS Customer Master Keys
Ensure EBS volumes are encrypted with CMKs to have full control over encrypting and decrypting data.
EBS General Purpose SSD
Ensure EC2 instances are using General Purpose SSD (gp2) EBS volumes instead of Provisioned IOPS SSD (io1) volumes to optimize AWS EBS costs.
EBS Snapshot Encrypted
Ensure Amazon EBS snapshots are encrypted to meet security and compliance requirements.
EBS Volume Naming Conventions
Ensure EBS volumes are using proper naming conventions to follow AWS tagging best practices.
EBS Volumes Attached To Stopped EC2 Instances
Identify Amazon EBS volumes attached to stopped EC2 instances (i.e. unused EBS volumes).
EBS Volumes Recent Snapshots
Ensure AWS Elastic Block Store (EBS) volumes have recent snapshots available for point-in-time recovery.
EBS Volumes Too Old Snapshots
Identify and remove old AWS Elastic Block Store (EBS) volume snapshots for cost optimization.
Enable Encryption by Default for EBS Volumes
Ensure that your new Amazon EBS volumes are always encrypted in the specified AWS region.
Idle EBS Volume
Identify idle AWS EBS volumes and delete them in order to optimize your AWS costs.
Unused EBS Volumes
Identify and remove any unused Elastic Block Store volumes to improve cost optimization and security.
Use Customer Master Keys for EBS Default Encryption
Ensure that your new EBS volumes are always encrypted with KMS Customer Master Keys.
Web-Tier EBS Encrypted
Ensure web-tier Amazon Elastic Block Store (EBS) volumes are encrypted.
Amazon EC2
AMI Naming Conventions
Follow proper naming conventions for Amazon Machine Images.
AWS AMI Encryption
Ensure that your existing AMIs are encrypted to meet security and compliance requirements.
Allowed AMIs Feature in Use
Ensure that Allowed AMIs feature is enabled in Amazon EC2.
App-Tier EC2 Instance Using IAM Roles
Ensure that your app-tier EC2 instances are using IAM roles to grant permissions to applications running on these instances.
App-Tier Publicly Shared AMI
Ensure app-tier AMIs aren't publicly shared to avoid exposing sensitive data.
Approved/Golden AMIs
Ensure all EC2 instances are launched from your approved AMIs.
Blocklisted AMIs
Ensure no EC2 instance is launched from any blocklisted AMIs
Check for EC2 Instances with Blocklisted Instance Types
Ensure there is no EC2 instance with the instance type blocklisted, available in your AWS account.
Check for Unrestricted Memcached Access
Ensure that no security group allows unrestricted inbound access on TCP/UDP port 11211 (Memcached).
Check for Unrestricted Redis Access
Ensure that no security group allows unrestricted inbound access on TCP port 6379 (Redis).
Default Security Group Unrestricted
Ensure the default security group of every VPC restricts all traffic.
Default Security Groups In Use
Ensure default security groups aren't in use. Instead create unique security groups to better adhere to the principle of least privilege.
Descriptions for Security Group Rules
Ensure AWS EC2 security group rules have descriptive text for organization and documentation.
Disable Public IP Address Assignment for EC2 Instances
Ensure that Amazon EC2 instances are not using public IP addresses.
EC2 AMI Too Old
Ensure EC2 Amazon Machine Images (AMIs) aren't too old
EC2 Desired Instance Type
Ensure all EC2 instances are of a given instance type.
EC2 Hibernation
Enable hibernation as an additional stop behavior for your EC2 instances backed by Amazon EBS in order to reduce the time it takes for these instances to return to service at restart.
EC2 Instance Counts
Ensure fewer EC2 instances than provided count in your account
EC2 Instance Dedicated Tenancy
Ensure dedicated EC2 instances are regularly reviewed
EC2 Instance Detailed Monitoring
Ensure that detailed monitoring is enabled for the AWS EC2 instances that you need to monitor closely.
EC2 Instance Generation
Ensure you always use the latest generation of EC2 instances to get better performance with lower cost.
EC2 Instance In VPC
Ensure EC2 instances are launched using the EC2-VPC platform instead of EC2-Classic outdated platform.
EC2 Instance Naming Conventions
Follow proper naming conventions for EC2 instances.
EC2 Instance Not In Public Subnet
Ensure that no backend EC2 instances are provisioned in public subnets.
EC2 Instance Scheduled Events
Identify any AWS EC2 instances that have scheduled events and take action to resolve them.
EC2 Instance Security Group Rules Counts
Determine if there is a large number of security group rules applied to an instance.
EC2 Instance Tenancy
Ensure EC2 instances have desired tenancy for compliance and regulatory requirements.
EC2 Instance Termination Protection
Ensure termination protection safety feature is enabled for ec2 instances that aren't part of ASGs
EC2 Instance Too Old
Ensure EC2 instances aren't too old.
EC2 Instance Using IAM Roles
Ensure IAM instance roles are used for AWS resource access from instances.
EC2 Instances Scanned by Amazon Inspector Classic
Ensure that all Amazon EC2 instances are successfully scanned by an Inspector Classic assessment run.
EC2 Instances with Multiple Elastic Network Interfaces
Ensure that Amazon EC2 instances are not using multiple ENIs.
EC2 Instances with Public IP Addresses or Available in Public Subnets
Ensure no backend EC2 instances are running in public subnets or having public IP addresses.
EC2 Reserved Instance Payment Failed
Ensure EC2 Reserved Instances purchases haven't failed.
EC2 Reserved Instance Payment Pending
Ensure EC2 Reserved Instances purchases aren't pending
EC2 Reserved Instance Recent Purchases
Ensure EC2 Reserved Instances purchases are regularly reviewed.
EC2-Classic Elastic IP Address Limit
Determine if the number of allocated EC2-Classic EIPs per region is close to Elastic IP Address Limit.
EC2-VPC Elastic IP Address Limit
Determine if the number of allocated EC2-VPC EIPs per region is close to Elastic IP Address Limit.
Enable Capacity Rebalancing
Ensure that Capacity Rebalancing is enabled for your Amazon Auto Scaling Groups.
Idle EC2 Instance
Identify any Amazon EC2 instances that appear to be idle and stop or terminate them to help lower the cost of your monthly AWS bill.
Instance In Auto Scaling Group
Ensure every EC2 instance is launched inside an Auto Scaling Group (ASG) in order to follow AWS reliability and security best practices.
Overutilized AWS EC2 Instances
Identify any Amazon EC2 instances that appear to be overutilized and upgrade (resize) them in order to help your EC2-hosted applications to handle better the workload and improve the response time.
Publicly Shared AMI
Ensure AMIs aren't publicly shared to avoid exposing sensitive data.
Require IMDSv2 for EC2 Instances
Ensure that all the Amazon EC2 instances require the use of Instance Metadata Service Version 2 (IMDSv2).
Reserved Instance Lease Expiration In The Next 30 Days
Ensure Amazon EC2 Reserved Instances (RI) are renewed before expiration.
Reserved Instance Lease Expiration In The Next 7 Days
Ensure Amazon EC2 Reserved Instances (RI) are renewed before expiration.
Security Group Excessive Counts
Determine if there is an excessive number of security groups per region
Security Group Large Counts
Determine if there is a large number of security groups per region
Security Group Name Prefixed With 'launch-wizard'
Ensure no security group name is prefixed with 'launch-wizard'.
Security Group Naming Conventions
Follow proper naming conventions for security groups
Security Group Port Range
Ensure no security group opens range of ports.
Security Group Rules Counts
Determine if there is a large number of rules in a security group.
SecurityGroup RFC 1918
Ensure no security group contains RFC 1918 CIDRs
Unassociated IP Addresses
Identify and remove any unassociated Elastic IP (EIP) and Carrier IP addresses for cost optimization.
Underutilized EC2 Instance
Identify underutilized EC2 instances and downsize them in order to optimize your AWS costs
Unrestricted CIFS Access
Ensure no security group allows unrestricted inbound access to UDP port 445 (CIFS).
Unrestricted DNS Access
Ensure no security group allows unrestricted ingress access to port 53.
Unrestricted FTP Access
Ensure no security group allows unrestricted inbound access to TCP ports 20 and 21 (FTP).
Unrestricted HTTP Access
Ensure no security group allows unrestricted inbound access to TCP port 80 (HTTP).
Unrestricted HTTPS Access
Ensure no security group allows unrestricted inbound access to TCP port 443 (HTTPS).
Unrestricted ICMP Access
Ensure no security group allows unrestricted inbound access to ICMP.
Unrestricted MongoDB Access
Ensure no security group allows unrestricted ingress access to MongoDB port 27017
Unrestricted MsSQL Access
Ensure no security group allows unrestricted ingress access to port 1433.
Unrestricted MySQL Access
Ensure no security group allows unrestricted ingress access to port 3306.
Unrestricted NetBIOS Access
Ensure no security group allows unrestricted inbound access to port UDP/137, UDP/138, and TPC/139 (NetBIOS).
Unrestricted OpenSearch Access
Ensure no security group allows unrestricted inbound access to TCP port 9200 (OpenSearch).
Unrestricted Oracle Access
Ensure no security group allows unrestricted ingress access to port 1521.
Unrestricted PostgreSQL Access
Ensure no security group allows unrestricted ingress access to port 5432.
Unrestricted RDP Access
Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389.
Unrestricted RPC Access
Ensure no security group allows unrestricted inbound access to TCP port 135 (RPC).
Unrestricted SMTP Access
- Ensure no security group allows unrestricted inbound access to TCP port 25 (SMTP).
Unrestricted SSH Access
Ensure no security groups allow ingress from 0.0.0.0/0 to port 22.
Unrestricted Security Group Egress
Ensure no security group contains any 0.0.0.0/0 egress rules
Unrestricted Security Group Ingress on Uncommon Ports
Ensure no security group contains any 0.0.0.0/0 ingress rules.
Unrestricted Telnet Access
Ensure no security group allows unrestricted inbound access to TCP port 23 (Telnet).
Unused AMI
Identify unused Amazon Machine Images (AMI), and delete them to help lower the cost of your monthly AWS bill.
Unused AWS EC2 Key Pairs
Ensure unused AWS EC2 key pairs are decommissioned to follow AWS security best practices.
Unused EC2 Reserved Instances
Ensure that your Amazon EC2 Reserved Instances are being fully utilized.
Unused Elastic Network Interfaces
Identify and delete any unused Elastic Network Interfaces
Web-Tier EC2 Instance Using IAM Roles
Ensure web-tier IAM instance roles are used for AWS resource access from instances.
Web-Tier Publicly Shared AMI
Ensure web-tier AMIs aren't publicly shared to avoid exposing sensitive data.
vCPU-Based EC2 Instance Limit
Ensure that your EC2 instances do not reach the limit set by AWS for the number of vCPUs.
Amazon Elastic Container Registry
ECR Repository Exposed
Ensure that AWS Elastic Container Registry (ECR) repositories are not exposed to everyone.
Enable Automated Scanning for Amazon ECR Container Images
Ensure that each Amazon ECR container image is automatically scanned for vulnerabilities.
Enable Cross-Region Replication
Ensure that Cross-Region Replication feature is enabled for your Amazon ECR container images.
Lifecycle Policy in Use
Ensure that Amazon ECR image repositories are using lifecycle policies for cost optimization.
Repository Cross Account Access
Ensure that Amazon ECR repositories do not allow unknown cross account access.
Amazon Elastic Container Service (ECS)
Amazon ECS Task Log Driver in Use
Ensure that a log driver has been defined for each active Amazon ECS task definition.
Check for Amazon ECS Service Placement Strategy
Ensure that your Amazon ECS cluster services are using optimal placement strategies.
Check for ECS Container Instance Agent Version
Ensure that your Amazon ECS instances are using the latest ECS container agent version.
Check for Fargate Platform Version
Ensure that your Amazon ECS cluster services are using the latest Fargate platform version.
Enable CloudWatch Container Insights
Ensure that CloudWatch Container Insights feature is enabled for your AWS ECS clusters.
Monitor Amazon ECS Configuration Changes
Amazon Elastic Container Service (ECS) configuration changes have been detected in your AWS account.
Amazon Elastic File System (EFS)
AWS KMS Customer Master Keys for EFS Encryption
Ensure EFS file systems are encrypted with KMS Customer Master Keys (CMKs) in order to have full control over data encryption and decryption.
EFS Encryption Enabled
Ensure encryption is enabled for AWS EFS file systems to protect your data at rest.
Amazon Elastic Kubernetes Service (EKS)
Check for the CoreDNS Add-On Version
Ensure that the CoreDNS add-on version matches the EKS cluster's Kubernetes version.
Disable Remote Access to EKS Cluster Node Groups
Ensure that remote access to EKS cluster node groups is disabled.
EKS Cluster Endpoint Public Access
Ensure that AWS EKS cluster endpoint access isn't public and prone to security risks.
EKS Cluster Node Group IAM Role Policies
Ensure that EKS Cluster node groups are using appropriate permissions.
EKS Security Groups
Ensure that AWS EKS security groups are configured to allow incoming traffic only on TCP port 443.
Enable CloudTrail Logging for Kubernetes API Calls
Ensure that all Kubernetes API calls are logged using Amazon CloudTrail.
Enable Cluster Access Management API
Ensure that Cluster Access Management API is enabled for Amazon EKS clusters.
Enable Envelope Encryption for EKS Kubernetes Secrets
Ensure that envelope encryption of Kubernetes secrets using Amazon KMS is enabled.
Enable Support for Network Policies
Ensure that EKS clusters are using network policies for proper segmentation and security.
Kubernetes Cluster Logging
Ensure that EKS control plane logging is enabled for your Amazon EKS clusters.
Kubernetes Cluster Version
Ensure that the latest version of Kubernetes is installed on your Amazon EKS clusters.
Monitor Amazon EKS Configuration Changes
Amazon EKS configuration changes have been detected within your Amazon Web Services account.
Use AWS-managed policy to Manage Networking Resources
Ensure that EKS cluster node groups implement the "AmazonEKS_CNI_Policy" managed policy.
Use AWS-managed policy to access Amazon ECR Repositories
Ensure that EKS cluster node groups implement the "AmazonEC2ContainerRegistryReadOnly" managed policy.
Use AWS-managed policy to manage AWS resources
Ensure that Amazon EKS clusters implement the "AmazonEKSClusterPolicy" managed policy.
Use OIDC Provider for Authenticating Kubernetes API Calls
Ensure that Amazon EKS clusters are using an OpenID Connect (OIDC) provider.
Elastic Load Balancing
App-Tier ELB Listener Security
Ensure app-tier ELB listener uses a secure HTTPS or SSL protocol.
App-Tier ELB Security Policy
Ensure app-tier ELBs use the latest predefined security policies.
App-Tier ELBs Health Check
Ensure app tier Elastic Load Balancer has application layer health check configured.
Classic Load Balancer
Ensure HTTP/HTTPS applications are using Application Load Balancer instead of Classic Load Balancer for cost and web traffic distribution optimization.
Configure HTTP Desync Mitigation Mode for Classic Load Balancers
Ensure that the suitable Desync Mitigation mode is configured for your Classic Load Balancers.
ELB Access Log
Ensure ELB access logging is enabled for security, troubleshooting, and statistical analysis purposes
ELB Connection Draining Enabled
Ensure connection draining is enabled for all load balancers.
ELB Cross-Zone Load Balancing Enabled
Ensure Cross-Zone Load Balancing is enabled for all load balancers. Also select at least two subnets in different availability zones to provide higher availability.
ELB Insecure SSL Ciphers
Ensure ELBs don't use insecure SSL ciphers.
ELB Insecure SSL Protocols
Ensure ELBs don't use insecure SSL protocols.
ELB Instances Distribution Across AZs
Ensure even distribution of backend instances registered to an ELB across Availability Zones.
ELB Listener Security
Ensure ELB listener uses a secure HTTPS or SSL protocol.
ELB Minimum Number Of EC2 Instances
Ensure there is a minimum number of two healthy backend instances associated with each ELB.
ELB Security Group
Check your Elastic Load Balancer (ELB) security layer for at least one valid security group that restricts access only to the ports defined in the load balancer listener's configuration
ELB Security Policy
Ensure ELBs use the latest predefined security policies.
Idle Elastic Load Balancer
Identify idle Elastic Load Balancers (ELBs) and terminate them in order to optimize AWS costs.
Internet Facing ELBs
Ensure Amazon internet-facing ELBs/ALBs are regularly reviewed for security purposes.
Unused Elastic Load Balancers
Identify unused Elastic Load Balancers, and delete them to help lower the cost of your monthly AWS bill.
Web-Tier ELB Listener Security
Ensure web-tier ELB listener uses a secure HTTPS or SSL protocol.
Web-Tier ELB Security Policy
Ensure web-tier ELBs use the latest predefined security policies.
Web-Tier ELBs Health Check
Ensure web tier Elastic Load Balancer has application layer health check configured.
Elastic Load Balancing V2
Configure HTTP Desync Mitigation Mode for Application Load Balancers
Ensure that the suitable Desync Mitigation mode is configured for your Application Load Balancers.
Configure Multiple Availability Zones for Gateway Load Balancers
Ensure that Amazon Gateway Load Balancers are using Multi-AZ configurations.
Drop Invalid Header Fields for Application Load Balancers
Ensure that Drop Invalid Header Fields feature is enabled for your Application Load Balancers to remove non-standard headers.
ELBv2 ALB Listener Security
Ensure ELBv2 ALBs are using a secure protocol.
ELBv2 ALB Security Group
Ensure ELBv2 load balancers have secure and valid security groups.
ELBv2 ALB Security Policy
Ensure that Amazon ALBs are using the latest predefined security policy for their SSL negotiation configuration in order to follow security best practices and protect their front-end connections against SSL/TLS vulnerabilities.
ELBv2 Access Log
Ensure that Amazon ALBs have Access Logging feature enabled for security, troubleshooting and statistical analysis purposes.
ELBv2 Elastic Load Balancing Deletion Protection
Ensure ELBv2 Load Balancers have Deletion Protection feature enabled in order to protect them from being accidentally deleted.
ELBv2 Minimum Number of EC2 Target Instances
Ensure there is a minimum number of two healthy target instances associated with each AWS ELBv2 load balancer.
ELBv2 NLB Listener Security
Ensure that your AWS Network Load Balancer listeners are using a secure protocol such as TLS.
Enable Amazon WAF Integration for Application Load Balancers
Use Amazon WAF to protect Application Load Balancers from common web exploits.
Enable Cross-Zone Load Balancing
Ensure fault tolerance for your Amazon Gateway Load Balancers by enabling Cross-Zone Load Balancing.
Enable Deletion Protection
Ensure that Deletion Protection is enabled for Amazon Gateway Load Balancers.
Enable HTTP to HTTPS Redirect for Application Load Balancers
Ensure that your Application Load Balancers have a rule that redirects HTTP traffic to HTTPS.
Enable Least Outstanding Requests Algorithm
Ensure that Least Outstanding Requests (LOR) algorithm is enabled for your AWS Application Load Balancers (ALBs).
Enable Support for HTTP/2
Ensure that HTTP/2 support is enabled for Amazon Application Load Balancers (ALBs).
Enable Support for gRPC Protocol
Ensure that support for gRPC protocol is enabled for Application Load Balancers (ALBs).
Enable TLS ALPN Policy for Network Load Balancers
Ensure that your AWS Network Load Balancers are using TLS ALPN policies.
Internet Facing ELBv2 Load Balancers
Ensure Amazon internet-facing ELBv2 Load Balancers are regularly reviewed for security purposes.
Network Load Balancer Security Policy
Ensure Amazon Network Load Balancers (NLBs) are using the latest recommended predefined security policy for TLS negotiation configuration.
Unused ELBv2 Load Balancers
Identify unused ELBv2 Elastic Load Balancers, and delete them to help lower the cost of your monthly AWS bill.
Amazon EMR
AWS EMR Instance Type Generation
Ensure AWS EMR clusters are using the latest generation of instances for performance and cost optimization.
Block Public Access to Amazon EMR Clusters
Enable the Block Public Access feature for Amazon EMR clusters in the specified AWS region.
Cluster in VPC
Ensure that your Amazon Elastic MapReduce clusters are provisioned using the AWS EC2-VPC platform instead of EC2-Classic platform.
EMR Cluster Logging
Ensure AWS Elastic MapReduce clusters capture detailed log data to Amazon S3.
EMR Desired Instance Type
Ensure that all your Amazon EMR cluster instances are of given instance types.
EMR In-Transit and At-Rest Encryption
Ensure that your AWS Elastic MapReduce clusters are encrypted in order to meet security and compliance requirements.
EMR Instances Counts
Ensure fewer Amazon EMR cluster instances than the provided limit in your AWS account.
Use Customer Master Keys for EMR Log Files Encryption
Ensure that Amazon EMR log files are encrypted with KMS Customer Master Keys (CMKs).
Amazon ElastiCache
Configure Preferred Maintenance Window for ElastiCache Clusters
Ensure there is a preferred maintenance window configured for your Amazon ElastiCache clusters.
ElastiCache Cluster Default Port
Ensure that AWS ElastiCache clusters aren't using their default endpoint ports.
ElastiCache Cluster In VPC
Ensure Amazon ElastiCache clusters are deployed into a Virtual Private Cloud.
ElastiCache Desired Node Type
Ensure that all your Amazon ElastiCache cluster cache nodes are of given types.
ElastiCache Engine Version
Ensure that your Amazon ElastiCache clusters are using the stable latest version of Redis/Memcached cache engine.
ElastiCache Instance Generation
Ensure ElastiCache clusters are using the latest generation of nodes for cost and performance improvements.
ElastiCache Nodes Counts
Ensure your AWS account hasn't reached the limit set for the number of ElastiCache cluster nodes.
ElastiCache Redis In-Transit and At-Rest Encryption
Ensure that your AWS ElastiCache Redis clusters are encrypted in order to meet security and compliance requirements.
ElastiCache Redis Multi-AZ
Ensure Amazon ElastiCache Redis clusters have the Multi-AZ feature enabled.
ElastiCache Reserved Cache Node Coverage
Ensure that your Amazon ElastiCache usage is covered by ElastiCache cluster node reservations.
ElastiCache Reserved Cache Node Lease Expiration In The Next 30 Days
Ensure Amazon ElastiCache Reserved Cache Nodes (RCN) are renewed before expiration.
ElastiCache Reserved Cache Node Lease Expiration In The Next 7 Days
Ensure Amazon ElastiCache Reserved Cache Nodes (RCN) are renewed before expiration.
ElastiCache Reserved Cache Node Payment Failed
Ensure AWS ElastiCache Reserved Node purchases have not failed.
ElastiCache Reserved Cache Node Payment Pending
Ensure AWS ElastiCache Reserved Node purchases are not pending.
ElastiCache Reserved Cache Node Recent Purchases
Ensure ElastiCache Reserved Cache Node purchases are regularly reviewed for cost optimization (informational).
ElastiCache Reserved Cache Nodes Expiration
Ensure that Amazon ElastiCache Reserved Nodes are renewed before expiration.
Enable Automatic Backups
Ensure that automatic backups are enabled for Amazon ElastiCache Redis cache clusters.
Enable Event Notifications
Ensure that event notifications via Amazon SNS are enabled for Amazon ElastiCache clusters.
Idle AWS ElastiCache Nodes
Identify any idle AWS ElastiCache nodes and terminate them in order to optimize your AWS costs.
Sufficient Backup Retention Period
Ensure that Redis cache clusters have a sufficient backup retention period configured for compliance purposes.
Unused ElastiCache Reserved Cache Nodes
Ensure that your ElastiCache Reserved Cache Nodes are being utilized.
AWS Elastic Beanstalk
Elastic Beanstalk Enhanced Health Reporting
Ensure Enhanced Health Reporting is enabled for your AWS Elastic Beanstalk environment(s).
Elastic Beanstalk Managed Platform Updates
Ensure managed platform updates are enabled for your AWS Elastic Beanstalk environment(s).
Elastic Beanstalk Persistent Logs
Ensure persistent logs are enabled for your Amazon Elastic Beanstalk environment(s).
Enable AWS X-Ray Daemon
Ensure that X-Ray tracing is enabled for your Amazon Elastic Beanstalk environments.
Enable Access Logs
Ensure that access logging is enabled for your Elastic Beanstalk environment load balancer.
Enable Elastic Beanstalk Environment Notifications
Enable alert notifications for important events triggered within your Amazon Elastic Beanstalk environment.
Enforce HTTPS
Enforce HTTPS for Amazon Elastic Beanstalk environment load balancers.
Amazon Opensearch Service
AWS OpenSearch Slow Logs
Ensure that your AWS OpenSearch domains publish slow logs to AWS CloudWatch Logs.
Check for IP-Based Access
Ensure that only approved IP addresses can access your Amazon OpenSearch domains.
Cluster Status
Ensure that your Amazon OpenSearch clusters are healthy (Green).
Enable Audit Logs
Ensure that audit logging is enabled for all your Amazon OpenSearch domains.
Enable In-Transit Encryption
Ensure that in-transit encryption is enabled for your Amazon OpenSearch domains.
Encryption At Rest
Ensure that your Amazon OpenSearch domains are encrypted in order to meet security and compliance requirements.
Idle OpenSearch Domains
Identify idle Amazon OpenSearch domains and delete them in order to optimize AWS costs.
OpenSearch Accessible Only From Safelisted IP Addresses
Ensure only safelisted IP addresses can access your Amazon OpenSearch domains.
OpenSearch Cross Account Access
Ensure Amazon OpenSearch clusters don't allow unknown cross account access.
OpenSearch Dedicated Master Enabled
Ensure Amazon OpenSearch clusters are using dedicated master nodes to increase the production environment stability.
OpenSearch Desired Instance Type(s)
Ensure that Amazon OpenSearch cluster instances are of given instance type.
OpenSearch Domain Exposed
Ensure Amazon OpenSearch domains aren't exposed to everyone.
OpenSearch Domain In VPC
Ensure that your Amazon OpenSearch domains are accessible only from AWS VPCs.
OpenSearch Domains Encrypted with KMS CMKs
Ensure that your OpenSearch domains are encrypted using KMS Customer-Managed Keys.
OpenSearch Free Storage Space
Identify OpenSearch clusters with low free storage space and scale them to optimize their performance.
OpenSearch General Purpose SSD
Ensure OpenSearch nodes are using General Purpose SSD storage instead of Provisioned IOPS SSD storage to optimize the service costs.
OpenSearch Node To Node Encryption
Ensure that your Amazon OpenSearch clusters are using node to node encryption in order to meet security and compliance requirements.
OpenSearch Reserved Instance Coverage
Ensure that your Amazon OpenSearch usage is covered by RI reservations in order to optimize AWS costs.
OpenSearch Reserved Instance Lease Expiration In The Next 30 Days
Ensure Amazon OpenSearch Reserved Instances are renewed before expiration.
OpenSearch Reserved Instance Lease Expiration In The Next 7 Days
Ensure that Amazon OpenSearch Reserved Instances are renewed before expiration.
OpenSearch Version
Ensure that the latest version of OpenSearch engine is used for your OpenSearch domains.
OpenSearch Zone Awareness Enabled
Ensure high availability for your Amazon OpenSearch clusters by enabling the Zone Awareness feature.
Reserved Instance Payment Pending Purchases
Ensure that none of your Amazon OpenSearch Reserved Instance purchases are pending.
Reserved Instance Purchase State
Ensure that none of your Amazon OpenSearch Reserved Instance purchases have been failed.
Review Reserved Instance Purchases
Ensure that OpenSearch Reserved Instance purchases are regularly reviewed for cost optimization (informational).
TLS Security Policy Version
Ensure that your OpenSearch domains are using the latest version of the TLS security policy.
Total Number of OpenSearch Cluster Nodes
Ensure there are fewer OpenSearch cluster nodes than the established limit
Amazon FSx
Use KMS Customer Master Keys for FSx Windows File Server File Systems
Ensure AWS FSx for Windows File Server file systems data is encrypted using AWS KMS CMKs.
Amazon Kinesis Data Firehose
Enable Firehose Delivery Stream Server-Side Encryption
Ensure that Kinesis Data Firehose delivery streams enforce Server-Side Encryption, ideally using Customer-managed Customer Master Keys.
Firehose Delivery Stream Destination Encryption
Ensure that Firehose delivery stream data records are encrypted at destination.
AWS Glue
CloudWatch Logs Encryption Mode
Ensure that at-rest encryption is enabled when writing Amazon Glue logs to CloudWatch Logs.
Glue Data Catalog Encrypted With KMS Customer Master Keys
Ensure that Amazon Glue Data Catalogs enforce data-at-rest encryption using KMS CMKs.
Glue Data Catalog Encryption At Rest
Ensure that Amazon Glue Data Catalog objects and connection passwords are encrypted.
Job Bookmark Encryption Mode
Ensure that encryption at rest is enabled for Amazon Glue job bookmarks.
S3 Encryption Mode
Ensure that at-rest encryption is enabled when writing AWS Glue data to Amazon S3.
Amazon Guard​Duty
AWS GuardDuty Configuration Changes
GuardDuty configuration changes have been detected within your Amazon Web Services account.
Enable Malware Protection for Amazon EC2
Ensure that Amazon GuardDuty detectors are configured to use Malware Protection for EC2.
Enable Malware Protection for Amazon S3
Ensure that Amazon GuardDuty detectors are configured to use Malware Protection for S3.
Enable S3 Protection
Ensure that Amazon GuardDuty detectors are configured to use S3 Protection.
GuardDuty Enabled
Ensure Amazon GuardDuty is enabled to help you protect your AWS accounts and workloads against security threats.
GuardDuty Findings
Ensure that Amazon GuardDuty findings are highlighted, audited and resolved.
AWS Health
Health Events
Provides real-time insights into the state of your AWS environment and infrastructure.
AWS Identity and Access Management (IAM)
AWS Account Root User Activity
Monitor AWS Account Root User Activity
AWS IAM Server Certificate Size
Ensure that all your SSL/TLS certificates are using either 2048 or 4096 bit RSA keys instead of 1024-bit keys.
AWS Multi-Account Centralized Management
Set up, organize and manage your AWS accounts for optimal security and manageability.
Access Keys During Initial IAM User Setup
Ensure no access keys are created during IAM user initial setup with AWS Management Console.
Access Keys Rotated 30 Days
Ensure AWS IAM access keys are rotated on a periodic basis as a security best practice (30 Days).
Access Keys Rotated 45 Days
Ensure AWS IAM access keys are rotated on a periodic basis as a security best practice (45 Days).
Access Keys Rotated 90 Days
Ensure AWS IAM access keys are rotated on a periodic basis as a security best practice (90 Days).
Account Alternate Contacts
Ensure alternate contacts are set to improve the security of your AWS account.
Account Security Challenge Questions
Ensure security challenge questions are enabled and configured to improve the security of your AWS account.
Allow IAM Users to Change Their Own Password
Ensure that all IAM users are allowed to change their own console password.
Amazon EC2 Purchase Restriction
Restrict unintended IAM users from purchasing Amazon EC2 Reserved Instances and/or Savings Plans.
Approved ECS Execute Command Access
Ensure that all access to the ECS Execute Command action is approved
Attach Policy to IAM Roles Associated with App-Tier EC2 Instances
Ensure IAM policy for EC2 IAM roles for app tier is configured.
Attach Policy to IAM Roles Associated with Web-Tier EC2 Instances
Ensure IAM policy for EC2 IAM roles for web tier is configured.
Canary Access Token
Detects when a canary token access key has been used
Check for IAM User Group Membership
Ensure that all Amazon IAM users have group memberships.
Check for IAM Users with Compromised Credentials
Identify IAM users with compromised credentials by checking for the presence of "AWSCompromisedKeyQuarantine" policies.
Check for Individual IAM Users
Ensure there is at least one IAM user used to access your AWS cloud account.
Check for Overly Permissive IAM Group Policies
Ensure that Amazon IAM policies attached to IAM groups aren't too permissive.
Check for Untrusted Cross-Account IAM Roles
Ensure that AWS IAM roles cannot be used by untrusted accounts via cross-account access feature.
Check that only safelisted IAM Users exist
Ensure that only safelisted IAM Users exist within your AWS account.
Credentials Last Used
Ensure that unused AWS IAM credentials are decommissioned to follow security best practices.
Cross-Account Access Lacks External ID and MFA
Ensure cross-account access roles are using Multi-Factor Authentication (MFA) or External IDs.
Enable MFA for IAM Users with Console Password
Ensure that Multi-Factor Authentication (MFA) is enabled for all Amazon IAM users with console access.
Enforce Infrastructure as Code using IAM Policies
Enforce Infrastructure as Code by controlling access for requests made on your behalf.
Expired SSL/TLS Certificate
Ensure expired SSL/TLS certificates are removed from AWS IAM.
Hardware MFA for AWS Root Account
Ensure hardware MFA is enabled for the 'root' account.
IAM Access Analyzer in Use
Ensure that IAM Access Analyzer feature is enabled to maintain access security to your AWS resources.
IAM Configuration Changes
AWS IAM configuration changes have been detected within your Amazon Web Services account.
IAM CreateLoginProfile detected
AWS IAM 'CreateLoginProfile' call has been detected within your Amazon Web Services account.
IAM Group With Inline Policies
Ensure IAM groups don't have inline policies attached.
IAM Groups with Administrative Privileges
Ensure there are no IAM groups with administrative permissions available in your AWS cloud account.
IAM Master and IAM Manager Roles (Deprecated)
Ensure that IAM Master and IAM Manager roles are active in your AWS cloud account.
IAM Password Policy
Ensure that your AWS cloud account has a strong IAM password policy in use.
IAM Policies With Full Administrative Privileges
Ensure IAM policies that allow full '*:*' administrative privileges aren't created.
IAM Policies with Effect Allow and NotAction
Ensure that IAM policies do not use "Effect": "Allow" in combination with "NotAction" element to follow IAM security best practices.
IAM Role Policy Too Permissive
Ensure that the access policies attached to your IAM roles adhere to the principle of least privilege.
IAM Roles Should Not be Assumed by Multiple Services
Ensure that Amazon IAM roles can only be assumed by a single, trusted service.
IAM Support Role
Ensure there is an active IAM Support Role available within your AWS cloud account.
IAM User Password Expiry 30 Days
Ensure AWS Identity and Access Management (IAM) user passwords are reset before expiration (30 Days).
IAM User Password Expiry 45 Days
Ensure AWS Identity and Access Management (IAM) user passwords are reset before expiration (45 Days).
IAM User Password Expiry 7 Days
Ensure AWS Identity and Access Management (IAM) user passwords are reset before expiration (7 Days).
IAM User Policies
Ensure AWS IAM policies are attached to groups instead of users as an IAM best practice.
IAM User with Password and Access Keys
Ensure that IAM users have either API access or console access in order to follow IAM security best practices.
IAM Users Unauthorized to Edit Access Policies
Ensure AWS IAM users that are not authorized to edit IAM access policies are decommissioned..
IAM Users with Administrative Privileges
Ensure there are no IAM users with administrative permissions available in your AWS cloud account.
Inactive IAM Console User
Ensure no AWS IAM users have been inactive for a long (specified) period of time.
MFA Device Deactivated
A Multi-Factor Authentication (MFA) device deactivation for an IAM user has been detected.
Pre-Heartbleed Server Certificates
Ensure that your server certificates are not vulnerable to Heartbleed security bug.
Prevent IAM Role Chaining
Ensure that IAM Role Chaining is not used within your AWS environment.
Receive Permissions via IAM Groups Only
Ensure that IAM users receive permissions only through IAM groups.
Root Account Access Keys Present
Ensure that your AWS root account is not using access keys as a security best practice.
Root Account Active Signing Certificates
Ensure that your AWS root account user is not using X.509 certificates to validate API requests.
Root Account Credentials Usage
Ensure that root account credentials have not been used recently to access your AWS account.
Root MFA Enabled
Ensure that Multi-Factor Authentication (MFA) is enabled for your AWS root account.
SSH Public Keys Rotated 30 Days
Ensure AWS IAM SSH public keys are rotated on a periodic basis as a security best practice.
SSH Public Keys Rotated 45 Days
Ensure IAM SSH public keys are rotated on a periodic basis to adhere to AWS security best practices.
SSH Public Keys Rotated 90 Days
Ensure IAM SSH public keys are rotated on a periodic basis to adhere to AWS security best practices.
SSL/TLS Certificate Expiry 30 Days
Ensure SSL/TLS certificates are renewed before their expiration.
SSL/TLS Certificate Expiry 45 Days
Ensure SSL/TLS certificates are renewed before their expiration.
SSL/TLS Certificate Expiry 7 Days
Ensure SSL/TLS certificates are renewed before their expiration.
Sign-In Events
AWS sign-in events for IAM and federated users have been detected.
Unapproved IAM Policy in Use
Ensure there are no unapproved AWS Identity and Access Management (IAM) policies in use.
Unnecessary Access Keys
Ensure there is a maximum of one active access key pair available for any single IAM user.
Unnecessary IAM Users
Require your human users to use temporary credentials instead of long-term credentials when accessing AWS cloud.
Unnecessary SSH Public Keys
Ensure there is a maximum of one active SSH public keys assigned to any single IAM user.
Unused IAM Group
Ensure all IAM groups have at least one user.
Unused IAM User
Ensure unused IAM users are removed from AWS account to follow security best practice.
Valid IAM Identity Providers
Ensure valid IAM Identity Providers are used within your AWS account for secure user authentication and authorization.
Amazon Inspector
Amazon Inspector Findings
Ensure that Amazon Inspector Findings are analyzed and resolved.
Check for Amazon Inspector Exclusions
Ensure there are no exclusions found by Amazon Inspector assessment runs.
Days since last Amazon Inspector run
Ensure that Amazon Inspector runs occur every n days.
Amazon Inspector 2
Check for Amazon Inspector v2 Findings
Ensure that Amazon Inspector v2 findings are analyzed and resolved.
Enable Amazon Inspector 2
Ensure that Amazon Inspector 2 is enabled for your AWS cloud environment.
AWS Key Management Service
App-Tier KMS Customer Master Key (CMK) In Use
Ensure a customer created Customer Master Key (CMK) is created for the app tier.
Database-Tier KMS Customer Master Key (CMK) In Use
Ensure a customer created Customer Master Key (CMK) is created for the database tier.
Existence of Specific AWS KMS CMKs
Ensure that specific Amazon KMS CMKs are available for use in your AWS account.
KMS Cross Account Access
Ensure Amazon KMS master keys don't allow unknown cross account access.
KMS Customer Master Key (CMK) In Use
Ensure KMS Customer Master Key (CMK) is in use to have full control over encrypting and decrypting data.
KMS Customer Master Key Pending Deletion
Identify and recover any KMS Customer Master Keys (CMK) scheduled for deletion.
Key Exposed
Ensure Amazon KMS master keys aren't exposed to everyone.
Key Rotation Enabled
Ensure that automatic rotation for Customer Managed Keys (CMKs) is enabled.
Monitor AWS KMS Configuration Changes
Key Management Service (KMS) configuration changes have been detected within your AWS account.
Unused Customer Master Key
Identify unused customer master keys, and delete them to help lower the cost of your monthly AWS bill.
Web-Tier KMS Customer Master Key (CMK) In Use
Ensure a customer created Customer Master Key (CMK) is created for the web tier.
Amazon Kinesis
Kinesis Server Side Encryption
Ensure Amazon Kinesis streams enforce Server-Side Encryption (SSE).
Kinesis Stream Encrypted With CMK
Ensure AWS Kinesis streams are encrypted with KMS Customer Master Keys for complete control over data encryption and decryption.
Kinesis Stream Shard Level Metrics
Ensure enhanced monitoring is enabled for your AWS Kinesis streams using shard-level metrics.
AWS Lambda
Check Lambda Function URL Not in Use
Check your Amazon Lambda functions are not using function URLs.
Check for Missing Execution Role
Ensure that Amazon Lambda functions are referencing active execution roles.
Enable Code Signing
Ensure that Code Signing is enabled for Amazon Lambda functions.
Enable Dead Letter Queue for Lambda Functions
Ensure there is a Dead Letter Queue configured for each Lambda function available in your AWS account.
Enable Encryption at Rest for Environment Variables using Customer Master Keys
Ensure that Lambda environment variables are encrypted at rest with Customer Master Keys (CMKs) to gain full control over data encryption/decryption
Enable Encryption in Transit for Environment Variables
Ensure that encryption in transit is enabled for the Lambda environment variables that store sensitive information.
Enable Encryption in Transit for Environment Variables
Ensure that encryption in transit is enabled for the Lambda environment variables that store sensitive information.
Enable Enhanced Monitoring for Lambda Functions
Ensure that your Amazon Lambda functions are configured to use enhanced monitoring.
Enable IAM Authentication for Lambda Function URLs
Ensure that IAM authorization is enabled for your Lambda function URLs.
Enable and Configure Provisioned Concurrency
Ensure that your Amazon Lambda functions are configured to use provisioned concurrency.
Enable and Configure Reserved Concurrency
Ensure that your Amazon Lambda functions are configured to use reserved concurrency.
Function Exposed
Ensure that your Amazon Lambda functions aren't exposed to everyone.
Function in Private Subnet
Ensure that your Amazon Lambda functions are configured to use private subnets.
Lambda Cross Account Access
Ensure AWS Lambda functions don't allow unknown cross account access via permission policies.
Lambda Function Execution Roles with Inline Policies
Ensure that IAM execution roles configured for Lambda functions are not using inline policies.
Lambda Function With Admin Privileges
Ensure no Lambda function available in your AWS account has admin privileges.
Lambda Functions Should not Share Roles that Contain Admin Privileges
Ensure that Amazon Lambda functions don't share roles that have admin privileges.
Lambda Using Latest Runtime Environment
Ensure that the latest version of the runtime environment is used for your AWS Lambda functions.
Lambda Using Supported Runtime Environment
Ensure the AWS Lambda function runtime version is currently supported.
Tracing Enabled
Ensure that tracing (Lambda support for Amazon X-Ray service) is enabled for your AWS Lambda functions.
Use AWS-Managed Policies for Lambda Function Execution Roles
Ensure that IAM execution roles configured for Lambda functions are using AWS-managed policies.
Use Customer-Managed Policies for Lambda Function Execution Roles
Ensure that IAM execution roles configured for Lambda functions are using customer-managed policies.
Using An IAM Role For More Than One Lambda Function
Ensure that Lambda functions don't share the same IAM execution role.
VPC Access for AWS Lambda Functions
Ensure that your Amazon Lambda functions have access to VPC-only resources.
Amazon MQ
MQ Auto Minor Version Upgrade
Ensure Auto Minor Version Upgrade is enabled for MQ to automatically receive minor engine upgrades during the maintenance window.
MQ Deployment Mode
Ensure MQ brokers are using the active/standby deployment mode for high availability.
MQ Desired Broker Instance Type
Ensure that all your Amazon MQ broker instances are of a given type.
MQ Engine Version
Ensure that the latest version of Apache ActiveMQ engine is used for your AWS MQ brokers.
MQ Log Exports
Ensure that your Amazon MQ brokers have Log Exports feature enabled.
MQ Network of Brokers
Ensure that Amazon MQ brokers are using the network of brokers configuration.
Publicly Accessible MQ Brokers
Ensure AWS MQ brokers aren't publicly accessible in order to avoid exposing sensitive data and minimize security risks.
Amazon Managed Streaming for Apache Kafka
Enable Apache Kafka Latest Security Features
Ensure access to the latest security features in Amazon MSK clusters.
Enable Enhanced Monitoring for Apache Kafka Brokers
Ensure that enhanced monitoring of Apache Kafka brokers using Amazon CloudWatch is enabled.
Enable In-Transit Encryption
Ensure that in-transit encryption is enabled for Amazon MSK clusters to protect against eavesdropping.
Enable MSK Cluster Encryption at Rest using CMK
Ensure that your Amazon MSK clusters are encrypted using KMS Customer Master Keys.
Enable Mutual TLS Authentication for Kafka Clients
Ensure that only trusted clients can connect to your Amazon MSK clusters using TLS certificates.
Publicly Accessible Clusters
Ensure that Amazon MSK clusters are not publicly accessible and prone to security risks.
Unrestricted Access to Apache Kafka Brokers
Ensure that unrestricted access to the Apache Kafka brokers is disabled.
Amazon Macie
Amazon Macie In Use
Ensure AWS Macie is in use to protect your sensitive and business-critical data.
AWS Macie v2
Amazon Macie Discovery Jobs
Ensure that Amazon Macie data discovery jobs are created and configured within each AWS region.
Amazon Macie Findings
Ensure that Amazon Macie security findings are highlighted, analyzed, and resolved.
Amazon Macie Sensitive Data Repository
Ensure that a data repository bucket is defined for Amazon Macie within each AWS region.
Compliance and Certifications
Amazon Neptune
IAM Database Authentication for Neptune
Ensure IAM Database Authentication feature is enabled for Amazon Neptune clusters.
Neptune Auto Minor Version Upgrade
Ensure Amazon Neptune instances have Auto Minor Version Upgrade feature enabled.
Neptune Database Backup Retention Period
Ensure AWS Neptune clusters have a sufficient backup retention period set for compliance purposes.
Neptune Database Encrypted With KMS Customer Master Keys
Ensure that AWS Neptune instances enforce data-at-rest encryption using KMS CMKs.
Neptune Database Encryption Enabled
Ensure that Amazon Neptune graph database instances are encrypted.
Neptune Desired Instance Type
Ensure that all your Amazon Neptune database instances are of a given type.
Neptune Multi-AZ
Ensure that Amazon Neptune database clusters have the Multi-AZ feature enabled.
AWS Network Firewall
AWS Network Firewall in Use
Ensure that your Amazon VPCs are using AWS Network Firewall.
Enable Deletion Protection for Network Firewalls
Ensure that Deletion Protection feature is enabled for your VPC network firewalls.
AWS Organizations
AWS Organizations Configuration Changes
AWS Organizations configuration changes have been detected within your Amazon Web Services account(s).
AWS Organizations In Use
Ensure Amazon Organizations is in use to consolidate all your AWS accounts into an organization.
Enable All Features
Ensure AWS Organizations All Features is enabled for fine-grained control over which services and actions the member accounts of an organization can access.
Enable Resource Control Policies (RCPs) for AWS Organizations
Ensure that Resource Control Policies (RCPs) are enabled for AWS Organizations.
Amazon Relational Database Service
Amazon RDS Configuration Changes
Amazon Relational Database Service (RDS) configuration changes have been detected in your AWS account.
Amazon RDS Public Snapshots
Ensure that your Amazon RDS database snapshots are not accessible to all AWS accounts.
Aurora Database Cluster Activity Streams
Ensure that Amazon Aurora clusters are configured to use database activity streams.
Aurora Database Instance Accessibility
Ensure that all database instances within an Amazon Aurora cluster have the same accessibility.
Backtrack
Enable Amazon Aurora Backtrack.
Cluster Deletion Protection
Enable AWS RDS Cluster Deletion Protection.
DB Instance Generation
Ensure you always use the latest generation of DB instances to get better performance with lower cost.
Enable AWS RDS Transport Encryption
Ensure AWS RDS SQL Server and Postgre instances have Transport Encryption feature enabled.
Enable Aurora Cluster Copy Tags to Snapshots
Ensure that Amazon Aurora clusters have Copy Tags to Snapshots feature enabled.
Enable Deletion Protection for Aurora Serverless Clusters
Ensure that the Deletion Protection feature is enabled for your Aurora Serverless clusters.
Enable Instance Storage AutoScaling
Ensure that the Storage AutoScaling feature is enabled to support unpredictable database workload.
Enable RDS Snapshot Encryption
Ensure that AWS RDS snapshots are encrypted to meet security and compliance requirements.
Enable Serverless Log Exports
Ensure Log Exports feature is enabled for your Amazon Aurora Serverless databases.
IAM Database Authentication
Enable IAM Database Authentication.
Idle RDS Instance
Identify idle AWS RDS database instances and terminate them to optimize AWS costs.
Instance Deletion Protection
Enable AWS RDS Instance Deletion Protection.
Instance Level Events Subscriptions
Enable Event Subscriptions for Instance Level Events.
Log Exports
Enable AWS RDS Log Exports.
Overutilized AWS RDS Instances
Identify overutilized RDS instances and upgrade them in order to optimize database workload and response time.
Performance Insights
Enable AWS RDS Performance Insights.
RDS Auto Minor Version Upgrade
Ensure Auto Minor Version Upgrade is enabled for RDS to automatically receive minor engine upgrades during the maintenance window.
RDS Automated Backups Enabled
Ensure automated backups are enabled for RDS instances. This feature of Amazon RDS enables point-in-time recovery of your database instance.
RDS Copy Tags to Snapshots
Enable RDS Copy Tags to Snapshots.
RDS Default Port
Ensure Amazon RDS database instances aren't using the default ports.
RDS Desired Instance Type
Ensure fewer Amazon RDS instances than the established limit in your AWS account.
RDS Encrypted With KMS Customer Master Keys
Ensure RDS instances are encrypted with CMKs to have full control over encrypting and decrypting data.
RDS Encryption Enabled
Ensure encryption is setup for RDS instances to fulfill compliance requirements for data-at-rest encryption.
RDS Event Notifications
Enable event notifications for RDS.
RDS Free Storage Space
Identify RDS instances with low free storage space and scale them in order to optimize their performance.
RDS General Purpose SSD
Ensure RDS instances are using General Purpose SSD storage instead of Provisioned IOPS SSD storage to optimize the RDS service costs.
RDS Instance Counts
Ensure fewer Amazon RDS instances than the established limit in your AWS account.
RDS Instance Not In Public Subnet
Ensure that no AWS RDS database instances are provisioned inside VPC public subnets.
RDS Master Username
Ensure AWS RDS instances are using secure and unique master usernames for their databases.
RDS Multi-AZ
Ensure RDS instances are launched into Multi-AZ.
RDS Publicly Accessible
Ensure RDS instances aren't public facing to minimise security risks.
RDS Reserved DB Instance Lease Expiration In The Next 30 Days
Ensure Amazon RDS Reserved Instances (RI) are renewed before expiration.
RDS Reserved DB Instance Lease Expiration In The Next 7 Days
Ensure Amazon RDS Reserved Instances (RI) are renewed before expiration.
RDS Reserved DB Instance Payment Failed
Ensure AWS RDS Reserved Instance purchases have not failed.
RDS Reserved DB Instance Payment Pending
Ensure Amazon RDS Reserved Instance purchases are not pending.
RDS Reserved DB Instance Recent Purchases
Ensure RDS Reserved Instance purchases are regularly reviewed for cost optimization (informational).
RDS Sufficient Backup Retention Period
Ensure RDS instances have sufficient backup retention period for compliance purposes.
Rotate SSL/TLS Certificates for Database Instances
Ensure that SSL/TLS certificates for RDS database instances are rotated according to the AWS schedule.
Security Groups Events Subscriptions
Enable Event Subscriptions for DB Security Groups Events.
Underutilized RDS Instance
Identify underutilized RDS instances and downsize them in order to optimize your AWS costs.
Unrestricted DB Security Group
Ensure there aren’t any unrestricted DB security groups assigned to your RDS instances.
Unused RDS Reserved Instances
Ensure that your Amazon RDS Reserved Instances are being fully utilized.
Use AWS Backup Service in Use for Amazon RDS
Ensure that Amazon Backup service is used to manage AWS RDS database snapshots.
Conformity Real-Time Threat monitoring
AWS IAM User Created
An AWS Identity and Access Management (IAM) user creation event has been detected.
AWS IAM user has signed in without MFA
Amazon Web Services IAM user authentication without MFA has been detected.
AWS Root user has signed in without MFA
Conformity user authentication without MFA has been detected.
Monitor Unintended AWS API Calls
Unintended AWS API calls have been detected within your Amazon Web Services account.
Root has signed in
Amazon Web Services account authentication using root credentials has been detected.
User activity in blocklisted regions
AWS User/API activity has been detected within blocklisted Amazon Web Services region(s).
User has failed signing in to AWS
Monitor AWS IAM user's failed signing attempts.
Users signed in to AWS from a safelisted IP Address
Amazon Web Services root/IAM user authentication from a blocklisted IP address has been detected.
Users signed in to AWS from an approved country
Amazon Web Services root/IAM user authentication from a non-approved country has been detected.
VPC Network Configuration Changes
Networking configuration changes have been detected within your Amazon Web Services account.
Amazon Redshift
Configure Preferred Maintenance Window
Ensure there is a preferred maintenance window configured for your Amazon Redshift clusters.
Deferred Maintenance
Enable Deferred Maintenance for Redshift Clusters.
Enable Cluster Relocation
Ensure that relocation is enabled and configured for your Amazon Redshift clusters.
Enable Cross-Region Snapshots
Ensure that cross-region snapshots are enabled for your Amazon Redshift clusters.
Enable Enhanced VPC Routing
Ensure that Enhanced VPC Routing is enabled for your Amazon Redshift clusters.
Enable Redshift User Activity Logging
Ensure that user activity logging is enabled for your Amazon Redshift clusters.
Idle Redshift Cluster
Identify idle AWS Redshift clusters and terminate them in order to optimize AWS costs.
Redshift Automated Snapshot Retention Period
Ensure that retention period is enabled for Amazon Redshift automated snapshots.
Redshift Cluster Allow Version Upgrade
Ensure Version Upgrade is enabled for Redshift clusters to automatically receive upgrades during the maintenance window.
Redshift Cluster Audit Logging Enabled
Ensure audit logging is enabled for Redshift clusters for security and troubleshooting purposes.
Redshift Cluster Default Master Username
Ensure AWS Redshift database clusters are not using "awsuser" (default master user name) for database access.
Redshift Cluster Default Port
Ensure Amazon Redshift clusters are not using port 5439 (default port) for database access.
Redshift Cluster Encrypted
Ensure database encryption is enabled for AWS Redshift clusters to protect your data at rest.
Redshift Cluster Encrypted With KMS Customer Master Keys
Ensure Redshift clusters are encrypted with KMS customer master keys (CMKs) in order to have full control over data encryption and decryption.
Redshift Cluster In VPC
Ensure Redshift clusters are launched in VPC.
Redshift Cluster Publicly Accessible
Ensure Redshift clusters are not publicly accessible to minimise security risks.
Redshift Desired Node Type
Ensure that your AWS Redshift cluster nodes are of given types.
Redshift Disk Space Usage
Identify AWS Redshift clusters with high disk usage and scale them to increase their storage capacity.
Redshift Instance Generation
Ensure Redshift clusters are using the latest generation of nodes for performance improvements.
Redshift Nodes Counts
Ensure that your AWS account has not reached the limit set for the number of Redshift cluster nodes.
Redshift Parameter Group Require SSL
Ensure AWS Redshift non-default parameter groups require SSL to secure data in transit.
Redshift Reserved Node Coverage
Ensure that your Amazon Redshift usage is covered by RI reservations in order to optimize costs.
Redshift Reserved Node Lease Expiration In The Next 30 Days
Ensure Amazon Redshift Reserved Nodes (RN) are renewed before expiration.
Redshift Reserved Node Lease Expiration In The Next 7 Days
Ensure Amazon Redshift Reserved Nodes (RN) are renewed before expiration.
Redshift Reserved Node Payment Failed
Ensure that none of your AWS Redshift Reserved Node purchases have been failed.
Redshift Reserved Node Payment Pending
Ensure that none of your AWS Redshift Reserved Node (RN) purchases are pending.
Redshift Reserved Node Recent Purchases
Ensure Redshift Reserved Node purchases are regularly reviewed for cost optimization (informational).
Sufficient Cross-Region Snapshot Retention Period
Ensure that Redshift clusters have a sufficient retention period configured for cross-region snapshots.
Underutilized Redshift Cluster
Identify underutilized Redshift clusters and downsize them in order to optimize AWS costs.
Unused Redshift Reserved Nodes
Ensure that your Amazon Redshift Reserved Nodes are being utilized.
AWS Resource Groups
Tags
Use tags metadata for identifying and organizing your AWS resources by purpose, owner, environment, or other criteria
Amazon Route 53
Amazon Route 53 Configuration Changes
Route 53 configuration changes have been detected within your Amazon Web Services account.
Enable DNSSEC Signing for Route 53 Hosted Zones
Ensure that DNSSEC signing is enabled for your Amazon Route 53 Hosted Zones.
Enable Query Logging for Route 53 Hosted Zones
Ensure that DNS query logging is enabled for your Amazon Route 53 hosted zones.
Privacy Protection
Ensure that Route 53 domains have Privacy Protection enabled.
Remove AWS Route 53 Dangling DNS Records
Ensure dangling DNS records are removed from your AWS Route 53 hosted zones to avoid domain/subdomain takeover.
Route 53 Domain Auto Renew
Ensure Route 53 domains are set to auto renew.
Route 53 Domain Expired
Ensure expired AWS Route 53 domains names are restored.
Route 53 Domain Expiry 30 Days
Ensure AWS Route 53 domain names are renewed before their expiration.
Route 53 Domain Expiry 45 Days
Ensure AWS Route 53 domain names are renewed before their expiration (45 days before expiration).
Route 53 Domain Expiry 7 Days
Ensure AWS Route 53 domain names are renewed before their expiration.
Route 53 Domain Transfer Lock
Ensure Route 53 domains have the transfer lock set to prevent an unauthorized transfer to another registrar.
Route 53 In Use
Ensure AWS Route 53 DNS service is in use for highly efficient DNS management.
Sender Policy Framework In Use
Ensure that Sender Policy Framework (SPF) is used to stop spammers from spoofing your AWS Route 53 domain.
Amazon Route 53 Domains
Amazon Route 53 Domains Configuration Changes
Route 53 Domains configuration changes have been detected within your Amazon Web Services account.
Amazon S3
Amazon Macie Finding Statistics for S3
Capture summary statistics about Amazon Macie security findings on a per-S3 bucket basis.
Configure Different S3 Bucket for Server Access Logging Storage
Ensure that Amazon S3 Server Access Logging uses a different bucket for storing access logs.
Configure S3 Object Ownership
Ensure that S3 Object Ownership is configured to allow you to take ownership of S3 objects.
DNS Compliant S3 Bucket Names
Ensure that Amazon S3 buckets always use DNS-compliant bucket names.
Deny S3 Log Delivery Group Write Permission on the Source Bucket
Ensure that the S3 Log Delivery Group write permissions are denied for the S3 source bucket.
Enable S3 Block Public Access for AWS Accounts
Ensure that Amazon S3 public access is blocked at the AWS account level for data protection.
Enable S3 Block Public Access for S3 Buckets
Ensure that Amazon S3 public access is blocked at the S3 bucket level for data protection.
Enable S3 Bucket Keys
Ensure that Amazon S3 buckets are using S3 bucket keys to optimize service costs.
S3 Bucket Authenticated Users 'FULL_CONTROL' Access
Ensure that S3 buckets do not allow FULL_CONTROL access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'READ' Access
Ensure that S3 buckets do not allow READ access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'READ_ACP' Access
Ensure that S3 buckets do not allow READ_ACP access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'WRITE' Access
Ensure that S3 buckets do not allow WRITE access to AWS authenticated users via ACLs.
S3 Bucket Authenticated Users 'WRITE_ACP' Access
Ensure that S3 buckets do not allow WRITE_ACP access to AWS authenticated users via ACLs.
S3 Bucket Default Encryption (Deprecated)
Ensure that encryption at rest is enabled for your Amazon S3 buckets and their data.
S3 Bucket Logging Enabled
Ensure S3 bucket access logging is enabled for security and access audits.
S3 Bucket MFA Delete Enabled
Ensure S3 buckets have an MFA-Delete policy to prevent deletion of files without an MFA token.
S3 Bucket Public 'FULL_CONTROL' Access
Ensure that your Amazon S3 buckets are not publicly exposed to the Internet.
S3 Bucket Public 'READ' Access
Ensure that S3 buckets do not allow public READ access via Access Control Lists (ACLs).
S3 Bucket Public 'READ_ACP' Access
Ensure that S3 buckets do not allow public READ_ACP access via Access Control Lists (ACLs).
S3 Bucket Public 'WRITE' ACL Access
Ensure S3 buckets don’t allow public WRITE ACL access
S3 Bucket Public 'WRITE_ACP' Access
Ensure that S3 buckets do not allow public WRITE_ACP access via Access Control Lists (ACLs).
S3 Bucket Public Access Via Policy
Ensure that Amazon S3 buckets do not allow public access via bucket policies.
S3 Bucket Versioning Enabled
Ensure S3 bucket versioning is enabled for additional level of data protection.
S3 Buckets Encrypted with Customer-Provided CMKs
Ensure that Amazon S3 buckets are encrypted with customer-provided KMS CMKs.
S3 Buckets Lifecycle Configuration
Ensure that AWS S3 buckets utilize lifecycle configurations to manage S3 objects during their lifetime.
S3 Buckets with Website Hosting Configuration Enabled
Ensure that the S3 buckets with website configuration are regularly reviewed (informational).
S3 Configuration Changes
AWS S3 configuration changes have been detected within your Amazon Web Services account.
S3 Cross Account Access
Ensure that S3 buckets do not allow unknown cross-account access via bucket policies.
S3 Object Lock
Ensure that S3 buckets use Object Lock for data protection and/or regulatory compliance.
S3 Transfer Acceleration
Ensure that S3 buckets use the Transfer Acceleration feature for faster data transfers.
Secure Transport
Ensure AWS S3 buckets enforce SSL to secure data in transit.
Server Side Encryption
Ensure AWS S3 buckets enforce Server-Side Encryption (SSE)
Amazon Simple Email Service
DKIM Enabled
Ensure DKIM signing is enabled in AWS SES to protect email senders and receivers against phishing.
Exposed SES Identities
Ensure that your AWS SES identities (domains and/or email addresses) are not exposed to everyone.
Identify Cross-Account Access
Ensure that AWS SES identities (domains and/or email addresses) do not allow unknown cross-account access via authorization policies.
Identity Verification Status
Ensure AWS SES identities (email addresses and/or domains) are verified.
Amazon Simple Notification Service (SNS)
AWS SNS Appropriate Subscribers
Ensure appropriate subscribers to all your AWS Simple Notification Service (SNS) topics.
SNS Cross Account Access
Ensure Amazon SNS topics don't allow unknown cross account access.
SNS Topic Accessible For Publishing
Ensure SNS topics don't allow 'Everyone' to publish.
SNS Topic Accessible For Subscription
Ensure SNS topics don't allow 'Everyone' to subscribe.
SNS Topic Encrypted
Enable Server-Side Encryption for AWS SNS Topics.
SNS Topic Encrypted With KMS Customer Master Keys
Ensure that Amazon SNS topics are encrypted with KMS Customer Master Keys.
SNS Topic Exposed
Ensure SNS topics aren't exposed to everyone.
Amazon Simple Queue Service
Queue Server Side Encryption
Ensure Amazon SQS queues enforce Server-Side Encryption (SSE).
Queue Unprocessed Messages
Ensure SQS queues aren't holding a high number of unprocessed messages due to unresponsive or incapacitated consumers.
SQS Cross Account Access
Ensure SQS queues don't allow unknown cross account access.
SQS Dead Letter Queue
Ensure Dead Letter Queue (DLQ) is configured for SQS queue.
SQS Encrypted With KMS Customer Master Keys
Ensure SQS queues are encrypted with KMS CMKs to gain full control over data encryption and decryption
SQS Queue Exposed
Ensure SQS queues aren't exposed to everyone.
AWS Systems Manager
Check for SSM Managed Instances
Ensure that all EC2 instances are managed by AWS Systems Manager (SSM) service.
SSM Parameter Encryption
Ensure that Amazon SSM parameters that hold sensitive configuration data are encrypted.
SSM Session Length
Ensure that all active sessions in the Session manager do not exceed a set period of time.
Amazon SageMaker
Amazon SageMaker Notebook Instance In VPC
Ensure that Amazon SageMaker notebook instances are deployed into a VPC.
Check for Missing Execution Role
Ensure that SageMaker notebook instances are referencing active execution roles.
Disable Direct Internet Access for Notebook Instances
Ensure that direct internet access is disabled for SageMaker Studio notebook instances.
Disable Root Access for SageMaker Notebook Instances
Ensure that root access is disabled for Amazon SageMaker notebook instances.
Enable Data Capture for SageMaker Endpoints
Ensure that SageMaker endpoints are configured to capture log data useful for training, debugging, and monitoring.
Enable Inter-Container Traffic Encryption
Ensure that inter-container traffic encryption is enabled for your SageMaker training jobs.
Enable Network Isolation for SageMaker Models
Ensure that network isolation is enabled for your SageMaker models to prevent unauthorized access.
Enable Network Isolation for SageMaker Training Jobs
Ensure that network isolation is enabled for your SageMaker training jobs to prevent unauthorized access.
Enable SageMaker Notebook Instance Data Encryption (Deprecated)
Ensure that data available on Amazon SageMaker notebook instances is encrypted.
Enable VPC Only for SageMaker Domains
Enable and configure "VPC Only" mode for added security control of your SageMaker notebooks.
Endpoints Encrypted With KMS Customer Managed Keys
Ensure that SageMaker endpoints are using Amazon KMS Customer Managed Keys (CMKs) for data encryption.
Notebook Data Encrypted With KMS Customer Managed Keys
Ensure SageMaker notebook instance storage volumes are encrypted with Amazon KMS Customer Managed Keys (CMKs).
Notebook in VPC Only Mode Can Access Required Resources
Ensure that SageMaker notebook instances deployed into a VPC can access required resources.
Output and Storage Volume Data Encrypted With KMS Customer Managed Keys
Ensure that training job volume and output data is encrypted with Amazon KMS Customer Managed Keys (CMKs).
SageMaker HyperPod Clusters Encrypted with KMS Customer Managed Keys
Ensure that SageMaker HyperPod cluster storage volumes are encrypted with Amazon KMS Customer Managed Keys (CMKs).
AWS Secrets Manager
Secret Encrypted With KMS Customer Master Keys
Ensure that AWS Secrets Manager service enforces data-at-rest encryption using KMS CMKs.
Secret Rotation Enabled
Ensure that automatic rotation is enabled for your Amazon Secrets Manager secrets.
Secret Rotation Interval
Ensure that Amazon Secrets Manager automatic rotation interval is properly configured.
Secrets Manager In Use
Ensure that AWS Secrets Manager is in use for secure and efficient credentials management.
AWS Security Hub
AWS Security Hub Findings
Ensure that Amazon Security Hub findings are analyzed and resolved.
AWS Security Hub Insights
Ensure that Amazon Security Hub insights are regularly reviewed (informational).
Detect AWS Security Hub Configuration Changes
Security Hub service configuration changes have been detected within your Amazon Web Services account.
Review Enabled Security Hub Standards
Ensure that enabled Amazon Security Hub standards are reviewed (informational).
Security Hub Enabled
Ensure that Amazon Security Hub service is enabled for your AWS accounts.
Service Quotas
Enable Alerts for Supported Service Quotas
Ensure that Amazon CloudWatch alarms are configured for supported AWS service quotas
AWS Shield
Shield Advanced In Use
Use AWS Shield Advanced to protect your web applications against DDoS attacks.
AWS Storage Gateway
Use KMS Customer Master Keys for AWS Storage Gateway File Shares
Ensure that your Amazon Storage Gateway file share data is encrypted using KMS Customer Master Keys (CMKs).
Use KMS Customer Master Keys for AWS Storage Gateway Tapes
Ensure that your Amazon Storage Gateway virtual tapes are encrypted using KMS Customer Master Keys.
Use KMS Customer Master Keys for AWS Storage Gateway Volumes
Ensure that your Amazon Storage Gateway volumes data is encrypted using KMS Customer Master Keys (CMKs).
AWS Support
Support Plan
Ensure appropriate support level is enabled for necessary AWS accounts (e.g. production accounts).
AWS Transfer
Enable AWS Transfer for SFTP Logging Activity
Ensure that AWS CloudWatch logging is enabled for Amazon Transfer for SFTP user activity.
Use AWS PrivateLink for Transfer for SFTP Server Endpoints
Ensure that Amazon Transfer for SFTP servers are using AWS PrivateLink for their endpoints.
AWS Trusted Advisor
Exposed IAM Access Keys
Ensure exposed IAM access keys are invalidated to protect your AWS resources from unauthorized access.
Trusted Advisor Checks
Ensure that Amazon Trusted Advisor checks are examined and resolved..
Trusted Advisor Service Limits
Monitor AWS Service Limits to ensure that the allocation of resources is not reaching the limit.
Amazon Virtual Private Cloud (VPC)
AWS VPC Peering Connections Route Tables Access
Ensure that the Amazon VPC peering connection configuration is compliant with the desired routing policy.
AWS VPN Tunnel State
Ensure the state of your AWS Virtual Private Network (VPN) tunnels is UP
Ineffective Network ACL DENY Rules
Ensure that Amazon Network ACL DENY rules are effective within the VPC configuration.
Managed NAT Gateway in Use
Ensure that the Managed NAT Gateway service is enabled for high availability (HA).
Specific Gateway Attached To Specific VPC
Ensure that a specific Internet/NAT gateway is attached to a specific VPC.
Unrestricted Inbound Traffic on Remote Server Administration Ports
Ensure that no Network ACL (NACL) allows unrestricted inbound traffic on TCP ports 22 and 3389.
Unrestricted Network ACL Inbound Traffic
Ensure that no Network ACL (NACL) allows inbound/ingress traffic from all ports.
Unrestricted Network ACL Outbound Traffic
Ensure that no Network ACL (NACL) allows outbound/egress traffic to all ports.
Unused VPC Internet Gateways
Ensure unused VPC Internet Gateways and Egress-Only Internet Gateways are removed to follow best practices.
Unused Virtual Private Gateways
Ensure unused Virtual Private Gateways (VGWs) are removed to follow best practices.
VPC Endpoint Cross Account Access
Ensure Amazon VPC endpoints don't allow unknown cross account access.
VPC Endpoint Exposed
Ensure Amazon VPC endpoints aren't exposed to everyone.
VPC Endpoints In Use
Ensure that VPC endpoints are being used to connect your VPC to another AWS cloud service.
VPC Flow Logs Enabled
Ensure VPC flow logging is enabled in all VPCs.
VPC Naming Conventions
Follow proper naming conventions for Virtual Private Clouds.
VPC Peering Connections To Accounts Outside AWS Organization
Ensure VPC peering communication is only between AWS accounts, members of the same AWS Organization.
VPN Tunnel Redundancy
Ensure AWS VPNs have always two tunnels active in order to enable redundancy.
AWS WAF - Web Application Firewall
AWS WAFv2 In Use
Ensure that AWS WAFv2 is in use to protect your web applications from common web exploits.
AWS Web Application Firewall In Use
Ensure AWS WAF is in use to protect your web applications from common web exploits.
Enable Logging for Web Access Control Lists
Ensure that logging is enabled for Amazon WAF Web Access Control Lists.
AWS Well-Architected
AWS Well-Architected Tool Findings
Ensure that the high and medium risk issues identified in a workload by the AWS Well-Architected Tool are highlighted, audited, and resolved.
AWS Well-Architected Tool in Use
Ensure AWS Well-Architected Tool is in use to help you build and maintain secure, efficient, high-performing and resilient cloud application architectures.
AWS WorkDocs
Enable MFA for Microsoft Entra Connector Directories
Ensure that Multi-Factor Authentication (MFA) is enabled for Microsoft Entra Connector directories in Amazon WorkDocs.
Amazon WorkSpaces
Unused WorkSpaces
Ensure that your Amazon WorkSpaces service instances are being utilized.
WorkSpaces Desired Bundle Type
Ensure your AWS account has not reached the limit set for the number of WorkSpaces instances.
WorkSpaces Instances Counts
Ensure your AWS account has not reached the limit set for the number of WorkSpaces instances.
WorkSpaces Operational State
Ensure that your Amazon WorkSpaces instances are healthy.
WorkSpaces Storage Encryption
Ensure that your Amazon WorkSpaces storage volumes are encrypted in order to meet security and compliance requirement.
AWS X-Ray
X-Ray Data Encrypted With KMS Customer Master Keys
Ensure Amazon X-Ray encrypts traces and related data at rest using KMS CMKs.
