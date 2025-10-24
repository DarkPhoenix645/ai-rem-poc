# GCP

## Overview
Knowledge Base
Google Cloud Platform
Get Started
Get Pricing
Contact Us
Google Cloud Platform best practice rules
Trend Vision One™ has over 1100+ cloud infrastructure configuration best practices for your
Alibaba Cloud
,
Amazon Web Services
,
Microsoft® Azure
, and Google Cloud™ environments. Here is our growing list of GCP best practice rules with clear instructions on how to perform the updates – made either through the GCP console or via the Command Line Interface (CLI).
Trend Vision One™ provides real-time monitoring and auto-remediation for the security, compliance and governance of your cloud infrastructure. Leaving you to grow and scale your business with confidence.
GCP ApiGateway
Check for API Gateway Authentication Method
Ensure that API Gateway uses an authentication method to secure access to your API backend.
Enable Data Access Audit Logs
Ensure that Data Access audit logs are enabled for Google Cloud API Gateway APIs.
Enable Data Encryption for API Gateway Backend Integrations
Ensure that associated backend services are configured to communicate with API Gateway using HTTPS.
Implement Least Privilege Access using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for API access control.
Protect API Gateway with Cloud Armor
Ensure that API Gateway leverages Cloud Armor as a network security service.
Rate Limit API Usage with Quotas
Ensure that API Gateway is configured to use rate limiting with quotas for your APIs.
Use Labels for Resource Management
Ensure that all Google Cloud API Gateway APIs are labeled for better resource management.
GCP ArtifactRegistry
Check for Publicly Accessible Artifact Registry Repositories
Ensure there are no publicly accessible Artifact Registry repositories available in your GCP account.
Enable Artifact Registry Vulnerability Scanning
Ensure that vulnerability scanning for Artifact Registry repositories is enabled to enhance security and mitigate potential risks.
Use Customer-Managed Encryption Keys for Repositories Encryption
Use Customer-Managed Encryption Keys (CMEKs) to protect Artifact Registry repositories and related data at rest.
GCP BigQuery
Check for Publicly Accessible BigQuery Datasets
Ensure that Google Cloud BigQuery datasets are not publicly accessible.
Enable BigQuery Dataset Encryption with Customer-Managed Encryption Keys
Ensure that BigQuery datasets are encrypted using Customer-Managed Encryption Keys (CMEKs).
Enable BigQuery Encryption with Customer-Managed Keys
Ensure that BigQuery dataset tables are encrypted using Customer-Managed Keys (CMKs).
GCP CertificateManager
Check for Compliant Trust Configuration
To prevent certificate validation from being bypassed, ensure your Certificate Manager Trust Configs are compliant.
Enable Data Access Audit Logs for Certificate Manager
Ensure that Data Access audit logs are enabled for Certificate Manager resources.
Enable Monitoring for Certificate Expiration
Ensure that Certificate Manager certificate expiration is being monitored using alerting policies.
Implement Least Privilege Access for Certificate Manager using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for Certificate Manager access control.
SSL certificates validity period
Ensure that SSL certificates are renewed within the appropriate validity period.
Use VPC Service Controls for Certificate Manager
Ensure that VPC Service Controls perimeters are used to protect your Certificate Manager resources from data exfiltration.
GCP API
API Keys Should Only Exist for Active Services
Ensure there are no API keys in use within your Google Cloud projects.
Check for API Key API Restrictions
Ensure that API keys are restricted to only those APIs that your application needs access to.
Check for API Key Application Restrictions
Ensure there are no unrestricted API keys available within your Google Cloud Platform (GCP) project.
Enable Cloud Asset Inventory
Ensure that Google Cloud Asset Inventory is enabled for your GCP projects.
Enable Security Command Center API
Ensure that Google Cloud Security Command Center API is enabled.
Enable critical service APIs
Ensure that critical service APIs are enabled for your GCP projects.
Latest Operating System Updates
Ensure that your Google Cloud virtual machine (VM) instances are using the latest operating system updates.
Rotate Google Cloud API Keys
Ensure that all the API keys created for your Google Cloud Platform (GCP) projects are regularly rotated.
GCP CloudCDN
Backend Buckets Referencing Missing Storage Buckets
Ensure that your backend buckets are using active storage buckets to store content.
Configure Cloud CDN origin authentication
Ensure that Cloud CDN origins are authenticating access to the cached content.
Configure SSL/TLS certificates for Cloud CDN backend bucket origins
Ensure that Cloud CDN backend bucket origins are using SSL/TLS certificates.
Configure SSL/TLS certificates for Cloud CDN backend service origins
Ensure that Cloud CDN backend service origins are using SSL/TLS certificates.
GCP Domain Name System (DNS)
Check for DNSSEC Key-Signing Algorithm in Use
Ensure that RSASHA1 signature algorithm is not used for DNSSEC key signing.
Check for DNSSEC Zone-Signing Algorithm in Use
Ensure that DNSSEC key signing is not using RSASHA1 as a signature algorithm.
Detect GCP Cloud DNS Configuration Changes
Cloud DNS configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable DNSSEC for Google Cloud DNS Zones
Ensure that DNSSEC is enabled for your Domain Name System (DNS) managed zones.
Remove Dangling DNS Records
Ensure that dangling DNS records are removed from your Cloud DNS zones to avoid domain/subdomain takeover.
GCP Cloud Function
Check for Unrestricted Outbound Network Access
Ensure no Google Cloud functions allow unrestricted outbound network access.
Cloud Logging Permissions for Google Cloud Functions
Ensure that Cloud Logging API has appropriate permissions to write function logs.
Configure Dead Lettering for Pub/Sub-Triggered Functions
Ensure that Dead-Letter Topics (DLTs) are configured for Pub/Sub-triggered functions.
Configure Maximum Instances for Cloud Functions
Configuring a maximum number of instances for your Google Cloud functions helps control costs by preventing uncontrolled scaling.
Configure Minimum Instances for Cloud Functions
To improve performance, ensure that the minimum number of function instances is greater than 0 (zero).
Enable Automatic Runtime Security Updates
Ensure that automatic runtime security updates are enabled for your Google Cloud functions.
Enable Serverless VPC Access for Google Cloud Functions
Ensure that Serverless VPC Access is enabled for your Google Cloud functions.
Functions with Inactive Service Accounts
Ensure that your Google Cloud functions are using active service accounts.
GCP Execution Runtime Environment Version
Ensure that your Google Cloud functions are using the latest execution runtime environment.
GCP Function Runtime Version
Ensure that your GCP functions are using the latest language runtime version available.
GCP Function using Default Service Account
Ensure that your Google Cloud functions are not using the default service account.
GCP Function using Service Account with Basic Roles
Ensure that your Google Cloud functions are not using basic roles for permissions.
GCP Functions with Admin Privileges
Ensure that your Google Cloud functions are not configured with admin privileges.
Publicly Accessible Functions
Ensure there are no publicly accessible Google Cloud functions available within your GCP account.
Use Customer-Managed Encryption Keys for Functions Encryption
Use Customer-Managed Encryption Keys (CMEKs) to protect Google Cloud functions and related data at rest.
Use Labels for Resource Management
Ensure that all Google Cloud functions are labeled for better resource management.
Use Secrets Manager for Managing Secrets in Google Cloud Functions
Manage secrets using Secrets Manager service instead of Cloud Functions environment variables.
GCP Identity and Access Management (IAM)
Check for IAM Members with Service Roles at the Project Level
Ensure there are no IAM members with Service Account User and Service Account Token Creator roles at the project level.
Configure Essential Contacts for Organizations
Ensure that Essential Contacts are defined for your Google Cloud organization.
Configure Google Cloud Audit Logs to Track All Activities
Ensure that the Audit Logs feature is configured to record all service and user activities.
Corporate Login Credentials In Use
Use corporate login credentials instead of personal accounts such as Gmail accounts.
Delete Google Cloud API Keys
Ensure there are no API keys associated with your Google Cloud Platform (GCP) projects.
Delete User-Managed Service Account Keys
Ensure there are no user-managed keys associated with your GCP service accounts.
Detect GCP IAM Configuration Changes
IAM configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable Access Approval
Ensure that Access Approval is enabled for your Google Cloud projects.
Enable Access Transparency
Ensure that Access Transparency is enabled within your Google Cloud organization.
Enable Multi-Factor Authentication for User Accounts
Ensure that Multi-Factor Authentication (MFA) feature is enabled for all GCP user accounts.
Enable Security Key Enforcement for Admin Accounts
Enforce the use of security keys to help prevent Google Cloud account hijacking.
Enforce Separation of Duties for KMS-Related Roles
Ensure that separation of duties is implemented for all Google Cloud KMS-related roles.
Enforce Separation of Duties for Service-Account Related Roles
Ensure that separation of duties is implemented for all Google Cloud service account roles.
Minimize the Use of Primitive Roles
Ensure that the use of Cloud Identity and Access Management (IAM) primitive roles is limited within your Google Cloud projects.
Restrict Administrator Access for Service Accounts
Ensure that user-managed service accounts are not using administrator-based roles.
Rotate User-Managed Service Account Keys
Ensure that your user-managed service account keys are rotated periodically.
GCP Cloud Key Management Service (KMS)
Check for Publicly Accessible Cloud KMS Keys
Ensure there are no publicly accessible KMS cryptographic keys available within your Google Cloud account.
Detect Google Cloud KMS Configuration Changes
Cloud KMS configuration changes have been detected within your Google Cloud Platform (GCP) account.
Rotate Google Cloud KMS Keys
Ensure that all KMS cryptographic keys available within your Google Cloud account are regularly rotated.
GCP Cloud Load Balancing
Approved External Load Balancers
Ensure that only approved external load balancers are used for load-balanced websites and applications.
Check for Insecure SSL Cipher Suites
Ensure there are no HTTPS/SSL Proxy load balancers configured with insecure SSL policies.
Configure Cloud CDN origin backend bucket
Ensure that your Cloud CDN origin points to a backend bucket.
Configure edge security policies for load balancer backend services
Ensure that load balancer backend services are protected with edge security policies.
Detect GCP Load Balancer Configuration Changes
Load Balancing configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable HTTPS for Google Cloud Load Balancers
Ensure that Google Cloud load balancers enforce HTTPS to handle encrypted web traffic.
Enable Logging for HTTP(S) Load Balancers
Ensure that logging is enabled for your Google Cloud HTTP(S) load balancers.
Use Google-Managed SSL Certificates for Application Load Balancers
Ensure that external Application Load Balancers are using Google-managed SSL certificates.
GCP Cloud Logging
Check for Sufficient Log Data Retention Period
Ensure that the retention period configured for your logging buckets is 365 days or greater.
Configure Retention Policies with Bucket Lock
Ensure that the log bucket retention policies are using the Bucket Lock feature.
Enable Global Logging
Ensure that the location of your Cloud Logging buckets is global.
Enable Logs Router Encryption with Customer-Managed Keys
Ensure that Google Cloud Logs Router data is encrypted using Customer-Managed Keys (CMKs).
Enable Monitoring for Audit Configuration Changes
Ensure that GCP project audit configuration changes are being monitored using alerting policies.
Enable Monitoring for Bucket Permission Changes
Ensure that Cloud Storage bucket permission changes are being monitored using alerting policies.
Enable Monitoring for Custom Role Changes
Ensure that custom IAM role changes are being monitored using alerting policies.
Enable Monitoring for Firewall Rule Changes
Ensure that VPC network firewall rule changes are being monitored using alerting policies.
Enable Monitoring for SQL Instance Configuration Changes
Ensure that SQL instance configuration changes are being monitored using alerting policies.
Enable Project Ownership Assignments Monitoring
Ensure that GCP project ownership changes are being monitored using alerting policies.
Enable VPC Network Changes Monitoring
Ensure that Google Cloud VPC network changes are being monitored using log metrics and alerting policies.
Enable VPC Network Route Changes Monitoring
Ensure that VPC network route changes are being monitored using alerting policies.
Enable data access audit logging for all critical service APIs
Ensure that data access audit logs are enabled for all critical service APIs within your GCP project.
Export All Log Entries Using Sinks
Ensure that all the log entries generated for your Google Cloud projects are exported using sinks.
GCP Cloud Pub/Sub Service
Check for Publicly Accessible Pub/Sub Topics
Ensure there are no publicly accessible Pub/Sub topics available within your cloud account.
Detect Google Cloud Pub/Sub Configuration Changes
Pub/Sub configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable Dead Lettering for Google Pub/Sub Subscriptions
Ensure there is a dead-letter topic configured for each Pub/Sub subscription.
Enable Pub/Sub Topic Encryption with Customer-Managed Encryption Key
Ensure that Pub/Sub topics are encrypted using Customer-Managed Encryption Keys (CMEKs).
Pub/Sub Subscription Cross-Project Access
Ensure that Pub/Sub subscriptions are not configured to allow unknown cross-project access.
Pub/Sub Topic Cross-Project Access
Ensure that Pub/Sub topics don't allow unknown cross-project access.
GCP Cloud Run
Check for Publicly Accessible Cloud Run Services
Ensure there are no publicly accessible Google Cloud services available within your GCP account.
Check for Unrestricted Outbound Network Access
Ensure no Google Cloud Run service allows unrestricted outbound network access.
Check for the Maximum Number of Container Instances
Configuring a maximum number of instances for your Cloud Run services helps control costs by preventing uncontrolled scaling.
Check for the Minimum Number of Container Instances
To improve performance, ensure that the minimum number of container instances is greater than 0 (zero).
Cloud Run Request Concurrency
Configure maximum concurrent requests per instance for Google Cloud Run services.
Cloud Run Service Runtime Version
Ensure that Cloud Run services are using the latest language runtime version available.
Cloud Run Services with Inactive Service Accounts
Ensure that your Cloud Run services are using active service accounts.
Configure Dead Lettering for Pub/Sub-Triggered Services
Ensure that Dead-Letter Topics (DLTs) are configured for Pub/Sub-triggered services.
Enable Automatic Runtime Security Updates
Ensure that automatic runtime security updates are enabled for your Cloud Run services.
Enable Binary Authorization
Ensure that Binary Authorization is enabled for Google Cloud Run services.
Enable End-to-End HTTP/2 for Cloud Run Services
Ensure that end-to-end HTTP/2 support is enabled for Cloud Run services.
Use Customer-Managed Encryption Keys for Services Encryption
Use Customer-Managed Encryption Keys (CMEKs) to protect Cloud Run services and related data at rest.
Use Labels for Resource Management
Ensure that all Cloud Run services are labeled for better resource management.
GCP Cloud SQL
Allow SSL/TLS Connections Only
Ensure that Cloud SQL database instances require SSL/TLS for incoming connections.
Check for Cloud SQL Database Instances with Public IPs
Ensure that Cloud SQL database instances don't have public IP addresses assigned.
Check for Idle Cloud SQL Database Instances
Identify idle Cloud SQL database instances and stop them in order to optimize your cloud costs.
Check for MySQL Major Version
Ensure that MySQL database servers are using the latest major version of MySQL database.
Check for PostgreSQL Major Version
Ensure that PostgreSQL database servers are using the latest major version of PostgreSQL database.
Check for Publicly Accessible Cloud SQL Database Instances
Ensure that your Google Cloud SQL database instances are configured to accept connections from trusted networks and IP addresses only.
Configure "log_error_verbosity" Flag for PostgreSQL Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_error_verbosity" flag.
Configure "log_min_error_statement" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_min_error_statement" flag.
Configure "log_min_messages" Flag for PostgreSQL Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_min_messages" flag.
Configure "log_statement" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_statement" flag.
Configure "max_connections" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "max_connections" flag.
Configure 'user connections' Flag for SQL Server Database Instances
Ensure that SQL Server database instances have the appropriate configuration set for the "user connections" flag.
Configure Automatic Storage Increase Limit
Ensure there is an automatic storage increase limit configured for your Cloud SQL database instances.
Configure Root Password for MySQL Database Access
Ensure that MySQL databases can't be accessed with administrative privileges only (i.e. without using passwords).
Detect GCP Cloud SQL Configuration Changes
Cloud SQL configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable "Contained Database Authentication" Flag for SQL Server Database Instances
Ensure that SQL Server database instances have "contained database authentication" flag set to Off.
Disable "Cross DB Ownership Chaining" Flag for SQL Server Database Instances
Ensure that SQL Server database instances have "cross db ownership chaining" flag set to Off.
Disable "local_infile" Flag for MySQL Database Instances
Ensure that MySQL database instances have the "local_infile" flag set to Off (disabled).
Disable "log_min_duration_statement" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have "log_min_duration_statement" flag set to -1 (Off).
Disable "log_planner_stats" Flag for PostgreSQL Database Instances
Ensure that the "log_planner_stats" PostgreSQL database flag is set to "off".
Disable '3625' Trace Flag for SQL Server Database Instances
Ensure that the "3625" trace flag for SQL database servers is set to "off".
Disable 'external scripts enabled' Flag for SQL Server Database Instances
Ensure that the "external scripts enabled" SQL Server flag is set to "off".
Disable 'log_executor_stats' Flag for PostgreSQL Database Instances
Ensure that the "log_executor_stats" PostgreSQL database flag is set to "off".
Disable 'log_parser_stats' Flag for PostgreSQL Database Instances
Ensure that the "log_parser_stats" PostgreSQL database flag is set to "off".
Disable 'log_statement_stats' Flag for PostgreSQL Database Instances
Ensure that the "log_statement_stats" PostgreSQL database flag is set to "off".
Disable 'remote access' Flag for SQL Server Database Instances
Ensure that the "remote access" SQL Server flag is set to "off".
Disable 'user options' Flag for SQL Server Instances
Ensure that the "user options" SQL Server flag is not configured.
Enable "log_checkpoints" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have "log_checkpoints" flag set to On.
Enable "log_checkpoints" Flag for PostgreSQL Database Server Configuration
Ensure that "log_checkpoints" flag is enabled within your PostgreSQL database servers configuration.
Enable "log_connections" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_connections" configuration flag set to On.
Enable "log_disconnections" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_disconnections" flag set to On (enabled).
Enable "log_lock_waits" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_lock_waits" flag set to On.
Enable "log_temp_files" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_temp_files" flag set to 0 (On).
Enable "skip_show_database" Flag for MySQL Database Instances
Ensure that the "skip_show_database" MySQL database flag is set to "on".
Enable "slow_query_log" Flag for MySQL Database Servers
Ensure that MySQL database instances have the "slow_query_log" flag set to On (enabled).
Enable 'cloudsql.enable_pgaudit' and 'pgaudit.log' Flags for PostgreSQL Database Instances
Ensure that the "cloudsql.enable_pgaudit" PostgreSQL database flag is set to "on" and that "pgaudit.log" is configured appropriately.
Enable 'log_hostname' Flag for PostgreSQL Database Instances
Ensure that the "log_hostname" PostgreSQL database flag is set to "on".
Enable Automated Backups for Cloud SQL Database Instances
Ensure that Cloud SQL database instances are configured with automated backups.
Enable Automatic Storage Increase
Ensure that automatic storage increase is enabled for your Cloud SQL database instances.
Enable Cloud SQL Instance Encryption with Customer-Managed Keys
Ensure that Cloud SQL instances are encrypted with Customer-Managed Keys (CMKs).
Enable High Availability for Cloud SQL Database Instances
Ensure that production SQL database instances are configured to automatically fail over to another zone within the selected cloud region.
Enable Point-in-Time Recovery for MySQL Database Instances
Ensure that your MySQL database instances have Point-in-Time Recovery feature enabled.
Enable SSL/TLS for Cloud SQL Incoming Connections
Ensure that Cloud SQL database instances require all incoming connections to use SSL/TLS.
Rotate Server Certificates for Cloud SQL Database Instances
Ensure that Cloud SQL server certificates are rotated (renewed) before their expiration.
GCP Cloud Storage
Bucket Policies with Administrative Permissions
Ensure that your Google Cloud Storage buckets are not configured with admin permissions.
Check for Publicly Accessible Cloud Storage Buckets
Ensure there are no publicly accessible Cloud Storage buckets available within your Google Cloud Platform (GCP) account.
Check for Sufficient Data Retention Period
Ensure there is a sufficient retention period configured for Google Cloud Storage objects.
Configure Retention Policies with Bucket Lock
Ensure that the log bucket retention policies are using the Bucket Lock feature.
Define index page suffix and error page for the bucket website configuration
Ensure that bucket website configuration includes main page suffix and error page.
Detect GCP Cloud Storage Configuration Changes
Cloud Storage configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable Data Access Audit Logs
Ensure that Data Access audit logs are enabled for your Google Cloud Storage buckets.
Enable Lifecycle Management for Cloud Storage Objects
Ensure that Google Cloud Storage objects are using a lifecycle configuration for cost management.
Enable Object Encryption with Customer-Managed Keys
Ensure that your Cloud Storage objects are encrypted using Customer-Managed Keys (CMKs).
Enable Object Versioning for Cloud Storage Buckets
Ensure that object versioning is enabled for your Google Cloud Storage buckets.
Enable Uniform Bucket-Level Access for Cloud Storage Buckets
Ensure that Google Cloud Storage buckets have uniform bucket-level access enabled.
Enable Usage and Storage Logs
Ensure that usage and storage logs are enabled for your Google Cloud Storage buckets.
Enforce Public Access Prevention
Ensure that Public Access Prevention is enabled for your Google Cloud Storage buckets.
Secure CORS Configuration
Ensure that CORS configuration for your Google Cloud Storage buckets is compliant.
Use VPC Service Controls for Cloud Storage Buckets
Ensure that VPC Service Controls are used to protect your Google Cloud Storage buckets from data exfiltration.
GCP Cloud Tasks
Check for Publicly Accessible Cloud Tasks Queues
Ensure there are no publicly accessible Cloud Tasks queues available in your GCP account.
Configure Exponential Backoff for Retries
Ensure that exponential backoff for retries is configured for Cloud Tasks queues.
Configure Rate Limits for Task Dispatches
Ensure that Cloud Tasks queues have task dispatch rate limits configured.
Configure Retry Policy for Cloud Tasks Queues
Ensure that a retry policy is configured for Cloud Tasks queues.
Enable Data Access Audit Logs for Cloud Tasks Resources
Ensure that Data Access audit logs are enabled for Google Cloud Tasks resources.
Implement Least Privilege Access for Cloud Tasks Queues
Ensure that IAM roles with administrative permissions are not used for Cloud Tasks queue management.
Implement Least Privilege for Cloud Tasks Queue Service Accounts
Ensure that Cloud Tasks queue service accounts are granted least privilege access.
Use Cloud Logging for Cloud Tasks Queues
Ensure that Cloud Logging is enabled for Cloud Tasks queues.
Use Customer-Managed Encryption Keys for Cloud Tasks
Use Customer-Managed Encryption Keys (CMEKs) to encrypt all Google Cloud tasks in your GCP project.
Use IAM Policy Conditions
Ensure Google Cloud Tasks queues are protected with IAM policy conditions.
Use VPC Service Controls for Cloud Tasks
Ensure that VPC Service Controls perimeters are used to protect your Cloud Tasks resources from data exfiltration.
GCP VPC
Check for Legacy Networks
Ensure that legacy networks are not being used anymore within your GCP projects.
Check for Unattached Static External IP Addresses
Release unattached static external IP addresses to optimize cloud costs.
Check for Unrestricted DNS Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP and UDP port 53 (DNS).
Check for Unrestricted FTP Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 20 and 21 (File Transfer Protocol – FTP).
Check for Unrestricted ICMP Access
Ensure that no VPC firewall rules allow unrestricted inbound access using Internet Control Message Protocol (ICMP).
Check for Unrestricted Inbound Access on Uncommon Ports
Ensure that no VPC firewall rules allow unrestricted ingress access to uncommon TCP/UDP ports.
Check for Unrestricted Memcached Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP/UDP port 11211 (Memcached).
Check for Unrestricted MySQL Database Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 3306 (MySQL Database).
Check for Unrestricted Oracle Database Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 1521 (Oracle Database).
Check for Unrestricted Outbound Access on All Ports
Ensure that VPC network firewall rules do not allow unrestricted outbound/egress access.
Check for Unrestricted PostgreSQL Database Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 5432 (PostgreSQL Database Server).
Check for Unrestricted RDP Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 3389 (RDP).
Check for Unrestricted RPC Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 135 (Remote Procedure Call – RPC).
Check for Unrestricted Redis Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 6379 (Redis).
Check for Unrestricted SMTP Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 25 (SMTP).
Check for Unrestricted SQL Server Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 1433 (Microsoft SQL Server).
Check for Unrestricted SSH Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 22 (SSH).
Check for VPC Firewall Rules with Port Ranges
Ensure there are no VPC network firewall rules with range of ports opened to allow incoming traffic.
Configure Private Service Connect Endpoints
Ensure that Private Service Connect endpoints are configured for your VPC networks.
Default VPC Network In Use
Ensure that the default VPC network is not being used within your GCP projects.
Enable Cloud DNS Logging for VPC Networks
Ensure that Cloud DNS logging is enabled for all VPC networks.
Enable Logging for VPC Firewall Rules
Ensure that logging is enabled for your Virtual Private Cloud (VPC) firewall rules.
Enable VPC Flow Logs for VPC Subnets
Ensure that VPC Flow Logs feature is enabled for all VPC network subnets.
Exclude Metadata from Firewall Logging
Ensure that logging metadata is not included within your VPC firewall log files.
Restrict Access to High Risk Ports
Ensure there are no VPC network firewall rules with high-risk ports opened to allow incoming traffic.
Unused Network Firewall Rules
Ensure that unused network firewall rules are disabled or removed from your Google Cloud account.
GCP Compute Engine
Approved Virtual Machine Image in Use
Ensure that all your virtual machine instances are launched from approved images only.
Check for Desired Machine Type(s)
Ensure that your virtual machine (VM) instances are of a given type (e.g. c2-standard-4).
Check for Instance-Associated Service Accounts with Full API Access
Ensure that VM instances are not associated with default service accounts that allow full access to all Google Cloud APIs.
Check for Instances Associated with Default Service Accounts
Ensure that your VM instances are not associated with the default GCP service account.
Check for Publicly Shared Disk Images
Ensure that your virtual machine disk images are not accessible to all GCP accounts.
Check for Virtual Machine Instances with Public IP Addresses
Ensure that Google Cloud VM instances are not using public IP addresses.
Compute Instances with Multiple Network Interfaces
Ensure that virtual machine (VM) instances are not using multiple network interfaces.
Configure Maintenance Behavior for VM Instances
Ensure that "On Host Maintenance" configuration setting is set to "Migrate" for all VM instances.
Configure load balancers for Managed Instance Groups
Ensure that Managed Instance Groups (MIGs) are associated with load balancers.
Configure multiple zones for Managed Instance Groups
Ensure that Managed Instance Groups are configured to run instances across multiple zones.
Detect GCP Compute Engine Configuration Changes
Compute Engine configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable Auto-Delete for VM Instance Persistent Disks
Ensure that the Auto-Delete feature is disabled for the disks attached to your VM instances.
Disable IP Forwarding for Virtual Machine Instances
Ensure that IP Forwarding is not enabled for your Google Cloud virtual machine (VM) instances.
Disable Interactive Serial Console Support
Ensure that interactive serial console support is not enabled for your Google Cloud instances.
Disable Preemptibility for VM Instances
Ensure that your production Google Cloud virtual machine instances are not preemptible.
Enable "Block Project-Wide SSH Keys" Security Feature
Ensure that project-wide SSH keys are not used to access your Google Cloud VM instances.
Enable "Shielded VM" Security Feature
Ensure that Shielded VM feature is enabled for your virtual machine (VM) instances.
Enable Automatic Restart for VM Instances
Ensure that automatic restart is enabled for your Google Cloud virtual machine (VM) instances.
Enable Confidential Computing for Virtual Machine Instances
Ensure that Confidential Computing is enabled for virtual machine (VM) instances.
Enable Deletion Protection for VM Instances
Ensure that deletion protection is enabled for your Google Cloud virtual machine (VM) instances.
Enable Instance Group Autohealing
Ensure that your Google Cloud instance groups are using autohealing to proactively replace failing instances.
Enable OS Login for GCP Projects
Ensure that the OS Login feature is enabled for your Google Cloud projects.
Enable VM Disk Encryption with Customer-Supplied Encryption Keys
Ensure that your virtual machine (VM) instance disks are encrypted with CSEKs.
Enable Virtual Machine Disk Encryption with Customer-Managed Keys
Ensure that your virtual machine (VM) instance disks are encrypted using Customer-Managed Keys (CMKs).
Enforce HTTPS Connections for App Engine Applications
Ensure that Google App Engine applications enforce HTTPS connections.
Instance templates should not assign a public IP address
Ensure that instance templates don't assign a public IP address to VM instances.
Persistent Disks Attached to Suspended Virtual Machines
Identify persistent disks attached to suspended VM instances (i.e. unused persistent disks).
Remove Old Persistent Disk Snapshots
Remove old virtual machine disk snapshots in order to optimize Google Cloud monthly costs.
Use OS Login with 2FA Authentication for VM Instances
Ensure that OS Login is configured with Two-Factor Authentication (2FA) for production VM instances.
GCP Dataproc Service
Enable Dataproc Cluster Encryption with Customer-Managed Keys
Ensure that your Dataproc clusters on Compute Engine are encrypted using Customer-Managed Keys (CMKs).
Publicly Accessible Dataproc Clusters
Ensure that your Dataproc cluster instances are not accessible from the Internet.
GCP Dialog Flow Service
Check for Data Security Settings
Ensure that Data Security Settings are configured for Dialogflow CX agents.
Check for Regional Data Residency and Location Controls
Ensure that Dialogflow CX agents are deployed in appropriate regions to meet compliance requirements.
Enable Cloud Logging for Dialogflow CX Agents
Enable and configure logging for Google Cloud Dialogflow CX virtual agents.
Use Customer-Managed Encryption Keys for Dialogflow CX Agents
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data for Dialogflow CX agents.
Use VPC Service Controls for Dialogflow
Ensure that VPC Service Controls perimeters are used to protect your Dialogflow resources from data exfiltration.
GCP Document AI Service
Check for Data Residency and Regional Controls
Ensure that Document AI processors are deployed in appropriate regions to meet compliance requirements.
Enable Access Approval for Document AI Resources
Ensure that Access Approval is enabled for all your Document AI resources.
Enable Data Access Audit Logs for Document AI
Ensure that Data Access audit logs are enabled for Document AI resources.
Implement Least Privilege Access for Document AI using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for Document AI access control.
Use Customer-Managed Encryption Keys for Document AI Processors
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data for Document AI processors.
Use VPC Service Controls for Document AI
Ensure that VPC Service Controls perimeters are used to protect your Document AI resources from data exfiltration.
GCP Eventarc Service
Configure Dead Lettering for Topics Associated with Eventarc Triggers
Ensure that Dead-Letter Topics (DLTs) are configured for Pub/Sub topics associated with Eventarc triggers.
Enable Data Access Audit Logs for Eventarc Resources
Ensure that Data Access audit logs are enabled for Google Cloud Eventarc resources.
Implement Least Privilege Access for Eventarc Resources
Ensure that IAM roles with administrative permissions are not used for Google Cloud Eventarc resources.
Implement Least Privilege for Eventarc Trigger Service Accounts
Ensure that Eventarc trigger service accounts are granted least privilege access.
Use Customer-Managed Encryption Keys for Eventarc Bus Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt Eventarc bus event messages.
Use Customer-Managed Encryption Keys for Eventarc Channel Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data related to Eventarc triggers.
Use Customer-Managed Encryption Keys for Eventarc GoogleApiSources
Use Customer-Managed Encryption Keys (CMEKs) to encrypt GoogleApiSource resources.
Use Customer-Managed Encryption Keys for Eventarc Pipeline Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data sent through Eventarc pipelines.
Use IAM Policy Conditions
Ensure Google Cloud Eventarc resources are protected with IAM policy conditions.
Use Labels for Resource Management
Ensure that all Google Cloud Eventarc triggers are labeled for better resource management.
Use VPC Service Controls for Eventarc
Ensure that VPC Service Controls perimeters are used to protect your Eventarc resources from data exfiltration.
GCP Filestore
Enable Deletion Protection for Filestore Instances
Ensure that Deletion Protection feature is enabled for Google Cloud Filestore instances.
Restrict Client Access by IP Address or IP Range
Restrict Filestore client access to trusted IP addresses or IP address ranges only.
Use Customer-Managed Encryption Keys for Filestore Data Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data at rest within your Filestore instances.
Use On-Demand Backup and Restore for Google Cloud Filestore Instances
Ensure that on-demand backup and restore functionality is in use for Google Cloud Filestore instances.
Use VPC Service Controls for Filestore Instances
Ensure that VPC Service Controls perimeters are used to protect your Filestore instances from data exfiltration.
GCP Google Kubernetes Engine Service
Access Secrets Stored Outside GKE Clusters
Ensure that Google Kubernetes Engine (GKE) clusters can access Secret Manager secrets.
Automate Cluster Version Upgrades using Release Channels
Automate version management for your Google Kubernetes Engine (GKE) clusters using Release Channels.
Check for Alpha Clusters in Production
Ensure that Alpha GKE clusters are not used for production workloads.
Detect GCP GKE Configuration Changes
GKE configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable Client Certificates
Ensure that authentication using client certificates is disabled.
Disable Kubernetes Dashboard for GKE Clusters
Ensure that Kubernetes Dashboard is disabled for GKE clusters.
Disable Legacy Authorization
Disable legacy authorization for Google Kubernetes Engine (GKE) clusters.
Enable Auto-Repair for GKE Cluster Nodes
Ensure that your Google Kubernetes Engine (GKE) clusters are using auto-repairing nodes.
Enable Auto-Upgrade for GKE Cluster Nodes
Ensure that your Google Kubernetes Engine (GKE) cluster nodes are using automatic upgrades.
Enable Binary Authorization
Ensure that Binary Authorization is enabled for Google Kubernetes Engine (GKE) clusters.
Enable Cluster Backups
Enable and configure backups for Google Kubernetes Engine (GKE) clusters.
Enable Cost Allocation
Enable cost allocation for Google Kubernetes Engine (GKE) clusters.
Enable Critical Notifications
Enable critical notifications for Google Kubernetes Engine (GKE) clusters.
Enable Encryption for Application-Layer Secrets for GKE Clusters
Ensure that encryption of Kubernetes secrets using Customer-Managed Keys is enabled for GKE clusters.
Enable GKE Cluster Node Encryption with Customer-Managed Encryption Keys
Ensure that boot disk encryption with Customer-Managed Encryption Keys is enabled for GKE cluster nodes.
Enable GKE Metadata Server
Enable the GKE Metadata Server feature for Google Kubernetes Engine (GKE) clusters.
Enable Integrity Monitoring for Cluster Nodes
Ensure that Integrity Monitoring is enabled for your Google Kubernetes Engine (GKE) cluster nodes.
Enable Inter-Node Transparent Encryption
Ensure that inter-node transparent encryption is enabled for Google Kubernetes Engine (GKE) clusters.
Enable Intranode Visibility
Enable the Intranode Visibility feature for Google Kubernetes Engine (GKE) clusters.
Enable Private Nodes
Enable private nodes for Google Kubernetes Engine (GKE) clusters.
Enable Secure Boot for Cluster Nodes
Ensure that Secure Boot is enabled for your Google Kubernetes Engine (GKE) cluster nodes.
Enable VPC-Native Traffic Routing
Enable VPC-native traffic routing for Google Kubernetes Engine (GKE) clusters.
Enable Workload Identity Federation
Enable Workload Identity Federation for Google Kubernetes Engine (GKE) clusters.
Enable Workload Vulnerability Scanning
Enable workload vulnerability scanning for Google Kubernetes Engine (GKE) clusters.
Enable and Configure Cluster Logging
Enable and configure logging for Google Kubernetes Engine (GKE) clusters.
Enable and Configure Cluster Monitoring
Enable and configure Cloud Monitoring for Google Kubernetes Engine (GKE) clusters.
Enable and Configure Security Posture
Enable the Security Posture dashboard for Google Kubernetes Engine (GKE) clusters.
Prevent Default Service Account Usage
Ensure that GKE clusters are not configured to use the default service account.
Restrict Network Access
Ensure that Google Kubernetes Engine (GKE) cluster control plane is not exposed to the Internet.
Use Confidential GKE Cluster Nodes
Enable confidential GKE nodes for Google Kubernetes Engine (GKE) clusters.
Use Container-Optimized OS for GKE Clusters Nodes
Enable Container-Optimized OS for Google Kubernetes Engine (GKE) cluster nodes.
Use GKE Clusters with Private Endpoints Only
Ensure that Google Kubernetes Engine (GKE) clusters are using private endpoints only for control plane access.
Use Labels for Resource Management
Ensure that all Google Kubernetes Engine (GKE) clusters are labeled for better resource management.
Use Sandbox with gVisor for GKE Clusters Nodes
Enable GKE Sandbox with gVisor to protect from untrusted workloads.
Use Shielded GKE Cluster Nodes
Ensure that your GKE clusters nodes are shielded to protect against impersonation attacks.
GCP Network Connectivity
Enable Cloud NAT for Private Subnets
Ensure that Cloud NAT is enabled for VPC private subnets.
Enable Logging for Cloud NAT Gateways
Ensure that logging is enabled for Cloud NAT gateways.
Implement Least Privilege Access for Cloud NAT Management
Ensure that IAM roles with administrative permissions are not used for Cloud NAT management.
Limit NAT to Specific Subnets Only
Avoid misconfiguration by limiting Cloud NAT gateways to specific subnets only.
Use Private Google Access with Cloud NAT
Ensure that Private Google Access is enabled for the VPC subnets associated with your Cloud NAT gateways.
Use Reserved External IPs for Cloud NAT Gateways
sEnsure that your Cloud NAT gateways are using reserved external IPs.
GCP Resource Manager
Define Allowed External IPs for VM Instances
Ensure that "Define Allowed External IPs for VM Instances" policy is enforced at the GCP organization level.
Detect GCP Resource Manager Configuration Changes
Resource Manager configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable Automatic IAM Role Grants for Default Service Accounts
Ensure that "Disable Automatic IAM Grants for Default Service Accounts" policy is enforced.
Disable Guest Attributes of Compute Engine Metadata
Ensure that "Disable Guest Attributes of Compute Engine Metadata" policy is enabled at the GCP organization level.
Disable Serial Port Access Support at Organization Level
Ensure that "Disable VM serial port access" policy is enforced at the GCP organization level.
Disable Service Account Key Upload
Ensure that the key upload feature for Cloud IAM service accounts is disabled.
Disable User-Managed Key Creation for Service Accounts
Ensure that the user-managed key creation for Cloud IAM service accounts is disabled.
Disable Workload Identity at Cluster Creation
Ensure that "Disable Workload Identity Cluster Creation" policy is enabled for your GCP organizations.
Enforce Detailed Audit Logging Mode
Ensure that "Google Cloud Platform - Detailed Audit Logging Mode" policy is enabled for your GCP organizations.
Enforce Uniform Bucket-Level Access
Ensure that "Enforce uniform bucket-level access" organization policy is enabled at the Google Cloud Platform (GCP) organization level, and that the project inherits the parent's policy.
Prevent Service Account Creation for Google Cloud Organizations
Ensure that Cloud IAM service account creation is disabled at the organization level.
Require OS Login
Ensure that "Require OS Login" policy is enabled for your GCP organizations.
Restrict Allowed Google Cloud APIs and Services
Ensure that "Restrict allowed Google Cloud APIs and services" organization policy is enforced for your GCP organizations.
Restrict Authorized Networks on Cloud SQL instances
Ensure that "Restrict Authorized Networks on Cloud SQL instances" policy is enforced at GCP organization level.
Restrict Default Google-Managed Encryption for Cloud SQL Instances (Deprecated)
Ensure that "Restrict Default Google-Managed Encryption for Cloud SQL Instances" policy is enforced at the GCP organization level.
Restrict Load Balancer Creation Based on Load Balancer Types
Ensure that "Restrict Load Balancer Creation Based on Load Balancer Types" policy is enforced at the GCP organization level.
Restrict Public IP Access for Cloud SQL Instances at Organization Level
Ensure that "Restrict Public IP access on Cloud SQL instances" policy is enabled at the GCP organization level.
Restrict Shared VPC Subnetworks
Ensure that "Restrict Shared VPC Subnetworks" policy is enforced for your GCP organizations.
Restrict VPC Peering Usage
Ensure that "Restrict VPC Peering Usage" policy is enforced for your GCP organizations.
Restrict VPN Peer IPs
Ensure that "Restrict VPN Peer IPs" constraint policy is enabled for your GCP organizations.
Restrict Virtual Machine IP Forwarding
Ensure that "Restrict VM IP Forwarding" policy is enforced at the GCP organization level.
Restrict the Creation of Cloud Resources to Specific Locations
Ensure that "Google Cloud Platform - Resource Location Restriction" constraint policy is enforced for your GCP organizations.
Restricting the Use of Images
Ensure that "Define Trusted Image Projects" policy is enforced for your GCP organizations.
Skip Default VPC Network Creation
Ensure that the creation of the default VPC network is disabled at the GCP organization level.
GCP Secret Manager
Enable Data Access Audit Logs for Secret Manager
Ensure that Data Access audit logs are enabled for Secret Manager resources.
Enable Destruction Delay for Secret Versions
Ensure that a delayed destruction policy is configured for your Secret Manager secrets.
Enable Rotation Schedules for Secret Manager Secrets
Ensure that rotation schedules are configured for your Secret Manager secrets.
Implement Least Privilege Access for Secret Manager Secrets using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for Secret Manager resource access control.
Use Customer-Managed Encryption Keys for Secret Manager Secret Encryption
Ensure that your Secret Manager secrets are encrypted with Customer-Managed Encryption Keys.
GCP VertexAI
Configure Private Service Connect Endpoints
Ensure that Private Service Connect endpoints are configured for your Vertex AI resources.
Default VPC Network In Use
Ensure that the default VPC network is not being used for your Vertex AI notebook instances.
Disable Root Access for Workbench Instances
Ensure root access is disabled for your Vertex AI notebook instances.
Enable Automatic Upgrades for Workbench Instances
Ensure that automatic upgrades are enabled for your Vertex AI notebook instances.
Enable Cloud Monitoring for Workbench Instances
Ensure that Cloud Monitoring feature is enabled for your Vertex AI notebook instances.
Enable Idle Shutdown for Workbench Instances
Ensure that the Idle Shutdown feature is enabled for your Vertex AI notebook instances.
Enable Integrity Monitoring for Workbench Instances
Ensure that the Integrity Monitoring feature is enabled for your Vertex AI notebook instances.
Enable Secure Boot for Workbench Instances
Ensure that Secure Boot is enabled for your Vertex AI notebook instances.
Enable Virtual Trusted Platform Module (vTPM) for Workbench Instances
Ensure that vTPM feature is enabled for your Vertex AI notebook instances.
Prevent Assigning External IPs to Workbench Instances
Ensure that external IP addresses are not assigned to Vertex AI notebook instances.
Use VPC Service Controls for Vertex AI
Ensure that VPC Service Controls perimeters are used to protect your Vertex AI resources from data exfiltration.
Vertex AI Dataset Encryption with Customer-Managed Encryption Keys
Ensure that Vertex AI datasets are encrypted using Customer-Managed Encryption Keys (CMEKs) (Not Scored).
Workbench Instance Encryption with Customer-Managed Encryption Keys
Ensure that Vertex AI notebook instances are encrypted using Customer-Managed Encryption Keys (CMEKs).

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
https://www.trendmicro.com/cloudoneconformity/knowledge-base/gcp/

## Full Content
Knowledge Base
Google Cloud Platform
Get Started
Get Pricing
Contact Us
Google Cloud Platform best practice rules
Trend Vision One™ has over 1100+ cloud infrastructure configuration best practices for your
Alibaba Cloud
,
Amazon Web Services
,
Microsoft® Azure
, and Google Cloud™ environments. Here is our growing list of GCP best practice rules with clear instructions on how to perform the updates – made either through the GCP console or via the Command Line Interface (CLI).
Trend Vision One™ provides real-time monitoring and auto-remediation for the security, compliance and governance of your cloud infrastructure. Leaving you to grow and scale your business with confidence.
GCP ApiGateway
Check for API Gateway Authentication Method
Ensure that API Gateway uses an authentication method to secure access to your API backend.
Enable Data Access Audit Logs
Ensure that Data Access audit logs are enabled for Google Cloud API Gateway APIs.
Enable Data Encryption for API Gateway Backend Integrations
Ensure that associated backend services are configured to communicate with API Gateway using HTTPS.
Implement Least Privilege Access using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for API access control.
Protect API Gateway with Cloud Armor
Ensure that API Gateway leverages Cloud Armor as a network security service.
Rate Limit API Usage with Quotas
Ensure that API Gateway is configured to use rate limiting with quotas for your APIs.
Use Labels for Resource Management
Ensure that all Google Cloud API Gateway APIs are labeled for better resource management.
GCP ArtifactRegistry
Check for Publicly Accessible Artifact Registry Repositories
Ensure there are no publicly accessible Artifact Registry repositories available in your GCP account.
Enable Artifact Registry Vulnerability Scanning
Ensure that vulnerability scanning for Artifact Registry repositories is enabled to enhance security and mitigate potential risks.
Use Customer-Managed Encryption Keys for Repositories Encryption
Use Customer-Managed Encryption Keys (CMEKs) to protect Artifact Registry repositories and related data at rest.
GCP BigQuery
Check for Publicly Accessible BigQuery Datasets
Ensure that Google Cloud BigQuery datasets are not publicly accessible.
Enable BigQuery Dataset Encryption with Customer-Managed Encryption Keys
Ensure that BigQuery datasets are encrypted using Customer-Managed Encryption Keys (CMEKs).
Enable BigQuery Encryption with Customer-Managed Keys
Ensure that BigQuery dataset tables are encrypted using Customer-Managed Keys (CMKs).
GCP CertificateManager
Check for Compliant Trust Configuration
To prevent certificate validation from being bypassed, ensure your Certificate Manager Trust Configs are compliant.
Enable Data Access Audit Logs for Certificate Manager
Ensure that Data Access audit logs are enabled for Certificate Manager resources.
Enable Monitoring for Certificate Expiration
Ensure that Certificate Manager certificate expiration is being monitored using alerting policies.
Implement Least Privilege Access for Certificate Manager using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for Certificate Manager access control.
SSL certificates validity period
Ensure that SSL certificates are renewed within the appropriate validity period.
Use VPC Service Controls for Certificate Manager
Ensure that VPC Service Controls perimeters are used to protect your Certificate Manager resources from data exfiltration.
GCP API
API Keys Should Only Exist for Active Services
Ensure there are no API keys in use within your Google Cloud projects.
Check for API Key API Restrictions
Ensure that API keys are restricted to only those APIs that your application needs access to.
Check for API Key Application Restrictions
Ensure there are no unrestricted API keys available within your Google Cloud Platform (GCP) project.
Enable Cloud Asset Inventory
Ensure that Google Cloud Asset Inventory is enabled for your GCP projects.
Enable Security Command Center API
Ensure that Google Cloud Security Command Center API is enabled.
Enable critical service APIs
Ensure that critical service APIs are enabled for your GCP projects.
Latest Operating System Updates
Ensure that your Google Cloud virtual machine (VM) instances are using the latest operating system updates.
Rotate Google Cloud API Keys
Ensure that all the API keys created for your Google Cloud Platform (GCP) projects are regularly rotated.
GCP CloudCDN
Backend Buckets Referencing Missing Storage Buckets
Ensure that your backend buckets are using active storage buckets to store content.
Configure Cloud CDN origin authentication
Ensure that Cloud CDN origins are authenticating access to the cached content.
Configure SSL/TLS certificates for Cloud CDN backend bucket origins
Ensure that Cloud CDN backend bucket origins are using SSL/TLS certificates.
Configure SSL/TLS certificates for Cloud CDN backend service origins
Ensure that Cloud CDN backend service origins are using SSL/TLS certificates.
GCP Domain Name System (DNS)
Check for DNSSEC Key-Signing Algorithm in Use
Ensure that RSASHA1 signature algorithm is not used for DNSSEC key signing.
Check for DNSSEC Zone-Signing Algorithm in Use
Ensure that DNSSEC key signing is not using RSASHA1 as a signature algorithm.
Detect GCP Cloud DNS Configuration Changes
Cloud DNS configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable DNSSEC for Google Cloud DNS Zones
Ensure that DNSSEC is enabled for your Domain Name System (DNS) managed zones.
Remove Dangling DNS Records
Ensure that dangling DNS records are removed from your Cloud DNS zones to avoid domain/subdomain takeover.
GCP Cloud Function
Check for Unrestricted Outbound Network Access
Ensure no Google Cloud functions allow unrestricted outbound network access.
Cloud Logging Permissions for Google Cloud Functions
Ensure that Cloud Logging API has appropriate permissions to write function logs.
Configure Dead Lettering for Pub/Sub-Triggered Functions
Ensure that Dead-Letter Topics (DLTs) are configured for Pub/Sub-triggered functions.
Configure Maximum Instances for Cloud Functions
Configuring a maximum number of instances for your Google Cloud functions helps control costs by preventing uncontrolled scaling.
Configure Minimum Instances for Cloud Functions
To improve performance, ensure that the minimum number of function instances is greater than 0 (zero).
Enable Automatic Runtime Security Updates
Ensure that automatic runtime security updates are enabled for your Google Cloud functions.
Enable Serverless VPC Access for Google Cloud Functions
Ensure that Serverless VPC Access is enabled for your Google Cloud functions.
Functions with Inactive Service Accounts
Ensure that your Google Cloud functions are using active service accounts.
GCP Execution Runtime Environment Version
Ensure that your Google Cloud functions are using the latest execution runtime environment.
GCP Function Runtime Version
Ensure that your GCP functions are using the latest language runtime version available.
GCP Function using Default Service Account
Ensure that your Google Cloud functions are not using the default service account.
GCP Function using Service Account with Basic Roles
Ensure that your Google Cloud functions are not using basic roles for permissions.
GCP Functions with Admin Privileges
Ensure that your Google Cloud functions are not configured with admin privileges.
Publicly Accessible Functions
Ensure there are no publicly accessible Google Cloud functions available within your GCP account.
Use Customer-Managed Encryption Keys for Functions Encryption
Use Customer-Managed Encryption Keys (CMEKs) to protect Google Cloud functions and related data at rest.
Use Labels for Resource Management
Ensure that all Google Cloud functions are labeled for better resource management.
Use Secrets Manager for Managing Secrets in Google Cloud Functions
Manage secrets using Secrets Manager service instead of Cloud Functions environment variables.
GCP Identity and Access Management (IAM)
Check for IAM Members with Service Roles at the Project Level
Ensure there are no IAM members with Service Account User and Service Account Token Creator roles at the project level.
Configure Essential Contacts for Organizations
Ensure that Essential Contacts are defined for your Google Cloud organization.
Configure Google Cloud Audit Logs to Track All Activities
Ensure that the Audit Logs feature is configured to record all service and user activities.
Corporate Login Credentials In Use
Use corporate login credentials instead of personal accounts such as Gmail accounts.
Delete Google Cloud API Keys
Ensure there are no API keys associated with your Google Cloud Platform (GCP) projects.
Delete User-Managed Service Account Keys
Ensure there are no user-managed keys associated with your GCP service accounts.
Detect GCP IAM Configuration Changes
IAM configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable Access Approval
Ensure that Access Approval is enabled for your Google Cloud projects.
Enable Access Transparency
Ensure that Access Transparency is enabled within your Google Cloud organization.
Enable Multi-Factor Authentication for User Accounts
Ensure that Multi-Factor Authentication (MFA) feature is enabled for all GCP user accounts.
Enable Security Key Enforcement for Admin Accounts
Enforce the use of security keys to help prevent Google Cloud account hijacking.
Enforce Separation of Duties for KMS-Related Roles
Ensure that separation of duties is implemented for all Google Cloud KMS-related roles.
Enforce Separation of Duties for Service-Account Related Roles
Ensure that separation of duties is implemented for all Google Cloud service account roles.
Minimize the Use of Primitive Roles
Ensure that the use of Cloud Identity and Access Management (IAM) primitive roles is limited within your Google Cloud projects.
Restrict Administrator Access for Service Accounts
Ensure that user-managed service accounts are not using administrator-based roles.
Rotate User-Managed Service Account Keys
Ensure that your user-managed service account keys are rotated periodically.
GCP Cloud Key Management Service (KMS)
Check for Publicly Accessible Cloud KMS Keys
Ensure there are no publicly accessible KMS cryptographic keys available within your Google Cloud account.
Detect Google Cloud KMS Configuration Changes
Cloud KMS configuration changes have been detected within your Google Cloud Platform (GCP) account.
Rotate Google Cloud KMS Keys
Ensure that all KMS cryptographic keys available within your Google Cloud account are regularly rotated.
GCP Cloud Load Balancing
Approved External Load Balancers
Ensure that only approved external load balancers are used for load-balanced websites and applications.
Check for Insecure SSL Cipher Suites
Ensure there are no HTTPS/SSL Proxy load balancers configured with insecure SSL policies.
Configure Cloud CDN origin backend bucket
Ensure that your Cloud CDN origin points to a backend bucket.
Configure edge security policies for load balancer backend services
Ensure that load balancer backend services are protected with edge security policies.
Detect GCP Load Balancer Configuration Changes
Load Balancing configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable HTTPS for Google Cloud Load Balancers
Ensure that Google Cloud load balancers enforce HTTPS to handle encrypted web traffic.
Enable Logging for HTTP(S) Load Balancers
Ensure that logging is enabled for your Google Cloud HTTP(S) load balancers.
Use Google-Managed SSL Certificates for Application Load Balancers
Ensure that external Application Load Balancers are using Google-managed SSL certificates.
GCP Cloud Logging
Check for Sufficient Log Data Retention Period
Ensure that the retention period configured for your logging buckets is 365 days or greater.
Configure Retention Policies with Bucket Lock
Ensure that the log bucket retention policies are using the Bucket Lock feature.
Enable Global Logging
Ensure that the location of your Cloud Logging buckets is global.
Enable Logs Router Encryption with Customer-Managed Keys
Ensure that Google Cloud Logs Router data is encrypted using Customer-Managed Keys (CMKs).
Enable Monitoring for Audit Configuration Changes
Ensure that GCP project audit configuration changes are being monitored using alerting policies.
Enable Monitoring for Bucket Permission Changes
Ensure that Cloud Storage bucket permission changes are being monitored using alerting policies.
Enable Monitoring for Custom Role Changes
Ensure that custom IAM role changes are being monitored using alerting policies.
Enable Monitoring for Firewall Rule Changes
Ensure that VPC network firewall rule changes are being monitored using alerting policies.
Enable Monitoring for SQL Instance Configuration Changes
Ensure that SQL instance configuration changes are being monitored using alerting policies.
Enable Project Ownership Assignments Monitoring
Ensure that GCP project ownership changes are being monitored using alerting policies.
Enable VPC Network Changes Monitoring
Ensure that Google Cloud VPC network changes are being monitored using log metrics and alerting policies.
Enable VPC Network Route Changes Monitoring
Ensure that VPC network route changes are being monitored using alerting policies.
Enable data access audit logging for all critical service APIs
Ensure that data access audit logs are enabled for all critical service APIs within your GCP project.
Export All Log Entries Using Sinks
Ensure that all the log entries generated for your Google Cloud projects are exported using sinks.
GCP Cloud Pub/Sub Service
Check for Publicly Accessible Pub/Sub Topics
Ensure there are no publicly accessible Pub/Sub topics available within your cloud account.
Detect Google Cloud Pub/Sub Configuration Changes
Pub/Sub configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable Dead Lettering for Google Pub/Sub Subscriptions
Ensure there is a dead-letter topic configured for each Pub/Sub subscription.
Enable Pub/Sub Topic Encryption with Customer-Managed Encryption Key
Ensure that Pub/Sub topics are encrypted using Customer-Managed Encryption Keys (CMEKs).
Pub/Sub Subscription Cross-Project Access
Ensure that Pub/Sub subscriptions are not configured to allow unknown cross-project access.
Pub/Sub Topic Cross-Project Access
Ensure that Pub/Sub topics don't allow unknown cross-project access.
GCP Cloud Run
Check for Publicly Accessible Cloud Run Services
Ensure there are no publicly accessible Google Cloud services available within your GCP account.
Check for Unrestricted Outbound Network Access
Ensure no Google Cloud Run service allows unrestricted outbound network access.
Check for the Maximum Number of Container Instances
Configuring a maximum number of instances for your Cloud Run services helps control costs by preventing uncontrolled scaling.
Check for the Minimum Number of Container Instances
To improve performance, ensure that the minimum number of container instances is greater than 0 (zero).
Cloud Run Request Concurrency
Configure maximum concurrent requests per instance for Google Cloud Run services.
Cloud Run Service Runtime Version
Ensure that Cloud Run services are using the latest language runtime version available.
Cloud Run Services with Inactive Service Accounts
Ensure that your Cloud Run services are using active service accounts.
Configure Dead Lettering for Pub/Sub-Triggered Services
Ensure that Dead-Letter Topics (DLTs) are configured for Pub/Sub-triggered services.
Enable Automatic Runtime Security Updates
Ensure that automatic runtime security updates are enabled for your Cloud Run services.
Enable Binary Authorization
Ensure that Binary Authorization is enabled for Google Cloud Run services.
Enable End-to-End HTTP/2 for Cloud Run Services
Ensure that end-to-end HTTP/2 support is enabled for Cloud Run services.
Use Customer-Managed Encryption Keys for Services Encryption
Use Customer-Managed Encryption Keys (CMEKs) to protect Cloud Run services and related data at rest.
Use Labels for Resource Management
Ensure that all Cloud Run services are labeled for better resource management.
GCP Cloud SQL
Allow SSL/TLS Connections Only
Ensure that Cloud SQL database instances require SSL/TLS for incoming connections.
Check for Cloud SQL Database Instances with Public IPs
Ensure that Cloud SQL database instances don't have public IP addresses assigned.
Check for Idle Cloud SQL Database Instances
Identify idle Cloud SQL database instances and stop them in order to optimize your cloud costs.
Check for MySQL Major Version
Ensure that MySQL database servers are using the latest major version of MySQL database.
Check for PostgreSQL Major Version
Ensure that PostgreSQL database servers are using the latest major version of PostgreSQL database.
Check for Publicly Accessible Cloud SQL Database Instances
Ensure that your Google Cloud SQL database instances are configured to accept connections from trusted networks and IP addresses only.
Configure "log_error_verbosity" Flag for PostgreSQL Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_error_verbosity" flag.
Configure "log_min_error_statement" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_min_error_statement" flag.
Configure "log_min_messages" Flag for PostgreSQL Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_min_messages" flag.
Configure "log_statement" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "log_statement" flag.
Configure "max_connections" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the appropriate configuration set for the "max_connections" flag.
Configure 'user connections' Flag for SQL Server Database Instances
Ensure that SQL Server database instances have the appropriate configuration set for the "user connections" flag.
Configure Automatic Storage Increase Limit
Ensure there is an automatic storage increase limit configured for your Cloud SQL database instances.
Configure Root Password for MySQL Database Access
Ensure that MySQL databases can't be accessed with administrative privileges only (i.e. without using passwords).
Detect GCP Cloud SQL Configuration Changes
Cloud SQL configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable "Contained Database Authentication" Flag for SQL Server Database Instances
Ensure that SQL Server database instances have "contained database authentication" flag set to Off.
Disable "Cross DB Ownership Chaining" Flag for SQL Server Database Instances
Ensure that SQL Server database instances have "cross db ownership chaining" flag set to Off.
Disable "local_infile" Flag for MySQL Database Instances
Ensure that MySQL database instances have the "local_infile" flag set to Off (disabled).
Disable "log_min_duration_statement" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have "log_min_duration_statement" flag set to -1 (Off).
Disable "log_planner_stats" Flag for PostgreSQL Database Instances
Ensure that the "log_planner_stats" PostgreSQL database flag is set to "off".
Disable '3625' Trace Flag for SQL Server Database Instances
Ensure that the "3625" trace flag for SQL database servers is set to "off".
Disable 'external scripts enabled' Flag for SQL Server Database Instances
Ensure that the "external scripts enabled" SQL Server flag is set to "off".
Disable 'log_executor_stats' Flag for PostgreSQL Database Instances
Ensure that the "log_executor_stats" PostgreSQL database flag is set to "off".
Disable 'log_parser_stats' Flag for PostgreSQL Database Instances
Ensure that the "log_parser_stats" PostgreSQL database flag is set to "off".
Disable 'log_statement_stats' Flag for PostgreSQL Database Instances
Ensure that the "log_statement_stats" PostgreSQL database flag is set to "off".
Disable 'remote access' Flag for SQL Server Database Instances
Ensure that the "remote access" SQL Server flag is set to "off".
Disable 'user options' Flag for SQL Server Instances
Ensure that the "user options" SQL Server flag is not configured.
Enable "log_checkpoints" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have "log_checkpoints" flag set to On.
Enable "log_checkpoints" Flag for PostgreSQL Database Server Configuration
Ensure that "log_checkpoints" flag is enabled within your PostgreSQL database servers configuration.
Enable "log_connections" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_connections" configuration flag set to On.
Enable "log_disconnections" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_disconnections" flag set to On (enabled).
Enable "log_lock_waits" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_lock_waits" flag set to On.
Enable "log_temp_files" Flag for PostgreSQL Database Instances
Ensure that PostgreSQL database instances have the "log_temp_files" flag set to 0 (On).
Enable "skip_show_database" Flag for MySQL Database Instances
Ensure that the "skip_show_database" MySQL database flag is set to "on".
Enable "slow_query_log" Flag for MySQL Database Servers
Ensure that MySQL database instances have the "slow_query_log" flag set to On (enabled).
Enable 'cloudsql.enable_pgaudit' and 'pgaudit.log' Flags for PostgreSQL Database Instances
Ensure that the "cloudsql.enable_pgaudit" PostgreSQL database flag is set to "on" and that "pgaudit.log" is configured appropriately.
Enable 'log_hostname' Flag for PostgreSQL Database Instances
Ensure that the "log_hostname" PostgreSQL database flag is set to "on".
Enable Automated Backups for Cloud SQL Database Instances
Ensure that Cloud SQL database instances are configured with automated backups.
Enable Automatic Storage Increase
Ensure that automatic storage increase is enabled for your Cloud SQL database instances.
Enable Cloud SQL Instance Encryption with Customer-Managed Keys
Ensure that Cloud SQL instances are encrypted with Customer-Managed Keys (CMKs).
Enable High Availability for Cloud SQL Database Instances
Ensure that production SQL database instances are configured to automatically fail over to another zone within the selected cloud region.
Enable Point-in-Time Recovery for MySQL Database Instances
Ensure that your MySQL database instances have Point-in-Time Recovery feature enabled.
Enable SSL/TLS for Cloud SQL Incoming Connections
Ensure that Cloud SQL database instances require all incoming connections to use SSL/TLS.
Rotate Server Certificates for Cloud SQL Database Instances
Ensure that Cloud SQL server certificates are rotated (renewed) before their expiration.
GCP Cloud Storage
Bucket Policies with Administrative Permissions
Ensure that your Google Cloud Storage buckets are not configured with admin permissions.
Check for Publicly Accessible Cloud Storage Buckets
Ensure there are no publicly accessible Cloud Storage buckets available within your Google Cloud Platform (GCP) account.
Check for Sufficient Data Retention Period
Ensure there is a sufficient retention period configured for Google Cloud Storage objects.
Configure Retention Policies with Bucket Lock
Ensure that the log bucket retention policies are using the Bucket Lock feature.
Define index page suffix and error page for the bucket website configuration
Ensure that bucket website configuration includes main page suffix and error page.
Detect GCP Cloud Storage Configuration Changes
Cloud Storage configuration changes have been detected within your Google Cloud Platform (GCP) account.
Enable Data Access Audit Logs
Ensure that Data Access audit logs are enabled for your Google Cloud Storage buckets.
Enable Lifecycle Management for Cloud Storage Objects
Ensure that Google Cloud Storage objects are using a lifecycle configuration for cost management.
Enable Object Encryption with Customer-Managed Keys
Ensure that your Cloud Storage objects are encrypted using Customer-Managed Keys (CMKs).
Enable Object Versioning for Cloud Storage Buckets
Ensure that object versioning is enabled for your Google Cloud Storage buckets.
Enable Uniform Bucket-Level Access for Cloud Storage Buckets
Ensure that Google Cloud Storage buckets have uniform bucket-level access enabled.
Enable Usage and Storage Logs
Ensure that usage and storage logs are enabled for your Google Cloud Storage buckets.
Enforce Public Access Prevention
Ensure that Public Access Prevention is enabled for your Google Cloud Storage buckets.
Secure CORS Configuration
Ensure that CORS configuration for your Google Cloud Storage buckets is compliant.
Use VPC Service Controls for Cloud Storage Buckets
Ensure that VPC Service Controls are used to protect your Google Cloud Storage buckets from data exfiltration.
GCP Cloud Tasks
Check for Publicly Accessible Cloud Tasks Queues
Ensure there are no publicly accessible Cloud Tasks queues available in your GCP account.
Configure Exponential Backoff for Retries
Ensure that exponential backoff for retries is configured for Cloud Tasks queues.
Configure Rate Limits for Task Dispatches
Ensure that Cloud Tasks queues have task dispatch rate limits configured.
Configure Retry Policy for Cloud Tasks Queues
Ensure that a retry policy is configured for Cloud Tasks queues.
Enable Data Access Audit Logs for Cloud Tasks Resources
Ensure that Data Access audit logs are enabled for Google Cloud Tasks resources.
Implement Least Privilege Access for Cloud Tasks Queues
Ensure that IAM roles with administrative permissions are not used for Cloud Tasks queue management.
Implement Least Privilege for Cloud Tasks Queue Service Accounts
Ensure that Cloud Tasks queue service accounts are granted least privilege access.
Use Cloud Logging for Cloud Tasks Queues
Ensure that Cloud Logging is enabled for Cloud Tasks queues.
Use Customer-Managed Encryption Keys for Cloud Tasks
Use Customer-Managed Encryption Keys (CMEKs) to encrypt all Google Cloud tasks in your GCP project.
Use IAM Policy Conditions
Ensure Google Cloud Tasks queues are protected with IAM policy conditions.
Use VPC Service Controls for Cloud Tasks
Ensure that VPC Service Controls perimeters are used to protect your Cloud Tasks resources from data exfiltration.
GCP VPC
Check for Legacy Networks
Ensure that legacy networks are not being used anymore within your GCP projects.
Check for Unattached Static External IP Addresses
Release unattached static external IP addresses to optimize cloud costs.
Check for Unrestricted DNS Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP and UDP port 53 (DNS).
Check for Unrestricted FTP Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 20 and 21 (File Transfer Protocol – FTP).
Check for Unrestricted ICMP Access
Ensure that no VPC firewall rules allow unrestricted inbound access using Internet Control Message Protocol (ICMP).
Check for Unrestricted Inbound Access on Uncommon Ports
Ensure that no VPC firewall rules allow unrestricted ingress access to uncommon TCP/UDP ports.
Check for Unrestricted Memcached Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP/UDP port 11211 (Memcached).
Check for Unrestricted MySQL Database Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 3306 (MySQL Database).
Check for Unrestricted Oracle Database Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 1521 (Oracle Database).
Check for Unrestricted Outbound Access on All Ports
Ensure that VPC network firewall rules do not allow unrestricted outbound/egress access.
Check for Unrestricted PostgreSQL Database Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 5432 (PostgreSQL Database Server).
Check for Unrestricted RDP Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 3389 (RDP).
Check for Unrestricted RPC Access
Ensure there are no VPC firewall rules that allow unrestricted inbound access on TCP port 135 (Remote Procedure Call – RPC).
Check for Unrestricted Redis Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 6379 (Redis).
Check for Unrestricted SMTP Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 25 (SMTP).
Check for Unrestricted SQL Server Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 1433 (Microsoft SQL Server).
Check for Unrestricted SSH Access
Ensure that no VPC firewall rules allow unrestricted inbound access on TCP port 22 (SSH).
Check for VPC Firewall Rules with Port Ranges
Ensure there are no VPC network firewall rules with range of ports opened to allow incoming traffic.
Configure Private Service Connect Endpoints
Ensure that Private Service Connect endpoints are configured for your VPC networks.
Default VPC Network In Use
Ensure that the default VPC network is not being used within your GCP projects.
Enable Cloud DNS Logging for VPC Networks
Ensure that Cloud DNS logging is enabled for all VPC networks.
Enable Logging for VPC Firewall Rules
Ensure that logging is enabled for your Virtual Private Cloud (VPC) firewall rules.
Enable VPC Flow Logs for VPC Subnets
Ensure that VPC Flow Logs feature is enabled for all VPC network subnets.
Exclude Metadata from Firewall Logging
Ensure that logging metadata is not included within your VPC firewall log files.
Restrict Access to High Risk Ports
Ensure there are no VPC network firewall rules with high-risk ports opened to allow incoming traffic.
Unused Network Firewall Rules
Ensure that unused network firewall rules are disabled or removed from your Google Cloud account.
GCP Compute Engine
Approved Virtual Machine Image in Use
Ensure that all your virtual machine instances are launched from approved images only.
Check for Desired Machine Type(s)
Ensure that your virtual machine (VM) instances are of a given type (e.g. c2-standard-4).
Check for Instance-Associated Service Accounts with Full API Access
Ensure that VM instances are not associated with default service accounts that allow full access to all Google Cloud APIs.
Check for Instances Associated with Default Service Accounts
Ensure that your VM instances are not associated with the default GCP service account.
Check for Publicly Shared Disk Images
Ensure that your virtual machine disk images are not accessible to all GCP accounts.
Check for Virtual Machine Instances with Public IP Addresses
Ensure that Google Cloud VM instances are not using public IP addresses.
Compute Instances with Multiple Network Interfaces
Ensure that virtual machine (VM) instances are not using multiple network interfaces.
Configure Maintenance Behavior for VM Instances
Ensure that "On Host Maintenance" configuration setting is set to "Migrate" for all VM instances.
Configure load balancers for Managed Instance Groups
Ensure that Managed Instance Groups (MIGs) are associated with load balancers.
Configure multiple zones for Managed Instance Groups
Ensure that Managed Instance Groups are configured to run instances across multiple zones.
Detect GCP Compute Engine Configuration Changes
Compute Engine configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable Auto-Delete for VM Instance Persistent Disks
Ensure that the Auto-Delete feature is disabled for the disks attached to your VM instances.
Disable IP Forwarding for Virtual Machine Instances
Ensure that IP Forwarding is not enabled for your Google Cloud virtual machine (VM) instances.
Disable Interactive Serial Console Support
Ensure that interactive serial console support is not enabled for your Google Cloud instances.
Disable Preemptibility for VM Instances
Ensure that your production Google Cloud virtual machine instances are not preemptible.
Enable "Block Project-Wide SSH Keys" Security Feature
Ensure that project-wide SSH keys are not used to access your Google Cloud VM instances.
Enable "Shielded VM" Security Feature
Ensure that Shielded VM feature is enabled for your virtual machine (VM) instances.
Enable Automatic Restart for VM Instances
Ensure that automatic restart is enabled for your Google Cloud virtual machine (VM) instances.
Enable Confidential Computing for Virtual Machine Instances
Ensure that Confidential Computing is enabled for virtual machine (VM) instances.
Enable Deletion Protection for VM Instances
Ensure that deletion protection is enabled for your Google Cloud virtual machine (VM) instances.
Enable Instance Group Autohealing
Ensure that your Google Cloud instance groups are using autohealing to proactively replace failing instances.
Enable OS Login for GCP Projects
Ensure that the OS Login feature is enabled for your Google Cloud projects.
Enable VM Disk Encryption with Customer-Supplied Encryption Keys
Ensure that your virtual machine (VM) instance disks are encrypted with CSEKs.
Enable Virtual Machine Disk Encryption with Customer-Managed Keys
Ensure that your virtual machine (VM) instance disks are encrypted using Customer-Managed Keys (CMKs).
Enforce HTTPS Connections for App Engine Applications
Ensure that Google App Engine applications enforce HTTPS connections.
Instance templates should not assign a public IP address
Ensure that instance templates don't assign a public IP address to VM instances.
Persistent Disks Attached to Suspended Virtual Machines
Identify persistent disks attached to suspended VM instances (i.e. unused persistent disks).
Remove Old Persistent Disk Snapshots
Remove old virtual machine disk snapshots in order to optimize Google Cloud monthly costs.
Use OS Login with 2FA Authentication for VM Instances
Ensure that OS Login is configured with Two-Factor Authentication (2FA) for production VM instances.
GCP Dataproc Service
Enable Dataproc Cluster Encryption with Customer-Managed Keys
Ensure that your Dataproc clusters on Compute Engine are encrypted using Customer-Managed Keys (CMKs).
Publicly Accessible Dataproc Clusters
Ensure that your Dataproc cluster instances are not accessible from the Internet.
GCP Dialog Flow Service
Check for Data Security Settings
Ensure that Data Security Settings are configured for Dialogflow CX agents.
Check for Regional Data Residency and Location Controls
Ensure that Dialogflow CX agents are deployed in appropriate regions to meet compliance requirements.
Enable Cloud Logging for Dialogflow CX Agents
Enable and configure logging for Google Cloud Dialogflow CX virtual agents.
Use Customer-Managed Encryption Keys for Dialogflow CX Agents
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data for Dialogflow CX agents.
Use VPC Service Controls for Dialogflow
Ensure that VPC Service Controls perimeters are used to protect your Dialogflow resources from data exfiltration.
GCP Document AI Service
Check for Data Residency and Regional Controls
Ensure that Document AI processors are deployed in appropriate regions to meet compliance requirements.
Enable Access Approval for Document AI Resources
Ensure that Access Approval is enabled for all your Document AI resources.
Enable Data Access Audit Logs for Document AI
Ensure that Data Access audit logs are enabled for Document AI resources.
Implement Least Privilege Access for Document AI using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for Document AI access control.
Use Customer-Managed Encryption Keys for Document AI Processors
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data for Document AI processors.
Use VPC Service Controls for Document AI
Ensure that VPC Service Controls perimeters are used to protect your Document AI resources from data exfiltration.
GCP Eventarc Service
Configure Dead Lettering for Topics Associated with Eventarc Triggers
Ensure that Dead-Letter Topics (DLTs) are configured for Pub/Sub topics associated with Eventarc triggers.
Enable Data Access Audit Logs for Eventarc Resources
Ensure that Data Access audit logs are enabled for Google Cloud Eventarc resources.
Implement Least Privilege Access for Eventarc Resources
Ensure that IAM roles with administrative permissions are not used for Google Cloud Eventarc resources.
Implement Least Privilege for Eventarc Trigger Service Accounts
Ensure that Eventarc trigger service accounts are granted least privilege access.
Use Customer-Managed Encryption Keys for Eventarc Bus Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt Eventarc bus event messages.
Use Customer-Managed Encryption Keys for Eventarc Channel Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data related to Eventarc triggers.
Use Customer-Managed Encryption Keys for Eventarc GoogleApiSources
Use Customer-Managed Encryption Keys (CMEKs) to encrypt GoogleApiSource resources.
Use Customer-Managed Encryption Keys for Eventarc Pipeline Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data sent through Eventarc pipelines.
Use IAM Policy Conditions
Ensure Google Cloud Eventarc resources are protected with IAM policy conditions.
Use Labels for Resource Management
Ensure that all Google Cloud Eventarc triggers are labeled for better resource management.
Use VPC Service Controls for Eventarc
Ensure that VPC Service Controls perimeters are used to protect your Eventarc resources from data exfiltration.
GCP Filestore
Enable Deletion Protection for Filestore Instances
Ensure that Deletion Protection feature is enabled for Google Cloud Filestore instances.
Restrict Client Access by IP Address or IP Range
Restrict Filestore client access to trusted IP addresses or IP address ranges only.
Use Customer-Managed Encryption Keys for Filestore Data Encryption
Use Customer-Managed Encryption Keys (CMEKs) to encrypt data at rest within your Filestore instances.
Use On-Demand Backup and Restore for Google Cloud Filestore Instances
Ensure that on-demand backup and restore functionality is in use for Google Cloud Filestore instances.
Use VPC Service Controls for Filestore Instances
Ensure that VPC Service Controls perimeters are used to protect your Filestore instances from data exfiltration.
GCP Google Kubernetes Engine Service
Access Secrets Stored Outside GKE Clusters
Ensure that Google Kubernetes Engine (GKE) clusters can access Secret Manager secrets.
Automate Cluster Version Upgrades using Release Channels
Automate version management for your Google Kubernetes Engine (GKE) clusters using Release Channels.
Check for Alpha Clusters in Production
Ensure that Alpha GKE clusters are not used for production workloads.
Detect GCP GKE Configuration Changes
GKE configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable Client Certificates
Ensure that authentication using client certificates is disabled.
Disable Kubernetes Dashboard for GKE Clusters
Ensure that Kubernetes Dashboard is disabled for GKE clusters.
Disable Legacy Authorization
Disable legacy authorization for Google Kubernetes Engine (GKE) clusters.
Enable Auto-Repair for GKE Cluster Nodes
Ensure that your Google Kubernetes Engine (GKE) clusters are using auto-repairing nodes.
Enable Auto-Upgrade for GKE Cluster Nodes
Ensure that your Google Kubernetes Engine (GKE) cluster nodes are using automatic upgrades.
Enable Binary Authorization
Ensure that Binary Authorization is enabled for Google Kubernetes Engine (GKE) clusters.
Enable Cluster Backups
Enable and configure backups for Google Kubernetes Engine (GKE) clusters.
Enable Cost Allocation
Enable cost allocation for Google Kubernetes Engine (GKE) clusters.
Enable Critical Notifications
Enable critical notifications for Google Kubernetes Engine (GKE) clusters.
Enable Encryption for Application-Layer Secrets for GKE Clusters
Ensure that encryption of Kubernetes secrets using Customer-Managed Keys is enabled for GKE clusters.
Enable GKE Cluster Node Encryption with Customer-Managed Encryption Keys
Ensure that boot disk encryption with Customer-Managed Encryption Keys is enabled for GKE cluster nodes.
Enable GKE Metadata Server
Enable the GKE Metadata Server feature for Google Kubernetes Engine (GKE) clusters.
Enable Integrity Monitoring for Cluster Nodes
Ensure that Integrity Monitoring is enabled for your Google Kubernetes Engine (GKE) cluster nodes.
Enable Inter-Node Transparent Encryption
Ensure that inter-node transparent encryption is enabled for Google Kubernetes Engine (GKE) clusters.
Enable Intranode Visibility
Enable the Intranode Visibility feature for Google Kubernetes Engine (GKE) clusters.
Enable Private Nodes
Enable private nodes for Google Kubernetes Engine (GKE) clusters.
Enable Secure Boot for Cluster Nodes
Ensure that Secure Boot is enabled for your Google Kubernetes Engine (GKE) cluster nodes.
Enable VPC-Native Traffic Routing
Enable VPC-native traffic routing for Google Kubernetes Engine (GKE) clusters.
Enable Workload Identity Federation
Enable Workload Identity Federation for Google Kubernetes Engine (GKE) clusters.
Enable Workload Vulnerability Scanning
Enable workload vulnerability scanning for Google Kubernetes Engine (GKE) clusters.
Enable and Configure Cluster Logging
Enable and configure logging for Google Kubernetes Engine (GKE) clusters.
Enable and Configure Cluster Monitoring
Enable and configure Cloud Monitoring for Google Kubernetes Engine (GKE) clusters.
Enable and Configure Security Posture
Enable the Security Posture dashboard for Google Kubernetes Engine (GKE) clusters.
Prevent Default Service Account Usage
Ensure that GKE clusters are not configured to use the default service account.
Restrict Network Access
Ensure that Google Kubernetes Engine (GKE) cluster control plane is not exposed to the Internet.
Use Confidential GKE Cluster Nodes
Enable confidential GKE nodes for Google Kubernetes Engine (GKE) clusters.
Use Container-Optimized OS for GKE Clusters Nodes
Enable Container-Optimized OS for Google Kubernetes Engine (GKE) cluster nodes.
Use GKE Clusters with Private Endpoints Only
Ensure that Google Kubernetes Engine (GKE) clusters are using private endpoints only for control plane access.
Use Labels for Resource Management
Ensure that all Google Kubernetes Engine (GKE) clusters are labeled for better resource management.
Use Sandbox with gVisor for GKE Clusters Nodes
Enable GKE Sandbox with gVisor to protect from untrusted workloads.
Use Shielded GKE Cluster Nodes
Ensure that your GKE clusters nodes are shielded to protect against impersonation attacks.
GCP Network Connectivity
Enable Cloud NAT for Private Subnets
Ensure that Cloud NAT is enabled for VPC private subnets.
Enable Logging for Cloud NAT Gateways
Ensure that logging is enabled for Cloud NAT gateways.
Implement Least Privilege Access for Cloud NAT Management
Ensure that IAM roles with administrative permissions are not used for Cloud NAT management.
Limit NAT to Specific Subnets Only
Avoid misconfiguration by limiting Cloud NAT gateways to specific subnets only.
Use Private Google Access with Cloud NAT
Ensure that Private Google Access is enabled for the VPC subnets associated with your Cloud NAT gateways.
Use Reserved External IPs for Cloud NAT Gateways
sEnsure that your Cloud NAT gateways are using reserved external IPs.
GCP Resource Manager
Define Allowed External IPs for VM Instances
Ensure that "Define Allowed External IPs for VM Instances" policy is enforced at the GCP organization level.
Detect GCP Resource Manager Configuration Changes
Resource Manager configuration changes have been detected within your Google Cloud Platform (GCP) account.
Disable Automatic IAM Role Grants for Default Service Accounts
Ensure that "Disable Automatic IAM Grants for Default Service Accounts" policy is enforced.
Disable Guest Attributes of Compute Engine Metadata
Ensure that "Disable Guest Attributes of Compute Engine Metadata" policy is enabled at the GCP organization level.
Disable Serial Port Access Support at Organization Level
Ensure that "Disable VM serial port access" policy is enforced at the GCP organization level.
Disable Service Account Key Upload
Ensure that the key upload feature for Cloud IAM service accounts is disabled.
Disable User-Managed Key Creation for Service Accounts
Ensure that the user-managed key creation for Cloud IAM service accounts is disabled.
Disable Workload Identity at Cluster Creation
Ensure that "Disable Workload Identity Cluster Creation" policy is enabled for your GCP organizations.
Enforce Detailed Audit Logging Mode
Ensure that "Google Cloud Platform - Detailed Audit Logging Mode" policy is enabled for your GCP organizations.
Enforce Uniform Bucket-Level Access
Ensure that "Enforce uniform bucket-level access" organization policy is enabled at the Google Cloud Platform (GCP) organization level, and that the project inherits the parent's policy.
Prevent Service Account Creation for Google Cloud Organizations
Ensure that Cloud IAM service account creation is disabled at the organization level.
Require OS Login
Ensure that "Require OS Login" policy is enabled for your GCP organizations.
Restrict Allowed Google Cloud APIs and Services
Ensure that "Restrict allowed Google Cloud APIs and services" organization policy is enforced for your GCP organizations.
Restrict Authorized Networks on Cloud SQL instances
Ensure that "Restrict Authorized Networks on Cloud SQL instances" policy is enforced at GCP organization level.
Restrict Default Google-Managed Encryption for Cloud SQL Instances (Deprecated)
Ensure that "Restrict Default Google-Managed Encryption for Cloud SQL Instances" policy is enforced at the GCP organization level.
Restrict Load Balancer Creation Based on Load Balancer Types
Ensure that "Restrict Load Balancer Creation Based on Load Balancer Types" policy is enforced at the GCP organization level.
Restrict Public IP Access for Cloud SQL Instances at Organization Level
Ensure that "Restrict Public IP access on Cloud SQL instances" policy is enabled at the GCP organization level.
Restrict Shared VPC Subnetworks
Ensure that "Restrict Shared VPC Subnetworks" policy is enforced for your GCP organizations.
Restrict VPC Peering Usage
Ensure that "Restrict VPC Peering Usage" policy is enforced for your GCP organizations.
Restrict VPN Peer IPs
Ensure that "Restrict VPN Peer IPs" constraint policy is enabled for your GCP organizations.
Restrict Virtual Machine IP Forwarding
Ensure that "Restrict VM IP Forwarding" policy is enforced at the GCP organization level.
Restrict the Creation of Cloud Resources to Specific Locations
Ensure that "Google Cloud Platform - Resource Location Restriction" constraint policy is enforced for your GCP organizations.
Restricting the Use of Images
Ensure that "Define Trusted Image Projects" policy is enforced for your GCP organizations.
Skip Default VPC Network Creation
Ensure that the creation of the default VPC network is disabled at the GCP organization level.
GCP Secret Manager
Enable Data Access Audit Logs for Secret Manager
Ensure that Data Access audit logs are enabled for Secret Manager resources.
Enable Destruction Delay for Secret Versions
Ensure that a delayed destruction policy is configured for your Secret Manager secrets.
Enable Rotation Schedules for Secret Manager Secrets
Ensure that rotation schedules are configured for your Secret Manager secrets.
Implement Least Privilege Access for Secret Manager Secrets using Cloud IAM
Ensure that IAM roles with administrative permissions are not used for Secret Manager resource access control.
Use Customer-Managed Encryption Keys for Secret Manager Secret Encryption
Ensure that your Secret Manager secrets are encrypted with Customer-Managed Encryption Keys.
GCP VertexAI
Configure Private Service Connect Endpoints
Ensure that Private Service Connect endpoints are configured for your Vertex AI resources.
Default VPC Network In Use
Ensure that the default VPC network is not being used for your Vertex AI notebook instances.
Disable Root Access for Workbench Instances
Ensure root access is disabled for your Vertex AI notebook instances.
Enable Automatic Upgrades for Workbench Instances
Ensure that automatic upgrades are enabled for your Vertex AI notebook instances.
Enable Cloud Monitoring for Workbench Instances
Ensure that Cloud Monitoring feature is enabled for your Vertex AI notebook instances.
Enable Idle Shutdown for Workbench Instances
Ensure that the Idle Shutdown feature is enabled for your Vertex AI notebook instances.
Enable Integrity Monitoring for Workbench Instances
Ensure that the Integrity Monitoring feature is enabled for your Vertex AI notebook instances.
Enable Secure Boot for Workbench Instances
Ensure that Secure Boot is enabled for your Vertex AI notebook instances.
Enable Virtual Trusted Platform Module (vTPM) for Workbench Instances
Ensure that vTPM feature is enabled for your Vertex AI notebook instances.
Prevent Assigning External IPs to Workbench Instances
Ensure that external IP addresses are not assigned to Vertex AI notebook instances.
Use VPC Service Controls for Vertex AI
Ensure that VPC Service Controls perimeters are used to protect your Vertex AI resources from data exfiltration.
Vertex AI Dataset Encryption with Customer-Managed Encryption Keys
Ensure that Vertex AI datasets are encrypted using Customer-Managed Encryption Keys (CMEKs) (Not Scored).
Workbench Instance Encryption with Customer-Managed Encryption Keys
Ensure that Vertex AI notebook instances are encrypted using Customer-Managed Encryption Keys (CMEKs).
