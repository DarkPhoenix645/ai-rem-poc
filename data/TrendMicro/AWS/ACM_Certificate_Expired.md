# ACM Certificate Expired

## Overview
Knowledge Base
Amazon Web Services
AWS Certificate Manager
ACM Certificate Expired
Risk Level:
High (not acceptable risk)
Rule ID:
ACM-001
Ensure that all the expired Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificates managed by AWS Certificate Manager are removed in order to adhere to Amazon Security Best Practices. Certificate Manager is the AWS service that lets you easily provision, manage, and deploy SSL/TLS certificates for use with other Amazon services such as Elastic Load Balancing and CloudFront.
This rule can help you with the following compliance standards:
PCI
APRA
MAS
NIST4
For further details on compliance standards supported by Conformity, see
here
.
This rule can help you work with the
AWS Well-Architected Framework
.
This rule resolution is part of the Conformity
Security & Compliance tool for AWS
.
Security
Operational
excellence
Removing expired AWS ACM certificates eliminates the risk that an invalid SSL/TLS certificate will be deployed accidentally to another resource such as Elastic Load Balancing (ELB), action that can trigger front-end errors and damage the credibility of the web application/website behind the ELB.
Audit
To determine if there are any expired SSL/TLS certificates managed by AWS Certificate Manager, perform the following :
Using AWS Console
01
Sign in to the AWS Management Console.
02
Navigate to AWS ACM dashboard at
https://console.aws.amazon.com/acm/
.
03
Click on the
Show/Hide Columns
button from the dashboard top-right menu:
04
Within the
Shown Columns
dialog box, under
Properties
, select
Status
checkbox then click X to return to the ACM dashboard.
05
Select the SSL/TLS certificate that you want to examine and verify its current status value available under the
Status
column. If the current status is set to
Expired
, i.e.
the selected certificate is not valid anymore and can be safely removed from your AWS account.
06
Repeat step no. 5 to check other SSL/TLS certificates managed by AWS ACM in the current region.
07
Change the AWS region from the navigation bar and repeat the audit process for other regions.
Using AWS CLI
01
Run
list-certificates
command (OSX/Linux/UNIX) using built-in query filters to list all the expired AWS ACM certificates available in the selected region:
aws acm list-certificates
 --region us-east-1
 --certificate-statuses EXPIRED
02
The command output should return the metadata (domain name and ARN) for all expired SSL/TLS certificates managed by Amazon Certificate Manager within US East (N. Virginia) region or an empty array, i.e.
[ ]
, if there are no expired certificates within the selected region:
{
 "CertificateSummaryList": [
 {
 "CertificateArn": "arn:aws:acm:us-east-1:123456789012:
 certificate/c19aa6f6-d6bc-4747-9274-89daa8001231",
 "DomainName": "cloudconformity.com"
 },
 {
 "CertificateArn": "arn:aws:acm:us-east-1:123456789012:
 certificate/87654321-4321-4321-4321-210987654321",
 "DomainName": "cloudrealisation.com"
 }
 ]
}
If the command output returns one or more values for the
CertificateSummaryList
array, there are expired SSL/TLS within the selected AWS region.
03
Repeat step no. 1 and 2 to verify other SSL/TLS certificates managed by AWS ACM service within the current region.
04
Change the AWS region by updating the
--region
command parameter value and repeat the entire audit process for other regions.
Remediation / Resolution
To delete any expired SSL/TLS certificates managed by AWS Certificate Manager, perform the following:
Using AWS Console
01
Sign in to the AWS Management Console.
02
Navigate to AWS ACM dashboard at
https://console.aws.amazon.com/acm/
.
03
Select the SSL/TLS certificate that you want to remove (see Audit section part I to identify the right certificate).
04
Click the
Actions
button from the dashboard top menu and select
Delete
option from the dropdown menu.
05
Inside the
Delete certificate
dialog box, review the certificate details (domain name and ID) then click
Delete
to confirm the action.
06
Repeat steps no. 3 – 5 to remove other expired AWS ACM certificates available within the selected region.
07
Change the AWS region from the navigation bar and repeat the process for other regions.
Using AWS CLI
01
Run
delete-certificate
command (OSX/Linux/UNIX) using the ARN of the resource as identifier (see Audit section part II to get the right ARN) to remove the selected expired AWS ACM certificate and the associated private key from your AWS account (the command does not return an output):
aws acm delete-certificate
 --region us-east-1
 --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/c19aa6f6-d6bc-4747-9274-89daa8001231
02
Repeat step no. 1 to remove other expired AWS Certificate Manager certificates available in the selected region.
03
Change the AWS region by updating the
--region
command parameter value and repeat the entire process for other regions.
References
AWS Documentation
AWS Certificate Manager FAQs
What Is AWS Certificate Manager?
Concepts
ACM Certificate Characteristics
AWS Command Line Interface (CLI) Documentation
acm
list-certificates
delete-certificate
Publication date May 2, 2017
Related ACM rules
AWS ACM Certificates Validity (Security, operational-excellence)
AWS ACM Certificates with Wildcard Domain Names (Security, operational-excellence)
AWS ACM Certificates Renewal (7 days before expiration) (Security)
AWS ACM Certificates Renewal (45 days before expiration) (Security)

## Key Principles
Follow security best practices and compliance requirements.

## Compliance Frameworks
AWS, TrendMicro, NIST, PCI-DSS

## Compliance Controls
Standard security controls apply

## Focus Areas
compliance_violations, resource_wildcards

## Analysis
Regular security assessments help identify potential risks and compliance gaps.

## Certification
Compliant with industry security standards and best practices.

## Source
https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/ACM/expired-certificate.html

## Full Content
Knowledge Base
Amazon Web Services
AWS Certificate Manager
ACM Certificate Expired
Risk Level:
High (not acceptable risk)
Rule ID:
ACM-001
Ensure that all the expired Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificates managed by AWS Certificate Manager are removed in order to adhere to Amazon Security Best Practices. Certificate Manager is the AWS service that lets you easily provision, manage, and deploy SSL/TLS certificates for use with other Amazon services such as Elastic Load Balancing and CloudFront.
This rule can help you with the following compliance standards:
PCI
APRA
MAS
NIST4
For further details on compliance standards supported by Conformity, see
here
.
This rule can help you work with the
AWS Well-Architected Framework
.
This rule resolution is part of the Conformity
Security & Compliance tool for AWS
.
Security
Operational
excellence
Removing expired AWS ACM certificates eliminates the risk that an invalid SSL/TLS certificate will be deployed accidentally to another resource such as Elastic Load Balancing (ELB), action that can trigger front-end errors and damage the credibility of the web application/website behind the ELB.
Audit
To determine if there are any expired SSL/TLS certificates managed by AWS Certificate Manager, perform the following :
Using AWS Console
01
Sign in to the AWS Management Console.
02
Navigate to AWS ACM dashboard at
https://console.aws.amazon.com/acm/
.
03
Click on the
Show/Hide Columns
button from the dashboard top-right menu:
04
Within the
Shown Columns
dialog box, under
Properties
, select
Status
checkbox then click X to return to the ACM dashboard.
05
Select the SSL/TLS certificate that you want to examine and verify its current status value available under the
Status
column. If the current status is set to
Expired
, i.e.
the selected certificate is not valid anymore and can be safely removed from your AWS account.
06
Repeat step no. 5 to check other SSL/TLS certificates managed by AWS ACM in the current region.
07
Change the AWS region from the navigation bar and repeat the audit process for other regions.
Using AWS CLI
01
Run
list-certificates
command (OSX/Linux/UNIX) using built-in query filters to list all the expired AWS ACM certificates available in the selected region:
aws acm list-certificates
 --region us-east-1
 --certificate-statuses EXPIRED
02
The command output should return the metadata (domain name and ARN) for all expired SSL/TLS certificates managed by Amazon Certificate Manager within US East (N. Virginia) region or an empty array, i.e.
[ ]
, if there are no expired certificates within the selected region:
{
 "CertificateSummaryList": [
 {
 "CertificateArn": "arn:aws:acm:us-east-1:123456789012:
 certificate/c19aa6f6-d6bc-4747-9274-89daa8001231",
 "DomainName": "cloudconformity.com"
 },
 {
 "CertificateArn": "arn:aws:acm:us-east-1:123456789012:
 certificate/87654321-4321-4321-4321-210987654321",
 "DomainName": "cloudrealisation.com"
 }
 ]
}
If the command output returns one or more values for the
CertificateSummaryList
array, there are expired SSL/TLS within the selected AWS region.
03
Repeat step no. 1 and 2 to verify other SSL/TLS certificates managed by AWS ACM service within the current region.
04
Change the AWS region by updating the
--region
command parameter value and repeat the entire audit process for other regions.
Remediation / Resolution
To delete any expired SSL/TLS certificates managed by AWS Certificate Manager, perform the following:
Using AWS Console
01
Sign in to the AWS Management Console.
02
Navigate to AWS ACM dashboard at
https://console.aws.amazon.com/acm/
.
03
Select the SSL/TLS certificate that you want to remove (see Audit section part I to identify the right certificate).
04
Click the
Actions
button from the dashboard top menu and select
Delete
option from the dropdown menu.
05
Inside the
Delete certificate
dialog box, review the certificate details (domain name and ID) then click
Delete
to confirm the action.
06
Repeat steps no. 3 – 5 to remove other expired AWS ACM certificates available within the selected region.
07
Change the AWS region from the navigation bar and repeat the process for other regions.
Using AWS CLI
01
Run
delete-certificate
command (OSX/Linux/UNIX) using the ARN of the resource as identifier (see Audit section part II to get the right ARN) to remove the selected expired AWS ACM certificate and the associated private key from your AWS account (the command does not return an output):
aws acm delete-certificate
 --region us-east-1
 --certificate-arn arn:aws:acm:us-east-1:123456789012:certificate/c19aa6f6-d6bc-4747-9274-89daa8001231
02
Repeat step no. 1 to remove other expired AWS Certificate Manager certificates available in the selected region.
03
Change the AWS region by updating the
--region
command parameter value and repeat the entire process for other regions.
References
AWS Documentation
AWS Certificate Manager FAQs
What Is AWS Certificate Manager?
Concepts
ACM Certificate Characteristics
AWS Command Line Interface (CLI) Documentation
acm
list-certificates
delete-certificate
Publication date May 2, 2017
Related ACM rules
AWS ACM Certificates Validity (Security, operational-excellence)
AWS ACM Certificates with Wildcard Domain Names (Security, operational-excellence)
AWS ACM Certificates Renewal (7 days before expiration) (Security)
AWS ACM Certificates Renewal (45 days before expiration) (Security)
