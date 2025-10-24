# AWS ACM Certificates Renewal (30 days before expiration)

## Overview
Knowledge Base
Amazon Web Services
AWS Certificate Manager
AWS ACM Certificates Renewal (30 days before expiration)
Risk Level:
Medium (should be achieved)
Rule ID:
ACM-003
Ensure that your SSL/TLS certificates managed by AWS ACM are renewed 30 days before their validity period ends. Certificate Manager is the AWS service that lets you easily provision, manage, and deploy SSL/TLS certificates for use with other AWS resources such as Elastic Load Balancers, CloudFront distributions or APIs on Amazon API Gateway.
This rule can help you with the following compliance standards:
PCI
APRA
MAS
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
When Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificates are not renewed prior to their expiration date, they become invalid and the communication between the client and the AWS resource that implements the certificates (e.g. Cloudfront distribution) is no longer secure.
Note: AWS Certificate Manager automatically renews certificates issued by the service that are used with other AWS resources. However, the ACM service does not renew automatically certificates that are not in use (i.e. not associated anymore with other AWS resources) so the renewal process must be done manually before these certificates become invalid. This conformity rules explains how to implement manually the renewal process 30 days before expiration.
Audit
To determine if there are any AWS ACM certificates that are expiring in 30 days, available in you AWS account, perform the following:
Using AWS Console
01
Sign in to the AWS Management Console.
02
Navigate to AWS ACM dashboard at
https://console.aws.amazon.com/acm/
.
03
Select the SSL/TLS certificate that you want to examine and click on the
Show/Hide Details
button:
to expand the panel with the certificate details.
04
Inside the
Details
section, verify the certificate expiration information (i.e. number of days remaining) displayed as value for the
Expires in
attribute:
If the
Expires in
attribute value is set to
30 days
, the selected SSL/TLS certificate is expiring in 30 days and should be renewed soon (see Remediation/Resolution section for the renewal process).
05
Repeat step no. 3 and 4 to check other SSL/TLS certificates that are about to expire, managed by AWS ACM within the current region.
06
Change the AWS region from the navigation bar and repeat the audit process for other regions.
Using AWS CLI
01
Run
list-certificates
command (OSX/Linux/UNIX) using built-in query filters to list all issued SSL/TLS certificates managed by AWS ACM service, available in the selected region:
aws acm list-certificates
 --region us-east-1
 --certificate-statuses ISSUED
02
The command output should return the metadata (domain name and ARN) for all issued (validated) AWS ACM certificates currently available in the US East (N. Virginia) region:
{

## Key Principles
Follow security best practices and compliance requirements.

## Compliance Frameworks
AWS, TrendMicro, PCI-DSS

## Compliance Controls
Standard security controls apply

## Focus Areas
compliance_violations, resource_wildcards

## Analysis
Regular security assessments help identify potential risks and compliance gaps.

## Certification
Compliant with industry security standards and best practices.

## Source
https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/ACM/certificate-expires-in-30-days.html

## Full Content
Knowledge Base
Amazon Web Services
AWS Certificate Manager
AWS ACM Certificates Renewal (30 days before expiration)
Risk Level:
Medium (should be achieved)
Rule ID:
ACM-003
Ensure that your SSL/TLS certificates managed by AWS ACM are renewed 30 days before their validity period ends. Certificate Manager is the AWS service that lets you easily provision, manage, and deploy SSL/TLS certificates for use with other AWS resources such as Elastic Load Balancers, CloudFront distributions or APIs on Amazon API Gateway.
This rule can help you with the following compliance standards:
PCI
APRA
MAS
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
When Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificates are not renewed prior to their expiration date, they become invalid and the communication between the client and the AWS resource that implements the certificates (e.g. Cloudfront distribution) is no longer secure.
Note: AWS Certificate Manager automatically renews certificates issued by the service that are used with other AWS resources. However, the ACM service does not renew automatically certificates that are not in use (i.e. not associated anymore with other AWS resources) so the renewal process must be done manually before these certificates become invalid. This conformity rules explains how to implement manually the renewal process 30 days before expiration.
Audit
To determine if there are any AWS ACM certificates that are expiring in 30 days, available in you AWS account, perform the following:
Using AWS Console
01
Sign in to the AWS Management Console.
02
Navigate to AWS ACM dashboard at
https://console.aws.amazon.com/acm/
.
03
Select the SSL/TLS certificate that you want to examine and click on the
Show/Hide Details
button:
to expand the panel with the certificate details.
04
Inside the
Details
section, verify the certificate expiration information (i.e. number of days remaining) displayed as value for the
Expires in
attribute:
If the
Expires in
attribute value is set to
30 days
, the selected SSL/TLS certificate is expiring in 30 days and should be renewed soon (see Remediation/Resolution section for the renewal process).
05
Repeat step no. 3 and 4 to check other SSL/TLS certificates that are about to expire, managed by AWS ACM within the current region.
06
Change the AWS region from the navigation bar and repeat the audit process for other regions.
Using AWS CLI
01
Run
list-certificates
command (OSX/Linux/UNIX) using built-in query filters to list all issued SSL/TLS certificates managed by AWS ACM service, available in the selected region:
aws acm list-certificates
 --region us-east-1
 --certificate-statuses ISSUED
02
The command output should return the metadata (domain name and ARN) for all issued (validated) AWS ACM certificates currently available in the US East (N. Virginia) region:
{

 "CertificateSummaryList": [
 {
 "CertificateArn": "arn:aws:acm:us-east-1:1234567890:
 certificate/F1c6999d-b027-4449-9694-55ce71b3655C",
 "DomainName": "cloudconformity.com"
 }
 ]
}
03
Run
describe-certificate
command (OSX/Linux/UNIX) using the ARN of the certificate returned at the previous step as identifier and custom query filters to return the timestamp (UNIX format) of the expiration date for the selected certificate:
aws acm describe-certificate
 --region us-east-1
 --certificate-arn arn:aws:acm:us-east-1:1234567890:certificate/F1c6999d-b027-4449-9694-55ce71b3655C
 --query 'Certificate.NotAfter'
04
The command output should return the timestamp of the expiration date for the selected certificate:
1490140799
05
Now run
date
command (Linux/UNIX) using the timestamp value returned at the previous step to convert it to a human readable date value:
date -d @1490140799
06
The command output should return the requested date in human readable format (UTC time):
Tue Mar 21 23:59:59 UTC 2017
If the date returned is 30 days from the checkup date, the selected SSL/TLS certificate is about to expire and should be renewed soon (see Remediation/Resolution section for the renewal process).
07
Repeat steps no. 3 – 6 to check other SSL/TLS certificates that are about to expire soon, managed by AWS ACM within the current region.
08
Change the AWS region by updating the
--region
command parameter value and repeat the entire audit process for other regions.
Remediation / Resolution
To renew any SSL/TLS certificates that are about to expire using AWS Certificate Manager service, perform the following:
Note: The renewal process outlined below can be implemented only for imported SSL/TLS certificate currently managed by AWS ACM service.
Using AWS Console
01
Sign in to the AWS Management Console.
02
Navigate to AWS ACM dashboard at
https://console.aws.amazon.com/acm/
.
03
Select the SSL/TLS certificate that is expiring in 30 days (see Audit section part I to identify the right certificate).
04
Click the
Actions
button from the dashboard top menu and select Reimport certificate option from the dropdown menu.
05
On the
Import a certificate
page, perform the following actions:
For
Certificate body*
, paste the PEM-encoded certificate to import, purchased from your SSL certificate provider.
For
Certificate private key*
, paste the PEM-encoded, unencrypted private key that matches the SSL/TLS certificate public key.
(Optional) For
Certificate chain
, paste the PEM-encoded certificate chain delivered with the certificate body specified at step a.
Click
Review and import
button to continue the process.
06
On the
Review and import
page, review the imported certificate details then click
Import
to confirm the action and complete the renewal process.
07
Repeat steps no. 3 – 6 to renew other certificates that are about to expire soon, managed by AWS ACM in the selected region.
08
Change the AWS region from the navigation bar and repeat the process for other regions.
Using AWS CLI
01
Run
import-certificate
command (OSX/Linux/UNIX) using the ARN of the SSL/TLS certificate that you want to renew as identifier (see Audit section part II to get the right resource ARN) to import and replace (renew) the selected AWS ACM certificate. The certificate to import (
--certificate
parameter value), the private key (
--private-key
value) and the certificate chain (--certificate-chain value), must be PEM-encoded:
aws acm import-certificate
 --region us-east-1
 --certificate-arn arn:aws:acm:us-east-1:1234567890:certificate/F1c6999d-b027-4449-9694-55ce71b3655C
 --certificate NDDFdTCuBF2gAw...
 --private-key NDDEvgIBADaNCk...
 --certificate-chain NDDETeCAzWAwIy...
02
The command output should return the ARN of the renewed SSL/TLS certificate:
{
 "CertificateArn": "arn:aws:acm:us-east-1:1234567890:
 certificate/F1c6999d-b027-4449-9694-55ce71b3655C"
}
03
Repeat step no. 1 and 2 to renew other certificates that are about to expire soon, managed by AWS ACM service in the selected region.
04
Change the AWS region by updating the
--region
command parameter value and repeat the entire process for other regions.
References
AWS Documentation
What Is AWS Certificate Manager?
Concepts
ACM Certificate Characteristics
AWS Certificate Manager FAQs
Troubleshooting
Importing Certificates into AWS Certificate Manager
AWS Command Line Interface (CLI) Documentation
acm
list-certificates
describe-certificate
import-certificate
Publication date May 2, 2017
Related ACM rules
AWS ACM Certificates Renewal (7 days before expiration) (Security)
AWS ACM Certificates Renewal (45 days before expiration) (Security)
AWS ACM Certificates Renewal (30 days before expiration) (Security)
AWS ACM Certificates with Wildcard Domain Names (Security, operational-excellence)
