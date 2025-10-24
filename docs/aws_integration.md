# AWS Cross-Account IAM Scanner Setup

## Quick Setup

### 1. Automated Setup (Recommended)

Use the provided setup script for automated configuration:

```bash
# Generate a random external ID and set up integration
./scripts/setup-aws-integration.sh -s 123456789012 -g

# Or use a custom external ID
./scripts/setup-aws-integration.sh -s 123456789012 -e my-custom-external-id
```

### 2. Manual Setup

If you prefer manual setup, follow these steps:

#### Step 1: Create IAM Policy

```bash
aws iam create-policy \
  --policy-name StackGuardIAMScannerPolicy \
  --policy-document file://aws-policies/iam-scanner-policy.json
```

#### Step 2: Create Trust Policy

Create `trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_SCANNER_ACCOUNT_ID:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "UNIQUE_EXTERNAL_ID_FOR_YOUR_APP"
        }
      }
    }
  ]
}
```

#### Step 3: Create IAM Role

```bash
aws iam create-role \
  --role-name StackGuardScannerRole \
  --assume-role-policy-document file://trust-policy.json
```

#### Step 4: Attach Policy to Role

```bash
aws iam attach-role-policy \
  --role-name StackGuardScannerRole \
  --policy-arn "arn:aws:iam::TARGET_ACCOUNT_ID:policy/StackGuardIAMScannerPolicy"
```

## IAM Policy Details

The scanner policy grants **read-only access** to IAM resources:

### Permissions Granted

| Resource Type | Actions                                                                                                         | Purpose                         |
| ------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| **Roles**     | `GetRole`, `ListRoleTags`, `ListAttachedRolePolicies`, `ListRolePolicies`, `GetRolePolicy`                      | Read role details and policies  |
| **Users**     | `GetUser`, `ListUserTags`, `ListAttachedUserPolicies`, `ListUserPolicies`, `GetUserPolicy`, `ListGroupsForUser` | Read user details and policies  |
| **Groups**    | `GetGroup`, `ListAttachedGroupPolicies`, `ListGroupPolicies`, `GetGroupPolicy`                                  | Read group details and policies |
| **Policies**  | `GetPolicy`, `GetPolicyVersion`, `ListPolicyVersions`                                                           | Read managed policy documents   |
| **Lists**     | `ListRoles`, `ListUsers`, `ListGroups`, `ListPolicies`                                                          | Enumerate IAM entities          |

## Application Configuration

### Environment Variables

Configure these variables in your scanner service:

```bash
# Default configuration (can be overridden per tenant)
DEFAULT_AWS_ROLE_ARN=arn:aws:iam::123456789012:role/StackGuardScannerRole
DEFAULT_AWS_ACCOUNT_ID=123456789012
# Required for role assumption
AWS_EXTERNAL_ID=stackguard-scanner-a1b2c3d4e5

```

## Verification

### Test Role Assumption

```bash
aws sts assume-role \
  --role-arn "arn:aws:iam::TARGET_ACCOUNT_ID:role/StackGuardScannerRole" \
  --role-session-name "VerificationTest" \
  --external-id "YOUR_EXTERNAL_ID"
```

### Test Permissions

```bash
# Export temporary credentials
export AWS_ACCESS_KEY_ID="AccessKeyId_from_output"
export AWS_SECRET_ACCESS_KEY="SecretAccessKey_from_output"
export AWS_SESSION_TOKEN="SessionToken_from_output"

# Test read access (should succeed)
aws iam list-roles --max-items 2

# Test write access (should fail with AccessDenied)
aws iam create-role --role-name ThisShouldFail
```

### Debug Commands

```bash
# Check current AWS identity
aws sts get-caller-identity

# List policies
aws iam list-policies --query 'Policies[?PolicyName==`StackGuardIAMScannerPolicy`]'

# Get role details
aws iam get-role --role-name StackGuardScannerRole

# Test role assumption with verbose output
aws sts assume-role \
  --role-arn "arn:aws:iam::123456789012:role/StackGuardScannerRole" \
  --role-session-name "DebugTest" \
  --external-id "your-external-id" \
  --debug
```
