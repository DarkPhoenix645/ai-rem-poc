# Manual AWS Setup Guide

If the automated setup script fails due to insufficient permissions, follow these manual steps:

## Prerequisites

- AWS CLI installed and configured
- IAM permissions to create policies and roles
- Access to the target AWS account

## Option 1: Use Automated Script with Credentials

The easiest way is to use the automated script with explicit credentials:

```bash
./scripts/setup-aws-integration.sh \
  -s 917394547150 \
  -u arn:aws:iam::917394547150:user/stackguard-ai-rem-poc \
  -e stackguard-test \
  -a YOUR_ACCESS_KEY_ID \
  -k YOUR_SECRET_ACCESS_KEY
```

## Option 2: Manual Setup Steps

### Step 1: Create IAM Policy

```bash
aws iam create-policy \
  --policy-name StackGuardIAMScannerPolicy \
  --policy-document file://aws-policies/iam-scanner-policy.json
```

**Note the Policy ARN from the output** - you'll need it for Step 4.

### Step 2: Create Trust Policy

Create a file called `trust-policy.json`:

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
          "sts:ExternalId": "YOUR_EXTERNAL_ID"
        }
      }
    }
  ]
}
```

Replace:

- `YOUR_SCANNER_ACCOUNT_ID` with your scanner account ID
- `YOUR_EXTERNAL_ID` with your chosen external ID

### Step 3: Create IAM Role

```bash
aws iam create-role \
  --role-name StackGuardScannerRole \
  --assume-role-policy-document file://trust-policy.json
```

### Step 4: Attach Policy to Role

```bash
aws iam attach-role-policy \
  --role-name StackGuardScannerRole \
  --policy-arn "arn:aws:iam::TARGET_ACCOUNT_ID:policy/StackGuardIAMScannerPolicy"
```

Replace `TARGET_ACCOUNT_ID` with your target account ID.

### Step 5: Test Role Assumption

```bash
aws sts assume-role \
  --role-arn "arn:aws:iam::TARGET_ACCOUNT_ID:role/StackGuardScannerRole" \
  --role-session-name "TestSession" \
  --external-id "YOUR_EXTERNAL_ID"
```

### Step 6: Configure Environment Variables

Add these to your `.env` file:

```bash
AWS_EXTERNAL_ID=YOUR_EXTERNAL_ID
DEFAULT_AWS_ROLE_ARN=arn:aws:iam::TARGET_ACCOUNT_ID:role/StackGuardScannerRole
DEFAULT_AWS_ACCOUNT_ID=TARGET_ACCOUNT_ID
```

## Verification

Run the test script to verify everything works:

```bash
python scripts/test-aws-integration.py
```

## Troubleshooting

### Access Denied Errors

- Ensure your AWS user has the required IAM permissions
- Check that the policy ARN is correct
- Verify the trust policy JSON is valid

### Policy Not Found

- Make sure the policy was created successfully
- Check the policy ARN format
- Ensure you're using the correct account ID

### Role Assumption Failed

- Verify the ExternalId matches exactly
- Check that the scanner account ID is correct
- Ensure the trust policy allows the correct principal
