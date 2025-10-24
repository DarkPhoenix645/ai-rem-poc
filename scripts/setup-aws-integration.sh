#!/bin/bash
# AWS Cross-Account IAM Scanner Setup Script
# This script helps set up the cross-account IAM role for secure scanning

set -e

# Simple output functions
print_status() {
    echo "[INFO] $1"
}

print_success() {
    echo "[SUCCESS] $1"
}

print_warning() {
    echo "[WARNING] $1"
}

print_error() {
    echo "[ERROR] $1"
}

# Function to check if AWS CLI is installed and configured
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    print_success "AWS CLI is installed"
}

# Function to get current AWS account ID
get_current_account_id() {
    aws sts get-caller-identity --query Account --output text
}

# Function to get current AWS user ARN
get_current_user_arn() {
    aws sts get-caller-identity --query Arn --output text
}

# Function to configure AWS credentials
configure_aws_credentials() {
    local access_key_id="$1"
    local secret_access_key="$2"
    local session_token="$3"
    
    export AWS_ACCESS_KEY_ID="$access_key_id"
    export AWS_SECRET_ACCESS_KEY="$secret_access_key"
    
    if [[ -n "$session_token" ]]; then
        export AWS_SESSION_TOKEN="$session_token"
    fi
    
    # Test the credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "Invalid AWS credentials provided"
        exit 1
    fi
    
    print_success "AWS credentials configured successfully"
}

# Function to create the IAM policy
create_iam_policy() {
    local policy_name="StackGuardIAMScannerPolicy"
    local policy_file="aws-policies/iam-scanner-policy.json"
    
    print_status "Creating IAM policy: $policy_name"
    
    # Check if policy file exists
    if [[ ! -f "$policy_file" ]]; then
        print_error "Policy file not found: $policy_file"
        exit 1
    fi
    
    # Check if policy already exists
    if aws iam get-policy --policy-arn "arn:aws:iam::$(get_current_account_id):policy/$policy_name" &> /dev/null; then
        print_warning "Policy $policy_name already exists"
        echo "arn:aws:iam::$(get_current_account_id):policy/$policy_name"
        return
    fi
    
    # Create the policy
    local policy_arn=$(aws iam create-policy \
        --policy-name "$policy_name" \
        --policy-document "file://$policy_file" \
        --query 'Policy.Arn' \
        --output text)
    
    print_success "Created IAM policy: $policy_arn"
    echo "$policy_arn"
}

# Function to create trust policy
create_trust_policy() {
    local scanner_account_id="$1"
    local external_id="$2"
    local scanner_user_arn="$3"
    
    print_status "Creating trust policy for scanner user: $scanner_user_arn"
    
    # Create temporary trust policy file
    local trust_policy_file="/tmp/trust-policy-$(date +%s).json"
    
    cat > "$trust_policy_file" << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "${scanner_user_arn}"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "sts:ExternalId": "${external_id}"
                }
            }
        }
    ]
}
EOF
    
    echo "$trust_policy_file"
}

# Function to create the IAM role
create_iam_role() {
    local role_name="StackGuardScannerRole"
    local trust_policy_file="$1"
    
    print_status "Creating IAM role: $role_name"
    
    # Check if trust policy file exists
    if [[ ! -f "$trust_policy_file" ]]; then
        print_error "Trust policy file not found: $trust_policy_file"
        exit 1
    fi
    
    # Check if role already exists
    if aws iam get-role --role-name "$role_name" &> /dev/null; then
        print_warning "Role $role_name already exists"
        echo "arn:aws:iam::$(get_current_account_id):role/$role_name"
        return
    fi
    
    # Create the role
    local role_arn=$(aws iam create-role \
        --role-name "$role_name" \
        --assume-role-policy-document "file://$trust_policy_file" \
        --query 'Role.Arn' \
        --output text)
    
    print_success "Created IAM role: $role_arn"
    echo "$role_arn"
}

# Function to attach policy to role
attach_policy_to_role() {
    local role_name="StackGuardScannerRole"
    local policy_arn="$1"
    
    print_status "Attaching policy to role: $role_name"
    
    aws iam attach-role-policy \
        --role-name "$role_name" \
        --policy-arn "$policy_arn"
    
    print_success "Attached policy to role"
}

# Function to test role assumption
test_role_assumption() {
    local role_arn="$1"
    local external_id="$2"
    
    print_status "Testing role assumption..."
    
    # Test role assumption
    local result=$(aws sts assume-role \
        --role-arn "$role_arn" \
        --role-session-name "SetupTest" \
        --external-id "$external_id" \
        --query 'Credentials.AccessKeyId' \
        --output text 2>&1)
    
    if [[ $result == AKIA* ]]; then
        print_success "Role assumption test passed"
        return 0
    else
        print_error "Role assumption test failed: $result"
        return 1
    fi
}

# Function to generate random external ID
generate_external_id() {
    # Generate a random external ID
    local external_id="stackguard-scanner-$(openssl rand -hex 8)"
    echo "$external_id"
}

# Main setup function
setup_aws_integration() {
    local scanner_account_id="$1"
    local external_id="$2"
    local scanner_user_arn="$3"
    
    print_status "Setting up AWS cross-account IAM integration"
    print_status "Target account ID: $(get_current_account_id)"
    print_status "Current AWS user (creating resources): $(get_current_user_arn)"
    print_status "Scanner user ARN (will assume role): $scanner_user_arn"
    print_status "External ID: $external_id"
    
    # Step 1: Create IAM policy
    local policy_arn
    policy_arn=$(create_iam_policy)
    
    # Step 2: Create trust policy
    local trust_policy_file
    trust_policy_file=$(create_trust_policy "$scanner_account_id" "$external_id" "$scanner_user_arn")
    
    # Step 3: Create IAM role
    local role_arn
    role_arn=$(create_iam_role "$trust_policy_file")
    
    # Step 4: Attach policy to role
    attach_policy_to_role "$policy_arn"
    
    # Step 5: Test role assumption
    if test_role_assumption "$role_arn" "$external_id"; then
        print_success "AWS integration setup completed successfully!"
        echo ""
        echo "Configuration Summary:"
        echo "====================="
        echo "Role ARN: $role_arn"
        echo "External ID: $external_id"
        echo "Policy ARN: $policy_arn"
        echo ""
        echo "Environment Variables for your application:"
        echo "==========================================="
        echo "AWS_EXTERNAL_ID=$external_id"
        echo "DEFAULT_AWS_ROLE_ARN=$role_arn"
        echo "DEFAULT_AWS_ACCOUNT_ID=$(get_current_account_id)"
    else
        print_error "Setup completed but role assumption test failed"
        print_error "Please check your configuration and try again"
        exit 1
    fi
    
    # Cleanup
    rm -f "$trust_policy_file"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --scanner-account-id ACCOUNT_ID    AWS account ID where scanner runs"
    echo "  -u, --scanner-user-arn USER_ARN       ARN of the scanner user/role"
    echo "  -e, --external-id EXTERNAL_ID          External ID for role assumption"
    echo "  -a, --access-key-id ACCESS_KEY_ID      AWS Access Key ID"
    echo "  -k, --secret-access-key SECRET_KEY    AWS Secret Access Key"
    echo "  -t, --session-token SESSION_TOKEN      AWS Session Token (optional)"
    echo "  -g, --generate-external-id             Generate a random external ID"
    echo "  -h, --help                            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -s 123456789012 -u arn:aws:iam::123456789012:user/myuser -e my-unique-id -a AKIA... -k secret..."
    echo "  $0 -s 123456789012 -u arn:aws:iam::123456789012:user/myuser -g -a AKIA... -k secret..."
    echo ""
    echo "This script sets up the cross-account IAM role for secure scanning."
    echo "It creates the necessary IAM policy, role, and trust relationship."
}

# Parse command line arguments
SCANNER_ACCOUNT_ID=""
SCANNER_USER_ARN=""
EXTERNAL_ID=""
AWS_ACCESS_KEY_ID=""
AWS_SECRET_ACCESS_KEY=""
AWS_SESSION_TOKEN=""
GENERATE_EXTERNAL_ID=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--scanner-account-id)
            SCANNER_ACCOUNT_ID="$2"
            shift 2
            ;;
        -u|--scanner-user-arn)
            SCANNER_USER_ARN="$2"
            shift 2
            ;;
        -e|--external-id)
            EXTERNAL_ID="$2"
            shift 2
            ;;
        -a|--access-key-id)
            AWS_ACCESS_KEY_ID="$2"
            shift 2
            ;;
        -k|--secret-access-key)
            AWS_SECRET_ACCESS_KEY="$2"
            shift 2
            ;;
        -t|--session-token)
            AWS_SESSION_TOKEN="$2"
            shift 2
            ;;
        -g|--generate-external-id)
            GENERATE_EXTERNAL_ID=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [[ -z "$SCANNER_ACCOUNT_ID" ]]; then
    print_error "Scanner account ID is required"
    show_usage
    exit 1
fi

if [[ -z "$SCANNER_USER_ARN" ]]; then
    print_error "Scanner user ARN is required"
    show_usage
    exit 1
fi

if [[ -z "$AWS_ACCESS_KEY_ID" ]]; then
    print_error "AWS Access Key ID is required"
    show_usage
    exit 1
fi

if [[ -z "$AWS_SECRET_ACCESS_KEY" ]]; then
    print_error "AWS Secret Access Key is required"
    show_usage
    exit 1
fi

# Generate external ID if requested
if [[ "$GENERATE_EXTERNAL_ID" == true ]]; then
    EXTERNAL_ID=$(generate_external_id)
    print_status "Generated external ID: $EXTERNAL_ID"
fi

# Validate external ID
if [[ -z "$EXTERNAL_ID" ]]; then
    print_error "External ID is required"
    show_usage
    exit 1
fi

# Validate scanner user ARN format
if [[ ! "$SCANNER_USER_ARN" =~ ^arn:aws:iam::[0-9]{12}:(user|role)/ ]]; then
    print_error "Scanner user ARN must be in format: arn:aws:iam::ACCOUNT_ID:(user|role)/NAME"
    exit 1
fi

# Check if policy file exists
if [[ ! -f "aws-policies/iam-scanner-policy.json" ]]; then
    print_error "IAM policy file not found: aws-policies/iam-scanner-policy.json"
    print_error "Please ensure you're running this script from the project root directory"
    exit 1
fi

# Main execution
print_status "Starting AWS cross-account IAM setup..."

# Check prerequisites
check_aws_cli

# Configure AWS credentials
configure_aws_credentials "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" "$AWS_SESSION_TOKEN"

# Run setup
setup_aws_integration "$SCANNER_ACCOUNT_ID" "$EXTERNAL_ID" "$SCANNER_USER_ARN"

print_success "Setup completed successfully!"
