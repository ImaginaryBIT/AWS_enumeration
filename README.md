# IAMenum - AWS IAM Enumeration Tool

A comprehensive AWS IAM enumeration tool designed for security assessments and privilege escalation analysis. This tool recursively enumerates IAM identities, policies, and trust relationships to build a complete privilege graph.

## Features

✅ **Comprehensive IAM Enumeration**
- Lists all IAM users, roles, groups, and policies
- Exports **all policy versions** (Phase 16) for historical analysis
- Identifies **AssumeRole** and **PassRole** escalation paths
- Includes trust policies and inline/attached documents

✅ **AI-Powered Escalation Analysis (analyze.py)**
- Multi-agent orchestration using OpenAI (GPT-5.2)
- **Active Execution**: Automatically gathers additional evidence (s3, lambda, secret values)
- **Heuristic Scanning**: Flags sensitive permission combinations (PrivEsc, DataExfil)
- Generates professional markdown security reports

✅ **Infrastructure & Network Context**
- Enumerates **EC2 instances** and linked **Instance Profiles**
- Maps **Network Interfaces (ENIs)**, Security Groups, and IP assignments
- Links **Lambda triggers** (S3, SNS, SQS, EventBridge)
- Audits **Exposed Assets** (Public S3, Open Security Groups, Public RDS/ECS)

✅ **Organization & SCP Visibility**
- Checks for AWS Organization membership
- Enumerates applied **Service Control Policies (SCPs)** (if allowed)


## Installation

### Prerequisites
- Python 3.7+
- AWS credentials configured
- Appropriate IAM permissions

### Setup

1. **Clone or download the repository**
```bash
cd IAMenum
```

2. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
# or
venv\Scripts\activate  # On Windows
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure AWS credentials**
```bash
# Option 1: AWS CLI configuration
aws configure --profile your-profile

# Option 2: Manual configuration
# Edit ~/.aws/credentials
[your-profile]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

## Usage

### Basic Usage

**Enumerate with default settings:**
```bash
python enumerate_iam.py --profile your-profile
```

This will:
- Use the specified AWS profile
- Default to `us-east-1` region
- Export to `./out/` directory
- Only export customer-managed policies

### Command-Line Options

```
usage: enumerate_iam.py [-h] [--profile PROFILE] [--region REGION] [--output OUTPUT]
              [--assume-role ASSUME_ROLE] [--include-aws-policies]
              [--dry-run] [--allow-assume] [--max-depth MAX_DEPTH]
              [--rate-limit RATE_LIMIT] [--deny DENY] [--allow ALLOW]

Options:
  -h, --help            Show help message and exit
  --profile PROFILE     AWS CLI profile to use (optional)
  --region REGION       AWS region (default: us-east-1)
  --output OUTPUT       Output directory (default: out)
  --assume-role ASSUME_ROLE
                        Role ARN to assume before enumeration
  --include-aws-policies
                        Include AWS-managed policies (slow)
  --dry-run             Do not perform state-changing actions (default: True)
  --allow-assume        Allow actual sts:AssumeRole calls
  --max-depth MAX_DEPTH
                        Maximum recursion depth (default: 3)
  --rate-limit RATE_LIMIT
                        Seconds between API calls (default: 0.2)
  --deny DENY           Deny-list substring for principal ARNs
  --allow ALLOW         Allow-list substring for principal ARNs
```

## Usage Examples

### 1. Basic Enumeration

**Enumerate current user's permissions:**
```bash
python enumerate_iam.py --profile my-profile --output results
```

**Specify custom region:**
```bash
python enumerate_iam.py --profile my-profile --region eu-west-1 --output eu-results
```

### 2. Assume Role Enumeration

**Start enumeration with an assumed role:**
```bash
python enumerate_iam.py --profile my-profile \
  --assume-role arn:aws:iam::123456789012:role/TargetRole \
  --output assumed-results
```

**Use case:** When your current user has limited permissions but can assume a more privileged role.

### 3. Include AWS-Managed Policies

**Export all policies including AWS-managed:**
```bash
python enumerate_iam.py --profile my-profile \
  --output all-policies \
  --include-aws-policies
```

⚠️ **Warning:** This can take 5-10 minutes as it exports 1000+ AWS-managed policies.

### 4. Advanced Options

**Custom rate limiting (slower, avoid throttling):**
```bash
python enumerate_iam.py --profile my-profile \
  --rate-limit 0.5 \
  --output slow-results
```

**Filter by principal ARN patterns:**
```bash
# Only enumerate specific principals
python enumerate_iam.py --profile my-profile \
  --allow "arn:aws:iam::123456789012:role/MyRole*" \
  --output filtered-results

# Exclude specific principals
python enumerate_iam.py --profile my-profile \
  --deny "arn:aws:iam::123456789012:role/ServiceRole*" \
  --output filtered-results
```

## AI-Powered Analysis (analyze.py)

After running the enumeration, use the `analyze.py` multi-agent pipeline to find escalation paths:

```bash
# Analyze results using OpenAI (requires OPENAI_API_KEY)
export OPENAI_API_KEY='sk-...'
python analyze.py --input path/to/results --model gpt-5.2
```

### Active Execution
To allow the AI to actively gather evidence (e.g., calling `get-secret-value` or `get-function` if it finds a target):
```bash
python analyze.py --input results --profile my-profile --execute
```
*Note: The AI is restricted to read-only discovery commands and blocked from IAM/STS mutation.*

### Features
- **Discovery Agent**: Identifies high-value targets from enumeration JSON.
- **Command Agent**: Crafts specific AWS CLI commands to gather deeper evidence.
- **Execution Agent**: Runs commands, pretty-prints results, and organizes evidence.
- **Analysis Agent**: Synthesizes all data into a professional threat report.

## Output Files

All output files are saved in the specified output directory:

| File | Description |
|------|-------------|
| `caller_identity.json` | Current STS identity results |
| `iam_users_detailed.json` | Users with full policy documents and groups |
| `iam_roles.json` | Roles with policies and trust documents |
| `iam_groups.json` | Global group list and their policies |
| `iam_policies.json` | Managed policies with **Full Version History** |
| `infrastructure_context.json` | EC2, Lambda triggers, and ENI network context |
| `exposed_assets.json` | Audit findings for public/risky assets |
| `organization_context.json` | Org info and applied SCPs |
| `graph.json` | Privilege escalation graph (IAM + Resource) |
| `graph.dot` | DOT format for visualization |

### Output File Details

**iam_users_detailed.json** - Complete user information:
```json
[
  {
    "UserInfo": {
      "UserName": "example-user",
      "Arn": "arn:aws:iam::123456789012:user/example-user",
      "CreateDate": "2024-01-01T00:00:00Z"
    },
    "AttachedPolicies": [
      {
        "PolicyName": "CustomPolicy",
        "PolicyArn": "arn:aws:iam::123456789012:policy/CustomPolicy",
        "PolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [...]
        }
      }
    ],
    "InlinePolicies": {...}
  }
]
```

**iam_roles.json** - Complete role information:
```json
[
  {
    "RoleInfo": {
      "RoleName": "example-role",
      "Arn": "arn:aws:iam::123456789012:role/example-role"
    },
    "AttachedPolicies": [...],
    "InlinePolicies": {...},
    "AssumeRolePolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [...]
    }
  }
]
```

**graph.json** - Privilege escalation graph:
```json
{
  "nodes": {
    "arn:aws:iam::123456789012:user/start-user": {
      "label": "start-user",
      "discovered_depth": 0
    }
  },
  "edges": [
    {
      "src": "arn:aws:iam::123456789012:user/start-user",
      "dst": "arn:aws:iam::123456789012:role/target-role",
      "relation": "trusted-by"
    }
  ]
}
```

## Visualizing Results

### Using Graphviz

**Install Graphviz:**
```bash
# macOS
brew install graphviz

# Ubuntu/Debian
sudo apt-get install graphviz

# Windows
# Download from https://graphviz.org/download/
```

**Generate visualization:**
```bash
dot -Tpng out/graph.dot -o privilege_graph.png
dot -Tsvg out/graph.dot -o privilege_graph.svg
```

### Analyzing JSON Output

**Using jq for analysis:**
```bash
# List all users
cat out/iam_users.json | jq '.[].UserName'

# Find users with specific policy
cat out/iam_users_detailed.json | jq '.[] | select(.AttachedPolicies[].PolicyName == "AdministratorAccess")'

# List all assumable roles
cat out/graph.json | jq '.edges[] | select(.relation == "trusted-by")'

# Count policies by type
cat out/iam_policies.json | jq '[.[] | select(.PolicyInfo.Arn | startswith("arn:aws:iam::aws"))] | length'
```

## Required IAM Permissions

Minimum permissions required for the script to function:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetUser",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:GetRole",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListUserPolicies",
        "iam:ListRolePolicies",
        "iam:GetUserPolicy",
        "iam:GetRolePolicy",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**For assume role functionality:**
```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/*"
}
```

## Troubleshooting

### Common Issues

**1. "ModuleNotFoundError: No module named 'boto3'"**
```bash
# Activate virtual environment first
source venv/bin/activate
pip install -r requirements.txt
```

**2. "AccessDenied" errors**
- Check that your AWS credentials have the required IAM permissions
- Some resources may be inaccessible - the script will continue with available data

**3. "ResponseParserError: Unable to parse response"**
- This is an intermittent AWS API issue
- The script handles these errors gracefully and continues
- Try running again if it persists

**4. Script is very slow**
- Default rate limit is 0.2 seconds between API calls
- Increase with `--rate-limit 0.5` if needed
- Using `--include-aws-policies` will take 5-10 minutes

**5. "Failed to assume role"**
- Verify the role ARN is correct
- Check that your user has `sts:AssumeRole` permission
- Verify the role's trust policy allows your user

## Security Considerations

⚠️ **Important Security Notes:**

1. **Read-Only by Default**: The script is read-only and does not modify any AWS resources
2. **Credential Safety**: Never commit AWS credentials to version control
3. **Output Sensitivity**: Output files contain sensitive IAM information - protect them appropriately
4. **Rate Limiting**: Default rate limiting prevents API throttling
5. **Authorized Use Only**: Only use this tool on AWS accounts you are authorized to assess

## Performance Tips

**Fast enumeration (customer policies only):**
```bash
python enumerate_iam.py --profile my-profile --output fast-results
# Completes in ~30 seconds
```

**Comprehensive enumeration (all policies):**
```bash
python enumerate_iam.py --profile my-profile --output comprehensive --include-aws-policies
# Takes 5-10 minutes
```

**Optimize for large environments:**
```bash
python enumerate_iam.py --profile my-profile \
  --rate-limit 0.1 \
  --max-depth 2 \
  --output optimized
```

## Examples for Common Scenarios

### Scenario 1: Initial Reconnaissance
```bash
# Quick enumeration to understand current permissions
python enumerate_iam.py --profile target-account --output recon
```

### Scenario 2: Privilege Escalation Lab
```bash
# Enumerate as limited user
python enumerate_iam.py --profile lab-start --output lab-start-results

# Assume discovered role
python enumerate_iam.py --profile lab-start \
  --assume-role arn:aws:iam::123456789012:role/lab-target \
  --output lab-target-results
```

### Scenario 3: Complete IAM Audit
```bash
# Full enumeration with all policies
python enumerate_iam.py --profile audit-account \
  --include-aws-policies \
  --output full-audit \
  --rate-limit 0.3
```

### Scenario 4: Multi-Region Assessment
```bash
# Enumerate different regions
for region in us-east-1 eu-west-1 ap-southeast-1; do
  python enumerate_iam.py --profile my-profile \
    --region $region \
    --output results-$region
done
```

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style
- Error handling is comprehensive
- Documentation is updated
- Security best practices are followed

## License

Use only with explicit authorization on AWS accounts you own or have permission to assess.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review the output logs for error messages
3. Ensure you have the required IAM permissions

## Changelog

### Latest Version
- ✅ **Multi-Agent AI Pipeline**: Added `analyze.py` with multi-agent orchestration.
- ✅ **Active Evidence Gathering**: AI can now execute read-only CLI commands.
- ✅ **Network Layer Enumeration**: Added ENI, Subnet, and Security Group mapping.
- ✅ **Policy Versioning**: Enumerate all available versions for managed policies.
- ✅ **Asset Exposure Audit**: Automated checks for public S3, RDS, and open SGs.
- ✅ **Infrastructure Context**: Linked EC2 profiles and Lambda triggers.
- ✅ **Organization/SCP Support**: Discover applied SCPs across accounts.
- ✅ **Group Enumeration**: Full visibility into global groups and memberships.
- ✅ **Stability**: Fixed circular imports and renamed main script to `enumerate_iam.py`.
