# Bash Script CLI Arguments

## Complete Argument Reference

### AWS Configuration

#### `--region REGION`
Specify AWS region for testing AWS service endpoints.

**Examples:**
```bash
./ona-network-check.sh --region us-east-1
./ona-network-check.sh --region eu-west-1
./ona-network-check.sh --region ap-southeast-2
```

**Auto-detection order:**
1. `--region` CLI argument (highest priority)
2. `$AWS_REGION` environment variable
3. `$AWS_DEFAULT_REGION` environment variable
4. EC2 instance metadata (if running on EC2)

**When to use:**
- Testing AWS service connectivity
- Pre-deployment validation in specific regions
- When auto-detection fails or you want to override

---

#### `--account-id ID`
Specify AWS account ID (included in JSON reports).

**Examples:**
```bash
./ona-network-check.sh --account-id 123456789012
./ona-network-check.sh --region us-east-1 --account-id 123456789012
```

**Auto-detection:**
- Attempts to detect via `aws sts get-caller-identity` if AWS CLI is configured
- Falls back to null if not available

**When to use:**
- When AWS CLI is not configured
- For documentation/reporting purposes
- When you want to explicitly set the account ID

---

### Source Control

#### `--scm URL`
Specify SCM provider URL(s) to test. Can be used multiple times.

**Examples:**
```bash
# Single SCM
./ona-network-check.sh --scm github.com

# Multiple SCMs
./ona-network-check.sh --scm github.com --scm gitlab.com

# Self-hosted
./ona-network-check.sh --scm github.enterprise.company.com

# Multiple self-hosted
./ona-network-check.sh \
  --scm github.company.com \
  --scm gitlab.company.com \
  --scm bitbucket.company.com
```

**Supported providers:**
- GitHub (github.com)
- GitHub Enterprise (self-hosted)
- GitLab (gitlab.com or self-hosted)
- Bitbucket (bitbucket.org)
- Azure DevOps (dev.azure.com)
- Any custom Git hosting

**Auto-detection:**
- If not specified, prompts interactively
- Default: github.com

**When to use:**
- Testing connectivity to your organization's SCM
- Pre-deployment validation
- Automated testing in CI/CD

---

### Authentication

#### `--sso URL`
Specify SSO provider URL for authentication testing.

**Examples:**
```bash
# Okta
./ona-network-check.sh --sso mycompany.okta.com

# Azure AD
./ona-network-check.sh --sso login.microsoftonline.com/tenant-id

# Google Workspace
./ona-network-check.sh --sso accounts.google.com

# Custom SSO
./ona-network-check.sh --sso sso.company.com
```

**Supported providers:**
- Okta
- Azure AD / Entra ID
- Google Workspace
- Any SAML/OIDC provider

**URL format:**
- Automatically adds `https://` if not present
- Can be domain only or full URL

**When to use:**
- Testing SSO connectivity
- Validating authentication flow
- Pre-deployment checks for SSO-enabled environments

---

### Container Registries

#### `--internal-registry URL`
Specify internal container registry URL.

**Examples:**
```bash
# JFrog Artifactory
./ona-network-check.sh --internal-registry artifactory.company.com

# Nexus
./ona-network-check.sh --internal-registry nexus.company.com

# Harbor
./ona-network-check.sh --internal-registry harbor.company.com

# AWS ECR
./ona-network-check.sh --internal-registry 123456789.dkr.ecr.us-east-1.amazonaws.com

# With full URL
./ona-network-check.sh --internal-registry https://registry.company.com:5000
```

**Supported registries:**
- JFrog Artifactory
- Nexus Repository
- Harbor
- AWS ECR (private)
- Any Docker-compatible registry

**URL format:**
- Automatically adds `https://` if not present
- Supports custom ports

**When to use:**
- Testing internal registry connectivity
- Validating image pull access
- Pre-deployment checks for air-gapped environments

---

### Custom Testing

#### `--test-url URL`
Test additional custom URLs. Can be used multiple times.

**Examples:**
```bash
# Single custom URL
./ona-network-check.sh --test-url api.company.com

# Multiple custom URLs
./ona-network-check.sh \
  --test-url api.company.com \
  --test-url cdn.company.com \
  --test-url monitoring.company.com

# With full URLs
./ona-network-check.sh \
  --test-url https://api.company.com/health \
  --test-url https://internal.company.com:8443
```

**URL format:**
- Automatically adds `https://` if not present
- Supports custom ports and paths

**When to use:**
- Testing custom internal services
- Validating API endpoints
- Testing CDN or monitoring services
- Any custom connectivity requirements

---

### Test Filtering

#### `--skip-aws`
Skip all AWS service endpoint tests.

**Examples:**
```bash
./ona-network-check.sh --skip-aws
./ona-network-check.sh --skip-aws --skip-vscode
```

**When to use:**
- Not deploying to AWS
- AWS connectivity not required
- Faster testing when AWS is not relevant

---

#### `--skip-vscode`
Skip VS Code endpoint tests.

**Examples:**
```bash
./ona-network-check.sh --skip-vscode
./ona-network-check.sh --skip-vscode --skip-jetbrains
```

**When to use:**
- Not using VS Code
- Only testing JetBrains IDEs
- Faster testing

---

#### `--skip-jetbrains`
Skip JetBrains endpoint tests.

**Examples:**
```bash
./ona-network-check.sh --skip-jetbrains
./ona-network-check.sh --skip-jetbrains --skip-vscode
```

**When to use:**
- Not using JetBrains IDEs
- Only testing VS Code
- Faster testing

---

### Output Options

#### `--json FILE`
Save test results to JSON file.

**Examples:**
```bash
# Basic JSON output
./ona-network-check.sh --json report.json

# With timestamp
./ona-network-check.sh --json "report-$(date +%Y%m%d-%H%M%S).json"

# Full path
./ona-network-check.sh --json /var/log/connectivity/report.json

# Combined with other options
./ona-network-check.sh \
  --region us-east-1 \
  --scm github.com \
  --json report.json
```

**JSON structure:**
```json
{
  "version": "1.0.0",
  "timestamp": "2026-02-06T10:44:09Z",
  "aws_context": {
    "region": "us-east-1",
    "account_id": "123456789012",
    "detection_method": "cli_argument"
  },
  "summary": {
    "total": 50,
    "passed": 45,
    "failed": 3,
    "warnings": 2
  },
  "tests": [
    {
      "name": "HTTP/2 Support",
      "endpoint": "https://app.gitpod.io",
      "status": "pass",
      "message": "HTTP/2 enabled",
      "command": "curl --http2 -I ...",
      "latency_ms": 123.45,
      "remediation": {
        "impact": "CLI failures, connection timeouts",
        "steps": ["Contact proxy admin", "Enable HTTP/2"],
        "reference": "https://ona.com/docs/..."
      }
    }
  ]
}
```

**When to use:**
- CI/CD integration
- Automated reporting
- Historical tracking
- Compliance documentation
- Integration with monitoring systems

---

#### `--verbose`
Enable verbose output (shows curl commands being executed).

**Examples:**
```bash
./ona-network-check.sh --verbose
./ona-network-check.sh --region us-east-1 --verbose
```

**Output includes:**
- Full curl commands
- Exit codes
- Additional debugging information

**When to use:**
- Debugging connectivity issues
- Understanding what tests are running
- Troubleshooting failures

---

#### `--help`
Show help message and exit.

**Examples:**
```bash
./ona-network-check.sh --help
./ona-network-check.sh -h  # Not supported, use --help
```

---

## Common Usage Patterns

### 1. Quick Check (Default)
```bash
./ona-network-check.sh
```
- Tests all default endpoints
- Prompts for SCM and internal registry
- No JSON output

### 2. Automated CI/CD
```bash
./ona-network-check.sh \
  --region us-east-1 \
  --scm github.com \
  --skip-vscode \
  --skip-jetbrains \
  --json report.json
```
- No interactive prompts
- JSON output for parsing
- Skips unnecessary tests

### 3. Full Enterprise Check
```bash
./ona-network-check.sh \
  --region us-east-1 \
  --account-id 123456789012 \
  --scm github.enterprise.company.com \
  --sso company.okta.com \
  --internal-registry artifactory.company.com \
  --test-url api.company.com \
  --test-url monitoring.company.com \
  --json full-report.json
```
- All custom endpoints
- Complete documentation
- JSON for compliance

### 4. Minimal Check (Fast)
```bash
./ona-network-check.sh \
  --scm github.com \
  --skip-aws \
  --skip-vscode \
  --skip-jetbrains
```
- Only essential tests
- No AWS (faster)
- No IDE endpoints

### 5. AWS-Only Check
```bash
./ona-network-check.sh \
  --region us-east-1 \
  --skip-vscode \
  --skip-jetbrains
```
- Focus on AWS connectivity
- Skip IDE endpoints
- Useful for AWS pre-deployment

### 6. Debug Mode
```bash
./ona-network-check.sh \
  --verbose \
  --test-url problematic-endpoint.com
```
- See all commands
- Test specific endpoint
- Troubleshoot issues

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed |
| 1 | One or more tests failed |

**Usage in scripts:**
```bash
if ./ona-network-check.sh --json report.json; then
    echo "✅ Connectivity check passed"
    deploy_application
else
    echo "❌ Connectivity check failed"
    exit 1
fi
```

---

## Environment Variables

The script respects these environment variables:

| Variable | Purpose | Example |
|----------|---------|---------|
| `AWS_REGION` | Default AWS region | `export AWS_REGION=us-east-1` |
| `AWS_DEFAULT_REGION` | Fallback AWS region | `export AWS_DEFAULT_REGION=us-west-2` |

**Note:** CLI arguments override environment variables.

---

## Interactive Prompts

If certain arguments are not provided, the script prompts interactively:

1. **SCM Provider** - If `--scm` not specified
2. **Internal Registry** - If `--internal-registry` not specified
3. **SSO Provider** - If `--sso` not specified

**Disable prompts:**
```bash
# Provide all arguments to avoid prompts
./ona-network-check.sh \
  --scm github.com \
  --skip-aws

# Or pipe input
echo -e "1\n6\n5" | ./ona-network-check.sh
```

---

## Dependencies

Required:
- `curl` (with HTTP/2 support)
- `openssl`

Optional:
- `bc` (for latency calculation, falls back to null)
- `aws` CLI (for account ID detection)

**Check dependencies:**
```bash
command -v curl && echo "✅ curl installed"
command -v openssl && echo "✅ openssl installed"
command -v bc && echo "✅ bc installed" || echo "⚠️  bc not installed (latency will be null)"
command -v aws && echo "✅ aws CLI installed" || echo "⚠️  aws CLI not installed (account ID detection disabled)"
```
