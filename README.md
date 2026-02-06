# Ona Network Diagnostic Tool

Pre-deployment connectivity checker for Ona runners. Identifies network issues before they cause deployment failures.

## Two Versions Available

This tool is available in both **Python** and **Bash** versions with ~95% feature parity:

| Feature | Python | Bash |
|---------|--------|------|
| All connectivity tests | ✅ | ✅ |
| JSON reports | ✅ | ✅ |
| Interactive prompts | ✅ | ✅ |
| Remediation guidance | ✅ | ✅ |
| Output formatting | Rich library (tables, progress) | ANSI colors |
| Dependencies | Python 3.6+, curl, openssl | bash, curl, openssl, bc |
| Startup time | ~100ms | ~10ms |
| Memory usage | ~30-50MB | ~5-10MB |

**Choose Python if:** You want enhanced output (tables, progress bars) or Python is already available.

**Choose Bash if:** You're in minimal environments, want faster startup, or Python is not available.

📖 See [COMPARISON.md](COMPARISON.md) for detailed feature comparison and [BASH_ARGUMENTS.md](BASH_ARGUMENTS.md) for bash-specific documentation.

## Problem

During Ona runner deployment, connectivity issues are difficult to diagnose. Customers often have network security tools (Zscaler, corporate firewalls, proxy servers) that interfere with required connections:

- WebSocket connections blocked or downgraded
- HTTP/2 downgraded to HTTP/1.1 by SSL inspection
- SSL certificates intercepted and replaced
- Specific endpoints blocked by firewall rules

This tool identifies these issues upfront with actionable remediation steps.

## Quick Start

### Python Version

```bash
# Download and run
curl -O https://raw.githubusercontent.com/ona-SE/ona-connectivity-tool/main/ona-network-check.py
python3 ona-network-check.py

# Or clone and run
git clone https://github.com/ona-SE/ona-connectivity-tool.git
cd ona-connectivity-tool
python3 ona-network-check.py
```

### Bash Version

```bash
# Download and run
curl -O https://raw.githubusercontent.com/ona-SE/ona-connectivity-tool/main/ona-network-check.sh
chmod +x ona-network-check.sh
./ona-network-check.sh

# Or clone and run
git clone https://github.com/ona-SE/ona-connectivity-tool.git
cd ona-connectivity-tool
chmod +x ona-network-check.sh
./ona-network-check.sh
```

## Requirements

### Python Version

**Required:**
- Python 3.6+
- curl (with HTTP/2 support)
- openssl

**Optional (for enhanced output):**
```bash
pip install rich
```

### Bash Version

**Required:**
- bash 4.0+
- curl (with HTTP/2 support)
- openssl
- bc (for latency calculation, optional)

**Optional:**
- aws CLI (for AWS account ID detection)

## Usage

Both versions support the same CLI arguments and produce identical JSON output:

```bash
# Run all tests with auto-detection
python3 ona-network-check.py
./ona-network-check.sh

# Specify AWS region
python3 ona-network-check.py --region us-east-1
./ona-network-check.sh --region us-east-1

# Test specific SCM providers
python3 ona-network-check.py --scm github.com --scm gitlab.company.com
./ona-network-check.sh --scm github.com --scm gitlab.company.com

# Test SSO and internal registry
python3 ona-network-check.py --sso company.okta.com --internal-registry artifactory.company.com
./ona-network-check.sh --sso company.okta.com --internal-registry artifactory.company.com

# Skip certain test categories
python3 ona-network-check.py --skip-jetbrains --skip-aws
./ona-network-check.sh --skip-jetbrains --skip-aws

# Show commands being executed (for transparency)
python3 ona-network-check.py --verbose
./ona-network-check.sh --verbose

# Save results to JSON (identical format)
python3 ona-network-check.py --json results.json
./ona-network-check.sh --json results.json
```

📖 For complete argument documentation, see [BASH_ARGUMENTS.md](BASH_ARGUMENTS.md)

## What It Tests

### Protocol Validation
- **HTTP/2 Support**: Detects if HTTP/2 is being downgraded to HTTP/1.1 (common Zscaler issue)
- **SSL Certificate**: Detects SSL interception by corporate proxies
- **WebSocket**: Validates WebSocket upgrade capability

### Endpoint Categories
- **Ona Management Plane**: app.gitpod.io, app.ona.com
- **VS Code**: update.code.visualstudio.com, marketplace, CDN
- **JetBrains**: downloads, plugins, services
- **Release Artifacts**: releases.gitpod.io
- **Container Registries**: MCR, Docker Hub, GHCR
- **AWS Services**: Regional endpoints (EC2, S3, ECS, etc.)
- **SCM Providers**: GitHub, GitLab, or custom

## Interpreting Results

```
✅ Passed    - Endpoint is reachable and working correctly
❌ Failed    - Endpoint is blocked or misconfigured (see remediation)
⚠️  Warning  - Endpoint works but with potential issues
⏭️  Skipped  - Test was skipped (via --skip-* flag)
```

### Example Output

```
[1/7] Protocol Validation
──────────────────────────────────────────────────────────────────
  ✅ https://app.gitpod.io HTTP/2 supported (version: 2) (45ms)
  ✅ app.gitpod.io Certificate issuer verified (not intercepted)
  ✅ https://app.gitpod.io WebSocket upgrade supported

[2/7] Ona Management Plane
──────────────────────────────────────────────────────────────────
  ✅ https://app.gitpod.io (200 OK) (52ms)
  ❌ https://app.ona.com Connection refused

     Impact: Cannot connect to Ona platform

     Remediation:
     1. Add app.gitpod.io to firewall allowlist
     Reference: https://ona.com/docs/ona/runners/aws/detailed-access-requirements
```

## Common Issues

### HTTP/2 Downgrade (Zscaler)
```
❌ HTTP/2 downgraded to HTTP/1.1
```
**Fix**: Contact Zscaler admin, enable HTTP/2 for SSL-inspected traffic in Administration > Advanced Settings.

### SSL Interception
```
❌ SSL interception detected: Zscaler Inc.
```
**Fix**: Add app.gitpod.io to SSL inspection bypass list.

### WebSocket Blocked
```
❌ WebSocket blocked (HTTP 403)
```
**Fix**: Ensure WebSocket traffic is allowed through firewall, add app.gitpod.io to WebSocket allowlist.

## AWS Context Detection

The tool automatically detects AWS region from:
1. `--region` CLI argument (highest priority)
2. `AWS_REGION` or `AWS_DEFAULT_REGION` environment variables
3. EC2 instance metadata (169.254.169.254)

Use `--skip-aws` to skip AWS endpoint tests if not in an AWS context.

## JSON Output

Save results for programmatic consumption:

```bash
python3 ona-network-check.py --json results.json
```

Output structure:
```json
{
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z",
  "aws_context": {
    "region": "us-east-1",
    "detection_method": "instance_metadata"
  },
  "summary": {
    "total": 19,
    "passed": 18,
    "failed": 1
  },
  "categories": [...]
}
```

## Documentation

- [Ona Access Requirements](https://ona.com/docs/ona/runners/aws/detailed-access-requirements)
- [Zscaler Troubleshooting](https://ona.com/docs/ona/runners/aws/troubleshooting-zscaler)
- [VPC Endpoints](https://ona.com/docs/ona/runners/aws/vpc-endpoints)
- [JetBrains Network Requirements](https://ona.com/docs/ona/editors/jetbrains#network-access-requirements)

## Contributing

This tool is maintained by the Ona Sales Engineering team. For issues or feature requests, open an issue at [github.com/ona-SE/ona-connectivity-tool](https://github.com/ona-SE/ona-connectivity-tool/issues).
