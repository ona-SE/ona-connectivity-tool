# Ona Network Diagnostic Tool

Pre-deployment connectivity checker for Ona runners. Identifies network issues before they cause deployment failures.

## Problem

During Ona runner deployment, connectivity issues are difficult to diagnose. Customers often have network security tools (Zscaler, corporate firewalls, proxy servers) that interfere with required connections:

- WebSocket connections blocked or downgraded
- HTTP/2 downgraded to HTTP/1.1 by SSL inspection
- SSL certificates intercepted and replaced
- Specific endpoints blocked by firewall rules

This tool identifies these issues upfront with actionable remediation steps.

## Quick Start

```bash
# Download and run
curl -O https://raw.githubusercontent.com/ona-SE/ona-connectivity-tool/main/ona-network-check.py
python3 ona-network-check.py

# Or clone and run
git clone https://github.com/ona-SE/ona-connectivity-tool.git
cd ona-connectivity-tool
python3 ona-network-check.py
```

## Requirements

**Required:**
- Python 3.6+
- curl (with HTTP/2 support)
- openssl

**Optional (for enhanced output):**
```bash
pip install rich
```

## Usage

```bash
# Run all tests with auto-detection
python3 ona-network-check.py

# Specify AWS region
python3 ona-network-check.py --region us-east-1

# Test specific SCM providers
python3 ona-network-check.py --scm github.com --scm gitlab.company.com

# Skip certain test categories
python3 ona-network-check.py --skip-jetbrains --skip-aws

# Show commands being executed (for transparency)
python3 ona-network-check.py --verbose

# Save results to JSON
python3 ona-network-check.py --json results.json
```

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
