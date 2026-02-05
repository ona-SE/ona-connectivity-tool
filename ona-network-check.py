#!/usr/bin/env python3
"""
Ona Network Connectivity Diagnostic Tool v1.0.0

Pre-deployment connectivity checker for Ona runners. Tests all required
endpoints and validates protocol requirements (HTTP/2, WebSocket, SSL).

Requirements:
- Python 3.6+
- curl (with HTTP/2 support)
- openssl

Optional (for enhanced output):
  pip install rich

Usage:
  python3 ona-network-check.py
  python3 ona-network-check.py --region us-east-1 --verbose
  python3 ona-network-check.py --scm github.com --scm gitlab.company.com

Documentation: https://ona.com/docs/ona/runners/aws/detailed-access-requirements
"""

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Any

VERSION = "1.0.0"

# Try to import rich for colored output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class Remediation:
    """Remediation steps for a failed test."""
    impact: str
    steps: List[str]
    reference: str


@dataclass
class TestResult:
    """Result of a single connectivity test."""
    name: str
    endpoint: str
    status: str  # "pass", "fail", "warn", "skip"
    message: str
    command: str = ""
    latency_ms: Optional[float] = None
    remediation: Optional[Remediation] = None


@dataclass
class TestCategory:
    """A category of related tests."""
    name: str
    tests: List[TestResult] = field(default_factory=list)


@dataclass
class AWSContext:
    """AWS context information."""
    region: Optional[str] = None
    account_id: Optional[str] = None
    detection_method: str = "none"


# =============================================================================
# Output Formatting
# =============================================================================

class PlainOutput:
    """Plain text output with ANSI colors."""
    
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    BOLD = "\033[1m"
    RESET = "\033[0m"
    
    @staticmethod
    def success(msg: str) -> str:
        return f"{PlainOutput.GREEN}✅ {msg}{PlainOutput.RESET}"
    
    @staticmethod
    def fail(msg: str) -> str:
        return f"{PlainOutput.RED}❌ {msg}{PlainOutput.RESET}"
    
    @staticmethod
    def warn(msg: str) -> str:
        return f"{PlainOutput.YELLOW}⚠️  {msg}{PlainOutput.RESET}"
    
    @staticmethod
    def info(msg: str) -> str:
        return f"{PlainOutput.BLUE}{msg}{PlainOutput.RESET}"
    
    @staticmethod
    def bold(msg: str) -> str:
        return f"{PlainOutput.BOLD}{msg}{PlainOutput.RESET}"


def print_header():
    """Print the tool header."""
    header = f"""
{'='*66}
           Ona Network Connectivity Diagnostic Tool
                        v{VERSION}
{'='*66}
"""
    if RICH_AVAILABLE:
        console.print(Panel(f"[bold]Ona Network Connectivity Diagnostic Tool[/bold]\nv{VERSION}", 
                           style="blue"))
    else:
        print(header)


def print_category(name: str, index: int, total: int):
    """Print a category header."""
    if RICH_AVAILABLE:
        console.print(f"\n[bold cyan][{index}/{total}] {name}[/bold cyan]")
        console.print("─" * 66)
    else:
        print(f"\n{PlainOutput.bold(f'[{index}/{total}] {name}')}")
        print("─" * 66)


def print_result(result: TestResult, verbose: bool = False):
    """Print a single test result."""
    if verbose and result.command:
        if RICH_AVAILABLE:
            console.print(f"  [dim]Command: {result.command}[/dim]")
        else:
            print(f"  Command: {result.command}")
    
    latency = f" ({result.latency_ms:.0f}ms)" if result.latency_ms else ""
    
    if result.status == "pass":
        if RICH_AVAILABLE:
            console.print(f"  [green]✅ {result.endpoint}[/green] {result.message}{latency}")
        else:
            print(f"  {PlainOutput.success(result.endpoint)} {result.message}{latency}")
    elif result.status == "fail":
        if RICH_AVAILABLE:
            console.print(f"  [red]❌ {result.endpoint}[/red] {result.message}")
        else:
            print(f"  {PlainOutput.fail(result.endpoint)} {result.message}")
        
        if result.remediation:
            print_remediation(result.remediation)
    elif result.status == "warn":
        if RICH_AVAILABLE:
            console.print(f"  [yellow]⚠️  {result.endpoint}[/yellow] {result.message}")
        else:
            print(f"  {PlainOutput.warn(result.endpoint)} {result.message}")
    else:  # skip
        if RICH_AVAILABLE:
            console.print(f"  [dim]⏭️  {result.endpoint} (skipped)[/dim]")
        else:
            print(f"  ⏭️  {result.endpoint} (skipped)")


def print_remediation(remediation: Remediation):
    """Print remediation steps for a failure."""
    print(f"\n     Impact: {remediation.impact}\n")
    print("     Remediation:")
    for i, step in enumerate(remediation.steps, 1):
        print(f"     {i}. {step}")
    print(f"     Reference: {remediation.reference}\n")


def print_summary(categories: List[TestCategory]):
    """Print the final summary."""
    total = sum(len(c.tests) for c in categories)
    passed = sum(1 for c in categories for t in c.tests if t.status == "pass")
    failed = sum(1 for c in categories for t in c.tests if t.status == "fail")
    warnings = sum(1 for c in categories for t in c.tests if t.status == "warn")
    skipped = sum(1 for c in categories for t in c.tests if t.status == "skip")
    
    print("\n" + "━" * 66)
    if RICH_AVAILABLE:
        console.print("\n[bold]Summary[/bold]")
    else:
        print(f"\n{PlainOutput.bold('Summary')}")
    print("─" * 66)
    
    print(f"\nTotal tests: {total}")
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print(f"  ⚠️  Warnings: {warnings}")
    if skipped:
        print(f"  ⏭️  Skipped: {skipped}")
    
    if failed > 0:
        print("\nFailed tests require attention before runner deployment.")
        print("See remediation steps above for each failure.")
    else:
        print("\n✅ All tests passed! Ready for runner deployment.")
    
    print(f"\nDocumentation: https://ona.com/docs/ona/runners/aws/detailed-access-requirements")
    
    return failed


# =============================================================================
# AWS Context Detection
# =============================================================================

def detect_aws_context(args) -> AWSContext:
    """Detect AWS region and account from various sources."""
    ctx = AWSContext()
    
    # Check for manual override first
    if args.region:
        ctx.region = args.region
        ctx.detection_method = "cli_argument"
    
    if args.account_id:
        ctx.account_id = args.account_id
    
    if ctx.region:
        return ctx
    
    # Try environment variables
    ctx.region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if ctx.region:
        ctx.detection_method = "environment_variable"
        return ctx
    
    # Try EC2 instance metadata
    try:
        result = subprocess.run(
            ["curl", "-s", "--connect-timeout", "2", 
             "http://169.254.169.254/latest/meta-data/placement/region"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0 and result.stdout and not result.stdout.startswith("<?"):
            ctx.region = result.stdout.strip()
            ctx.detection_method = "instance_metadata"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    # Try to get account ID
    if not ctx.account_id:
        try:
            result = subprocess.run(
                ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                ctx.account_id = result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    return ctx


# =============================================================================
# Command Execution
# =============================================================================

def run_command(cmd: List[str], timeout: int = 30) -> tuple:
    """Run a command and return (returncode, stdout, stderr, duration_ms)."""
    import time
    start = time.time()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration = (time.time() - start) * 1000
        return result.returncode, result.stdout, result.stderr, duration
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout", (time.time() - start) * 1000
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}", 0


def test_endpoint(url: str, timeout: int = 10, allow_4xx: bool = False) -> TestResult:
    """Test basic HTTPS connectivity to an endpoint.
    
    Args:
        url: The URL to test
        timeout: Connection timeout in seconds
        allow_4xx: If True, treat 4xx responses as pass (endpoint reachable but requires auth)
    """
    cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", 
           "--connect-timeout", str(timeout), url]
    
    code, stdout, stderr, _ = run_command(cmd, timeout + 5)
    cmd_str = " ".join(cmd)
    
    if code != 0:
        return TestResult(
            name=url, endpoint=url, status="fail",
            message=f"Connection failed: {stderr}",
            command=cmd_str
        )
    
    parts = stdout.strip().split()
    http_code = parts[0] if parts else "000"
    latency = float(parts[1]) * 1000 if len(parts) > 1 else None
    
    # Success: 2xx or 3xx responses
    if http_code.startswith("2") or http_code.startswith("3"):
        return TestResult(
            name=url, endpoint=url, status="pass",
            message=f"({http_code} OK)",
            command=cmd_str, latency_ms=latency
        )
    # AWS APIs return 4xx on unauthenticated requests - endpoint is reachable
    elif allow_4xx and http_code.startswith("4"):
        return TestResult(
            name=url, endpoint=url, status="pass",
            message=f"(reachable, {http_code})",
            command=cmd_str, latency_ms=latency
        )
    else:
        return TestResult(
            name=url, endpoint=url, status="fail",
            message=f"HTTP {http_code}",
            command=cmd_str, latency_ms=latency
        )


# =============================================================================
# Protocol Tests
# =============================================================================

def test_http2(url: str = "https://app.gitpod.io") -> TestResult:
    """Test HTTP/2 support."""
    cmd = ["curl", "--http2", "-I", "-s", "-o", "/dev/null", "-w", "%{http_version}", url]
    code, stdout, stderr, latency = run_command(cmd)
    cmd_str = " ".join(cmd)
    
    if code != 0:
        return TestResult(
            name="HTTP/2 Support", endpoint=url, status="fail",
            message=f"Connection failed: {stderr}",
            command=cmd_str,
            remediation=Remediation(
                impact="CLI failures, connection timeouts, protocol errors",
                steps=[
                    "Contact your Zscaler/proxy admin",
                    "Enable HTTP/2 for SSL-inspected traffic",
                    "Location: Administration > Advanced Settings"
                ],
                reference="https://ona.com/docs/ona/runners/aws/troubleshooting-zscaler"
            )
        )
    
    version = stdout.strip()
    if version == "2" or version == "2.0":
        return TestResult(
            name="HTTP/2 Support", endpoint=url, status="pass",
            message=f"HTTP/2 supported (version: {version})",
            command=cmd_str, latency_ms=latency
        )
    else:
        return TestResult(
            name="HTTP/2 Support", endpoint=url, status="fail",
            message=f"HTTP/2 downgraded to HTTP/{version}",
            command=cmd_str, latency_ms=latency,
            remediation=Remediation(
                impact="CLI failures, connection timeouts, protocol errors",
                steps=[
                    "Contact your Zscaler admin",
                    "Enable HTTP/2 for SSL-inspected traffic",
                    "Location: Administration > Advanced Settings"
                ],
                reference="https://ona.com/docs/ona/runners/aws/troubleshooting-zscaler"
            )
        )


def test_ssl_certificate(host: str = "app.gitpod.io") -> TestResult:
    """Test SSL certificate chain for interception."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host]
    code, stdout, stderr, latency = run_command(cmd, timeout=10)
    cmd_str = f"openssl s_client -connect {host}:443 -servername {host} | openssl x509 -noout -issuer"
    
    # Parse issuer from output
    issuer = "Unknown"
    for line in (stdout + stderr).split("\n"):
        if "issuer=" in line.lower() or "i:" in line:
            issuer = line.strip()
            break
    
    # Known intercepting proxies
    interceptors = ["zscaler", "palo alto", "fortinet", "blue coat", "symantec"]
    is_intercepted = any(i in issuer.lower() for i in interceptors)
    
    if is_intercepted:
        return TestResult(
            name="SSL Certificate", endpoint=host, status="fail",
            message=f"SSL interception detected: {issuer}",
            command=cmd_str, latency_ms=latency,
            remediation=Remediation(
                impact="VS Code can't connect, certificate verify failed errors",
                steps=[
                    f"Add {host} to SSL inspection bypass list",
                    "Alternative: Enable 'System certificates' in VS Code (v1.97+)"
                ],
                reference="https://ona.com/docs/ona/runners/aws/troubleshooting-zscaler"
            )
        )
    elif "amazon" in issuer.lower() or "digicert" in issuer.lower():
        return TestResult(
            name="SSL Certificate", endpoint=host, status="pass",
            message="Certificate issuer verified (not intercepted)",
            command=cmd_str, latency_ms=latency
        )
    else:
        return TestResult(
            name="SSL Certificate", endpoint=host, status="warn",
            message=f"Unknown issuer: {issuer[:50]}...",
            command=cmd_str, latency_ms=latency
        )


def test_websocket(url: str = "https://app.gitpod.io") -> TestResult:
    """Test WebSocket upgrade capability."""
    cmd = [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "-H", "Connection: Upgrade",
        "-H", "Upgrade: websocket",
        "-H", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "-H", "Sec-WebSocket-Version: 13",
        url
    ]
    code, stdout, stderr, latency = run_command(cmd)
    cmd_str = "curl -H 'Connection: Upgrade' -H 'Upgrade: websocket' ..."
    
    http_code = stdout.strip()
    
    # 101 = Switching Protocols (ideal), 200/400 = endpoint exists but not WS
    if http_code in ["101", "200", "400", "426"]:
        return TestResult(
            name="WebSocket", endpoint=url, status="pass",
            message="WebSocket upgrade supported",
            command=cmd_str, latency_ms=latency
        )
    else:
        return TestResult(
            name="WebSocket", endpoint=url, status="fail",
            message=f"WebSocket blocked (HTTP {http_code})",
            command=cmd_str, latency_ms=latency,
            remediation=Remediation(
                impact="Real-time features won't work, environment status updates will fail",
                steps=[
                    "Ensure WebSocket traffic is allowed through firewall",
                    "Add app.gitpod.io to WebSocket allowlist",
                    "Check if proxy supports WebSocket passthrough"
                ],
                reference="https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
            )
        )


# =============================================================================
# Endpoint Test Categories
# =============================================================================

def get_ona_endpoints() -> List[str]:
    return ["https://app.gitpod.io", "https://app.ona.com"]


def get_vscode_endpoints() -> List[str]:
    return [
        "https://update.code.visualstudio.com",
        "https://marketplace.visualstudio.com",
        "https://vscode.gitpod.io",
    ]


def get_jetbrains_endpoints() -> List[str]:
    return [
        "https://www.jetbrains.com",
        "https://download.jetbrains.com",
        "https://data.services.jetbrains.com/products",  # API endpoint
        "https://plugins.jetbrains.com",
    ]


def get_release_endpoints() -> List[str]:
    return [
        "https://releases.gitpod.io/ec2/stable/manifest.json",
        "https://releases.gitpod.io/cli/stable/manifest.json",
    ]


def get_registry_endpoints() -> List[str]:
    return [
        "https://mcr.microsoft.com",
        "https://index.docker.io",
        "https://ghcr.io",
    ]


def get_aws_endpoints(region: str) -> List[str]:
    services = ["ec2", "s3", "ssm", "sts", "ecs", "logs", "secretsmanager"]
    return [f"https://{svc}.{region}.amazonaws.com" for svc in services]


# =============================================================================
# Main Test Runner
# =============================================================================

def run_tests(args) -> List[TestCategory]:
    """Run all connectivity tests."""
    categories = []
    
    # Protocol validation
    cat = TestCategory(name="Protocol Validation")
    cat.tests.append(test_http2())
    cat.tests.append(test_ssl_certificate())
    cat.tests.append(test_websocket())
    categories.append(cat)
    
    # Ona Management Plane
    cat = TestCategory(name="Ona Management Plane")
    for url in get_ona_endpoints():
        result = test_endpoint(url)
        if result.status == "fail":
            result.remediation = Remediation(
                impact="Cannot connect to Ona platform",
                steps=["Add app.gitpod.io to firewall allowlist"],
                reference="https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
            )
        cat.tests.append(result)
    categories.append(cat)
    
    # VS Code
    if not args.skip_vscode:
        cat = TestCategory(name="VS Code Endpoints")
        for url in get_vscode_endpoints():
            cat.tests.append(test_endpoint(url))
        categories.append(cat)
    
    # JetBrains
    if not args.skip_jetbrains:
        cat = TestCategory(name="JetBrains Endpoints")
        for url in get_jetbrains_endpoints():
            cat.tests.append(test_endpoint(url))
        categories.append(cat)
    
    # Release artifacts
    cat = TestCategory(name="Release Artifacts")
    for url in get_release_endpoints():
        cat.tests.append(test_endpoint(url))
    categories.append(cat)
    
    # Container registries
    cat = TestCategory(name="Container Registries")
    for url in get_registry_endpoints():
        cat.tests.append(test_endpoint(url))
    categories.append(cat)
    
    # AWS Services
    if not args.skip_aws and args.aws_context.region:
        cat = TestCategory(name="AWS Services")
        for url in get_aws_endpoints(args.aws_context.region):
            # AWS APIs return 4xx on unauthenticated requests - that's fine, endpoint is reachable
            result = test_endpoint(url, allow_4xx=True)
            if result.status == "fail":
                result.remediation = Remediation(
                    impact="Runner deployment will fail, AWS resources won't be accessible",
                    steps=[
                        "Configure VPC endpoints for AWS services, OR",
                        "Ensure NAT gateway allows outbound to AWS service endpoints"
                    ],
                    reference="https://ona.com/docs/ona/runners/aws/vpc-endpoints"
                )
            cat.tests.append(result)
        categories.append(cat)
    
    # SCM Providers
    scm_urls = args.scm if args.scm else ["github.com"]
    cat = TestCategory(name="SCM Providers")
    for scm in scm_urls:
        url = f"https://{scm}" if not scm.startswith("http") else scm
        cat.tests.append(test_endpoint(url))
        if "github.com" in scm:
            cat.tests.append(test_endpoint("https://api.github.com"))
    categories.append(cat)
    
    return categories


def save_json_report(categories: List[TestCategory], aws_ctx: AWSContext, filepath: str):
    """Save results to JSON file."""
    report = {
        "version": VERSION,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "aws_context": asdict(aws_ctx),
        "summary": {
            "total": sum(len(c.tests) for c in categories),
            "passed": sum(1 for c in categories for t in c.tests if t.status == "pass"),
            "failed": sum(1 for c in categories for t in c.tests if t.status == "fail"),
            "warnings": sum(1 for c in categories for t in c.tests if t.status == "warn"),
        },
        "categories": []
    }
    
    for cat in categories:
        cat_data = {"name": cat.name, "tests": []}
        for t in cat.tests:
            test_data = asdict(t)
            if t.remediation:
                test_data["remediation"] = asdict(t.remediation)
            cat_data["tests"].append(test_data)
        report["categories"].append(cat_data)
    
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nJSON report saved to: {filepath}")


# =============================================================================
# CLI Entry Point
# =============================================================================

def parse_args():
    parser = argparse.ArgumentParser(
        description="Ona Network Connectivity Diagnostic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Run all tests with auto-detection
  %(prog)s --region us-east-1           # Specify AWS region
  %(prog)s --scm github.com --scm gitlab.company.com
  %(prog)s --skip-jetbrains --verbose   # Skip JetBrains, show commands
        """
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--region", help="AWS region (auto-detected if not provided)")
    parser.add_argument("--account-id", help="AWS account ID (auto-detected if not provided)")
    parser.add_argument("--scm", action="append", help="SCM provider URL (can specify multiple)")
    parser.add_argument("--skip-aws", action="store_true", help="Skip AWS endpoint tests")
    parser.add_argument("--skip-jetbrains", action="store_true", help="Skip JetBrains tests")
    parser.add_argument("--skip-vscode", action="store_true", help="Skip VS Code tests")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show commands being run")
    parser.add_argument("--json", metavar="FILE", help="Save results to JSON file")
    return parser.parse_args()


def main():
    args = parse_args()
    
    print_header()
    
    # Detect AWS context
    args.aws_context = detect_aws_context(args)
    
    if args.aws_context.region:
        print(f"\nAWS Context:")
        print(f"  Region: {args.aws_context.region} ({args.aws_context.detection_method})")
        if args.aws_context.account_id:
            print(f"  Account: {args.aws_context.account_id}")
    elif not args.skip_aws:
        print("\n⚠️  AWS region not detected. Use --region or --skip-aws")
    
    # Run tests
    categories = run_tests(args)
    
    # Print results
    total_categories = len(categories)
    for i, cat in enumerate(categories, 1):
        print_category(cat.name, i, total_categories)
        for result in cat.tests:
            print_result(result, args.verbose)
    
    # Print summary
    failed = print_summary(categories)
    
    # Save JSON if requested
    if args.json:
        save_json_report(categories, args.aws_context, args.json)
    
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
