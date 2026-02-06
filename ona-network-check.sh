#!/bin/bash
#
# Ona Network Connectivity Diagnostic Tool v1.0.0 (Bash Edition)
#
# Pre-deployment connectivity checker for Ona runners. Tests required
# endpoints and validates protocol requirements (HTTP/2, WebSocket, SSL).
#
# Requirements:
# - curl (with HTTP/2 support)
# - openssl
#
# Usage:
#   ./ona-network-check.sh
#   ./ona-network-check.sh --region us-east-1 --verbose
#   ./ona-network-check.sh --scm github.com --scm gitlab.company.com
#
# Documentation: https://ona.com/docs/ona/runners/aws/detailed-access-requirements
#

set -o pipefail

VERSION="1.0.0"

# ANSI colors
GREEN="\033[92m"
RED="\033[91m"
YELLOW="\033[93m"
BLUE="\033[94m"
CYAN="\033[96m"
BOLD="\033[1m"
RESET="\033[0m"

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
WARN_TESTS=0

# Options
VERBOSE=0
REGION=""
ACCOUNT_ID=""
SKIP_AWS=0
SKIP_VSCODE=0
SKIP_JETBRAINS=0
SKIP_CURSOR=0
SKIP_MCP=0
SCM_URLS=()
SSO_URL=""
INTERNAL_REGISTRY=""
TEST_URLS=()
JSON_OUTPUT=""

# AWS Context
AWS_REGION_DETECTED=""
AWS_ACCOUNT_DETECTED=""
AWS_DETECTION_METHOD="none"

# Test results storage (for JSON export)
declare -a TEST_RESULTS_JSON=()
CURRENT_CATEGORY=""

# =============================================================================
# Helper Functions
# =============================================================================

json_escape() {
    local str="$1"
    # Escape quotes, backslashes, newlines, tabs
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\t'/\\t}"
    echo "$str"
}

store_test_result() {
    local name="$1"
    local endpoint="$2"
    local status="$3"
    local message="$4"
    local command="$5"
    local latency_ms="$6"
    local remediation_impact="$7"
    local remediation_steps="$8"
    local remediation_ref="$9"
    
    # Escape JSON strings
    name=$(json_escape "$name")
    endpoint=$(json_escape "$endpoint")
    message=$(json_escape "$message")
    command=$(json_escape "$command")
    
    # Build JSON object
    local json="{"
    json+="\"name\":\"$name\","
    json+="\"endpoint\":\"$endpoint\","
    json+="\"status\":\"$status\","
    json+="\"message\":\"$message\","
    json+="\"command\":\"$command\","
    json+="\"latency_ms\":${latency_ms:-null}"
    
    # Add remediation if provided
    if [ -n "$remediation_impact" ]; then
        remediation_impact=$(json_escape "$remediation_impact")
        remediation_ref=$(json_escape "$remediation_ref")
        json+=",\"remediation\":{"
        json+="\"impact\":\"$remediation_impact\","
        json+="\"steps\":["
        
        # Parse steps (separated by |)
        IFS='|' read -ra STEPS <<< "$remediation_steps"
        local first=1
        for step in "${STEPS[@]}"; do
            [ $first -eq 0 ] && json+=","
            step=$(json_escape "$step")
            json+="\"$step\""
            first=0
        done
        
        json+="],\"reference\":\"$remediation_ref\"}"
    else
        json+=",\"remediation\":null"
    fi
    
    json+="}"
    
    TEST_RESULTS_JSON+=("$json")
}

print_header() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BOLD}$1${RESET}"
    echo "──────────────────────────────────────────────────────────────────"
    CURRENT_CATEGORY="$1"
}

print_test() {
    local name="$1"
    local status="$2"
    local message="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    case "$status" in
        pass)
            echo -e "  ${GREEN}✅${RESET} $name ${message}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            ;;
        fail)
            echo -e "  ${RED}❌${RESET} $name ${message}"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            ;;
        warn)
            echo -e "  ${YELLOW}⚠️${RESET}  $name ${message}"
            WARN_TESTS=$((WARN_TESTS + 1))
            ;;
    esac
}

print_remediation() {
    local impact="$1"
    shift
    local steps=("$@")
    
    echo -e "    ${YELLOW}Impact:${RESET} $impact"
    echo -e "    ${YELLOW}Steps:${RESET}"
    for step in "${steps[@]}"; do
        echo "      • $step"
    done
}

# =============================================================================
# Test Functions
# =============================================================================

test_endpoint() {
    local url="$1"
    local allow_4xx="${2:-false}"
    local timeout="${3:-10}"
    local remediation_impact="$4"
    local remediation_steps="$5"
    local remediation_ref="$6"
    
    local cmd="curl -s -o /dev/null -w \"%{http_code} %{time_total}\" --connect-timeout $timeout $url"
    local response
    response=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" \
                    --connect-timeout "$timeout" "$url" 2>&1)
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        print_test "$url" "fail" "(connection failed)"
        store_test_result "$url" "$url" "fail" "connection failed" "$cmd" "null" \
            "$remediation_impact" "$remediation_steps" "$remediation_ref"
        [ "$VERBOSE" -eq 1 ] && echo "    curl exit code: $exit_code"
        return 1
    fi
    
    local http_code=$(echo "$response" | awk '{print $1}')
    local latency=$(echo "$response" | awk '{print $2}')
    local latency_ms=$(echo "$latency * 1000" | bc 2>/dev/null || echo "null")
    
    if [[ "$http_code" =~ ^2 ]] || [[ "$http_code" =~ ^3 ]]; then
        print_test "$url" "pass" "(${http_code} OK, ${latency_ms}ms)"
        store_test_result "$url" "$url" "pass" "${http_code} OK" "$cmd" "$latency_ms" "" "" ""
        return 0
    elif [ "$allow_4xx" = "true" ] && [[ "$http_code" =~ ^4 ]]; then
        print_test "$url" "pass" "(reachable, ${http_code}, ${latency_ms}ms)"
        store_test_result "$url" "$url" "pass" "reachable, ${http_code}" "$cmd" "$latency_ms" "" "" ""
        return 0
    else
        print_test "$url" "fail" "(HTTP ${http_code})"
        store_test_result "$url" "$url" "fail" "HTTP ${http_code}" "$cmd" "$latency_ms" \
            "$remediation_impact" "$remediation_steps" "$remediation_ref"
        return 1
    fi
}

test_http2() {
    local url="${1:-https://app.gitpod.io}"
    local cmd="curl --http2 -I -s -o /dev/null -w \"%{http_version}\" $url"
    
    local http_version
    http_version=$(curl --http2 -I -s -o /dev/null -w "%{http_version}" "$url" 2>&1)
    local exit_code=$?
    
    local remediation_steps="Contact your Zscaler/proxy admin|Enable HTTP/2 for SSL-inspected traffic|Location: Administration > Advanced Settings"
    
    if [ $exit_code -ne 0 ]; then
        print_test "HTTP/2 Support" "fail" "(connection failed)"
        store_test_result "HTTP/2 Support" "$url" "fail" "connection failed" "$cmd" "null" \
            "CLI failures, connection timeouts, protocol errors" \
            "$remediation_steps" \
            "https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
        print_remediation "CLI failures, connection timeouts, protocol errors" \
            "Contact your Zscaler/proxy admin" \
            "Enable HTTP/2 for SSL-inspected traffic" \
            "Location: Administration > Advanced Settings"
        return 1
    fi
    
    if [[ "$http_version" == "2" ]]; then
        print_test "HTTP/2 Support" "pass" "(HTTP/2 enabled)"
        store_test_result "HTTP/2 Support" "$url" "pass" "HTTP/2 enabled" "$cmd" "null" "" "" ""
        return 0
    else
        print_test "HTTP/2 Support" "fail" "(HTTP/$http_version detected)"
        store_test_result "HTTP/2 Support" "$url" "fail" "HTTP/$http_version detected" "$cmd" "null" \
            "CLI failures, connection timeouts, protocol errors" \
            "$remediation_steps" \
            "https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
        print_remediation "CLI failures, connection timeouts, protocol errors" \
            "Contact your Zscaler/proxy admin" \
            "Enable HTTP/2 for SSL-inspected traffic"
        return 1
    fi
}

test_ssl_certificate() {
    local url="${1:-app.gitpod.io}"
    local cmd="echo | openssl s_client -connect $url:443 -servername $url"
    
    local output
    output=$(echo | openssl s_client -connect "$url:443" -servername "$url" 2>&1)
    local exit_code=$?
    
    local zscaler_remediation="Add $url to SSL inspection bypass list|Alternative: Enable 'System certificates' in VS Code (v1.97+)"
    local general_remediation="Check if corporate proxy is intercepting SSL|Install corporate CA certificates if required|Verify system time is correct"
    
    if [ $exit_code -ne 0 ]; then
        print_test "SSL Certificate" "fail" "(connection failed)"
        store_test_result "SSL Certificate" "$url" "fail" "connection failed" "$cmd" "null" \
            "SSL/TLS errors, certificate validation failures" \
            "$general_remediation" \
            "https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
        return 1
    fi
    
    # Check for SSL interception by examining the certificate issuer
    local issuer
    issuer=$(echo "$output" | grep "issuer=" | head -1)
    
    # Known SSL intercepting proxies
    if echo "$issuer" | grep -qi "zscaler\|palo alto\|fortinet\|blue coat\|symantec"; then
        print_test "SSL Certificate" "fail" "(SSL interception detected)"
        store_test_result "SSL Certificate" "$url" "fail" "SSL interception detected" "$cmd" "null" \
            "VS Code can't connect, certificate verify failed errors" \
            "$zscaler_remediation" \
            "https://ona.com/docs/ona/runners/aws/troubleshooting-zscaler"
        print_remediation "VS Code can't connect, certificate verify failed errors" \
            "Add $url to SSL inspection bypass list" \
            "Alternative: Enable 'System certificates' in VS Code (v1.97+)" \
            "https://ona.com/docs/ona/runners/aws/troubleshooting-zscaler"
        return 1
    fi
    
    # Check if certificate is valid
    if echo "$output" | grep -q "Verify return code: 0 (ok)"; then
        # Check for known good issuers
        if echo "$issuer" | grep -qi "amazon\|digicert\|let's encrypt\|google"; then
            print_test "SSL Certificate" "pass" "(Certificate issuer verified, not intercepted)"
            store_test_result "SSL Certificate" "$url" "pass" "Certificate issuer verified" "$cmd" "null" "" "" ""
        else
            print_test "SSL Certificate" "warn" "(Unknown issuer)"
            store_test_result "SSL Certificate" "$url" "warn" "Unknown issuer" "$cmd" "null" "" "" ""
        fi
        return 0
    else
        local error=$(echo "$output" | grep "Verify return code:" | head -1)
        print_test "SSL Certificate" "fail" "($error)"
        store_test_result "SSL Certificate" "$url" "fail" "$error" "$cmd" "null" \
            "SSL/TLS errors, certificate validation failures" \
            "$general_remediation" \
            "https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
        print_remediation "SSL/TLS errors, certificate validation failures" \
            "Check if corporate proxy is intercepting SSL" \
            "Install corporate CA certificates if required" \
            "Verify system time is correct"
        return 1
    fi
}

test_websocket() {
    local url="${1:-wss://app.gitpod.io}"
    local https_url="${url/wss:/https:}"
    local cmd="curl -s -o /dev/null -w \"%{http_code}\" --connect-timeout 10 -H \"Connection: Upgrade\" -H \"Upgrade: websocket\" $https_url"
    
    # WebSocket test using curl (basic check)
    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" \
                    --connect-timeout 10 \
                    -H "Connection: Upgrade" \
                    -H "Upgrade: websocket" \
                    "$https_url" 2>&1)
    local exit_code=$?
    
    local remediation_steps="Contact your proxy/firewall admin|Enable WebSocket protocol (ws:// and wss://)|Ensure proxy doesn't block Upgrade headers"
    
    if [ $exit_code -ne 0 ]; then
        print_test "WebSocket Support" "fail" "(connection failed)"
        store_test_result "WebSocket Support" "$url" "fail" "connection failed" "$cmd" "null" \
            "IDE won't load, terminal won't work" \
            "$remediation_steps" \
            "https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
        print_remediation "IDE won't load, terminal won't work" \
            "Contact your proxy/firewall admin" \
            "Enable WebSocket protocol (ws:// and wss://)" \
            "Ensure proxy doesn't block Upgrade headers"
        return 1
    fi
    
    # 101 = Switching Protocols (ideal)
    # 200 = endpoint exists, responded
    # 400 = Bad Request (endpoint exists, rejected malformed WS request)
    # 426 = Upgrade Required (endpoint exists, wants different protocol)
    # Any of these means the endpoint is reachable and responding
    if [[ "$response" == "101" || "$response" == "200" || "$response" == "400" || "$response" == "426" ]]; then
        print_test "WebSocket Support" "pass" "(WebSocket upgrade supported)"
        store_test_result "WebSocket Support" "$url" "pass" "WebSocket upgrade supported" "$cmd" "null" "" "" ""
        return 0
    else
        print_test "WebSocket Support" "fail" "(HTTP $response, WebSocket blocked)"
        store_test_result "WebSocket Support" "$url" "fail" "HTTP $response, WebSocket blocked" "$cmd" "null" \
            "Real-time features won't work, environment status updates will fail" \
            "$remediation_steps" \
            "https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
        print_remediation "Real-time features won't work, environment status updates will fail" \
            "Contact your proxy/firewall admin" \
            "Enable WebSocket protocol (ws:// and wss://)" \
            "Ensure proxy doesn't block Upgrade headers"
        return 1
    fi
}

# =============================================================================
# Endpoint Lists
# =============================================================================

get_ona_endpoints() {
    echo "https://app.gitpod.io"
    echo "https://app.ona.com"
}

get_vscode_endpoints() {
    # Note: vscode.download.prss.microsoft.com returns 403 on root, but is reachable
    echo "https://update.code.visualstudio.com"
    echo "https://marketplace.visualstudio.com"
    echo "https://vscode.gitpod.io"
}

get_jetbrains_endpoints() {
    # Only include endpoints that return valid responses on root path
    echo "https://www.jetbrains.com"
    echo "https://download.jetbrains.com"
    echo "https://plugins.jetbrains.com"
    echo "https://account.jetbrains.com"
}

get_release_endpoints() {
    echo "https://releases.gitpod.io/ec2/stable/manifest.json"
    echo "https://releases.gitpod.io/cli/stable/manifest.json"
}

get_registry_endpoints() {
    echo "https://mcr.microsoft.com"
    echo "https://index.docker.io"
    echo "https://ghcr.io"
    echo "https://gcr.io"
}

get_cursor_endpoints() {
    echo "https://cursor.blob.core.windows.net"
}

get_mcp_endpoints() {
    echo "https://api.linear.app"
    echo "https://api.notion.com"
    echo "https://api.figma.com"
    echo "https://sentry.io"
}

get_aws_endpoints() {
    local region="$1"
    local services=(
        "ec2" "s3" "ssm" "sts" "ecs" "logs" "secretsmanager"
        "autoscaling" "kms" "firehose" "eks" "cloudformation"
        "elasticloadbalancing" "ecr.api" "ssmmessages" "ec2messages"
    )
    
    for svc in "${services[@]}"; do
        echo "https://${svc}.${region}.amazonaws.com"
    done
}

# =============================================================================
# AWS Context Detection
# =============================================================================

detect_aws_context() {
    # Check CLI argument (already set via REGION variable)
    if [ -n "$REGION" ]; then
        AWS_REGION_DETECTED="$REGION"
        AWS_DETECTION_METHOD="cli_argument"
    # Check environment variables
    elif [ -n "$AWS_REGION" ]; then
        AWS_REGION_DETECTED="$AWS_REGION"
        AWS_DETECTION_METHOD="environment_variable"
    elif [ -n "$AWS_DEFAULT_REGION" ]; then
        AWS_REGION_DETECTED="$AWS_DEFAULT_REGION"
        AWS_DETECTION_METHOD="environment_variable"
    else
        # Try EC2 instance metadata
        local metadata
        metadata=$(curl -s --connect-timeout 2 \
                        http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$metadata" ] && [[ ! "$metadata" =~ ^\<\? ]]; then
            AWS_REGION_DETECTED="$metadata"
            AWS_DETECTION_METHOD="instance_metadata"
        fi
    fi
    
    # Try to get account ID if not provided
    if [ -z "$ACCOUNT_ID" ]; then
        local account
        account=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$account" ]; then
            AWS_ACCOUNT_DETECTED="$account"
        fi
    else
        AWS_ACCOUNT_DETECTED="$ACCOUNT_ID"
    fi
}

# =============================================================================
# Interactive Prompts
# =============================================================================

prompt_for_scm() {
    echo ""
    echo "──────────────────────────────────────────────────────────────────"
    echo "Source Control Configuration"
    echo "──────────────────────────────────────────────────────────────────"
    echo ""
    echo "Which source control provider(s) does your organization use?"
    echo "  1. GitHub (github.com)"
    echo "  2. GitHub Enterprise (self-hosted)"
    echo "  3. GitLab (gitlab.com)"
    echo "  4. GitLab Self-Managed"
    echo "  5. Bitbucket Cloud (bitbucket.org)"
    echo "  6. Azure DevOps (dev.azure.com)"
    echo "  7. Other / Custom"
    echo "  8. Skip SCM tests"
    echo ""
    
    read -p "Enter choice (1-8), or comma-separated for multiple (e.g., 1,4): " choice
    choice=${choice:-1}  # Default to GitHub
    
    IFS=',' read -ra choices <<< "$choice"
    
    local scm_list=()
    for c in "${choices[@]}"; do
        c=$(echo "$c" | xargs)  # trim whitespace
        case "$c" in
            1) scm_list+=("github.com") ;;
            2) 
                read -p "  Enter GitHub Enterprise URL (e.g., github.mycompany.com): " url
                [ -n "$url" ] && scm_list+=("$url")
                ;;
            3) scm_list+=("gitlab.com") ;;
            4)
                read -p "  Enter GitLab URL (e.g., gitlab.mycompany.com): " url
                [ -n "$url" ] && scm_list+=("$url")
                ;;
            5) scm_list+=("bitbucket.org") ;;
            6) scm_list+=("dev.azure.com") ;;
            7)
                read -p "  Enter custom SCM URL: " url
                [ -n "$url" ] && scm_list+=("$url")
                ;;
            8) 
                echo "  Skipping SCM tests."
                return
                ;;
        esac
    done
    
    if [ ${#scm_list[@]} -eq 0 ]; then
        echo "  No SCM specified, using default: github.com"
        scm_list=("github.com")
    fi
    
    echo ""
    echo "  Testing: ${scm_list[*]}"
    echo ""
    
    SCM_URLS=("${scm_list[@]}")
}

prompt_for_internal_registry() {
    echo ""
    echo "──────────────────────────────────────────────────────────────────"
    echo "Internal Container Registry Configuration"
    echo "──────────────────────────────────────────────────────────────────"
    echo ""
    echo "Does your organization host container images internally?"
    echo "  1. JFrog Artifactory"
    echo "  2. Nexus Repository"
    echo "  3. Harbor"
    echo "  4. AWS ECR (private)"
    echo "  5. Other internal registry"
    echo "  6. No / Use public registries only"
    echo ""
    
    read -p "Enter choice (1-6): " choice
    
    case "$choice" in
        1)
            read -p "  Enter Artifactory URL (e.g., artifactory.mycompany.com): " url
            [ -n "$url" ] && INTERNAL_REGISTRY="$url"
            ;;
        2)
            read -p "  Enter Nexus URL (e.g., nexus.mycompany.com): " url
            [ -n "$url" ] && INTERNAL_REGISTRY="$url"
            ;;
        3)
            read -p "  Enter Harbor URL (e.g., harbor.mycompany.com): " url
            [ -n "$url" ] && INTERNAL_REGISTRY="$url"
            ;;
        4)
            read -p "  Enter ECR URL (e.g., 123456789.dkr.ecr.us-east-1.amazonaws.com): " url
            [ -n "$url" ] && INTERNAL_REGISTRY="$url"
            ;;
        5)
            read -p "  Enter registry URL: " url
            [ -n "$url" ] && INTERNAL_REGISTRY="$url"
            ;;
        6|"")
            echo "  Using public registries only."
            return
            ;;
    esac
    
    # Add https:// if not present
    if [ -n "$INTERNAL_REGISTRY" ] && [[ ! "$INTERNAL_REGISTRY" =~ ^http ]]; then
        INTERNAL_REGISTRY="https://$INTERNAL_REGISTRY"
    fi
    
    [ -n "$INTERNAL_REGISTRY" ] && echo "" && echo "  Testing: $INTERNAL_REGISTRY" && echo ""
}

prompt_for_sso() {
    echo ""
    echo "──────────────────────────────────────────────────────────────────"
    echo "SSO Provider Configuration"
    echo "──────────────────────────────────────────────────────────────────"
    echo ""
    echo "Does your organization use an SSO provider for Ona authentication?"
    echo "  1. Okta"
    echo "  2. Azure AD / Entra ID"
    echo "  3. Google Workspace"
    echo "  4. Other SSO provider"
    echo "  5. No SSO / Skip SSO tests"
    echo ""
    
    read -p "Enter choice (1-5): " choice
    
    case "$choice" in
        1)
            read -p "  Enter Okta domain (e.g., mycompany.okta.com): " url
            [ -n "$url" ] && SSO_URL="$url"
            ;;
        2)
            read -p "  Enter Azure AD tenant URL (e.g., login.microsoftonline.com/tenant-id): " url
            [ -n "$url" ] && SSO_URL="$url"
            ;;
        3)
            SSO_URL="accounts.google.com"
            ;;
        4)
            read -p "  Enter SSO provider URL: " url
            [ -n "$url" ] && SSO_URL="$url"
            ;;
        5|"")
            echo "  Skipping SSO tests."
            return
            ;;
    esac
    
    # Add https:// if not present
    if [ -n "$SSO_URL" ] && [[ ! "$SSO_URL" =~ ^http ]]; then
        SSO_URL="https://$SSO_URL"
    fi
    
    [ -n "$SSO_URL" ] && echo "" && echo "  Testing: $SSO_URL" && echo ""
}

# =============================================================================
# Main Test Runner
# =============================================================================

run_tests() {
    # Protocol validation
    print_header "Protocol Validation"
    test_http2
    test_ssl_certificate
    test_websocket
    
    # Ona Management Plane
    print_header "Ona Management Plane"
    local remediation_steps="Add app.gitpod.io to firewall allowlist"
    local remediation_ref="https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
    while IFS= read -r url; do
        test_endpoint "$url" "false" "10" "Cannot connect to Ona platform" "$remediation_steps" "$remediation_ref"
    done < <(get_ona_endpoints)
    
    # VS Code
    if [ "$SKIP_VSCODE" -eq 0 ]; then
        print_header "VS Code Endpoints"
        while IFS= read -r url; do
            test_endpoint "$url"
        done < <(get_vscode_endpoints)
    fi
    
    # JetBrains
    if [ "$SKIP_JETBRAINS" -eq 0 ]; then
        print_header "JetBrains Endpoints"
        while IFS= read -r url; do
            test_endpoint "$url"
        done < <(get_jetbrains_endpoints)
    fi
    
    # Release artifacts
    print_header "Release Artifacts"
    while IFS= read -r url; do
        test_endpoint "$url"
    done < <(get_release_endpoints)
    
    # Container registries
    print_header "Container Registries"
    while IFS= read -r url; do
        test_endpoint "$url"
    done < <(get_registry_endpoints)
    
    # Internal container registry
    if [ -z "$INTERNAL_REGISTRY" ]; then
        prompt_for_internal_registry
    fi
    
    if [ -n "$INTERNAL_REGISTRY" ]; then
        print_header "Internal Container Registry"
        local remediation_steps="Verify the registry URL is correct|Ensure the registry is accessible from this network|Check if VPN or private link is required|Verify firewall allows outbound to registry"
        local remediation_ref="https://ona.com/docs/ona/runners/aws/detailed-access-requirements#container-registries"
        test_endpoint "$INTERNAL_REGISTRY" "true" "10" "Cannot pull container images from internal registry" "$remediation_steps" "$remediation_ref"
    fi
    
    # Cursor editor endpoints
    if [ "$SKIP_CURSOR" -eq 0 ]; then
        print_header "Cursor Editor"
        local remediation_steps="Add cursor.blob.core.windows.net to firewall allowlist|Ensure HTTPS (port 443) outbound is permitted"
        local remediation_ref="https://ona.com/docs/ona/editors/cursor"
        while IFS= read -r url; do
            test_endpoint "$url" "false" "10" "Cursor editor remote server won't download" "$remediation_steps" "$remediation_ref"
        done < <(get_cursor_endpoints)
    fi
    
    # MCP integration endpoints
    if [ "$SKIP_MCP" -eq 0 ]; then
        print_header "MCP Integrations"
        local remediation_steps="Add this domain to firewall allowlist|Ensure HTTPS (port 443) outbound is permitted"
        local remediation_ref="https://ona.com/docs/ona/integrations/mcp"
        while IFS= read -r url; do
            test_endpoint "$url" "true" "10" "MCP integrations won't work for this service" "$remediation_steps" "$remediation_ref"
        done < <(get_mcp_endpoints)
    fi
    
    # AWS Services
    if [ "$SKIP_AWS" -eq 0 ]; then
        if [ -n "$AWS_REGION_DETECTED" ]; then
            print_header "AWS Services (Region: $AWS_REGION_DETECTED)"
            local remediation_steps="Configure VPC endpoints for AWS services, OR|Ensure NAT gateway allows outbound to AWS service endpoints"
            local remediation_ref="https://ona.com/docs/ona/runners/aws/vpc-endpoints"
            while IFS= read -r url; do
                test_endpoint "$url" "true" "10" "Runner deployment will fail, AWS resources won't be accessible" "$remediation_steps" "$remediation_ref"
            done < <(get_aws_endpoints "$AWS_REGION_DETECTED")
        else
            echo ""
            echo "ℹ️  AWS region not detected. Use --region to test AWS endpoints."
        fi
    fi
    
    # SCM Providers
    if [ ${#SCM_URLS[@]} -eq 0 ]; then
        prompt_for_scm
    fi
    
    if [ ${#SCM_URLS[@]} -gt 0 ]; then
        print_header "SCM Providers"
        for scm in "${SCM_URLS[@]}"; do
            local url="$scm"
            [[ ! "$url" =~ ^http ]] && url="https://$url"
            test_endpoint "$url"
            
            # Test API endpoints for known providers
            if [[ "$scm" == *"github.com"* ]]; then
                test_endpoint "https://api.github.com"
            elif [[ "$scm" == *"gitlab"* ]]; then
                local api_url="$url/api/v4/projects"
                test_endpoint "$api_url" "true"
            elif [[ "$scm" == *"bitbucket"* ]]; then
                test_endpoint "https://api.bitbucket.org"
            fi
        done
    fi
    
    # SSO Provider
    if [ -z "$SSO_URL" ]; then
        prompt_for_sso
    fi
    
    if [ -n "$SSO_URL" ]; then
        print_header "SSO Provider"
        local remediation_steps="Add SSO provider domain to firewall allowlist|Ensure HTTPS (port 443) outbound is permitted|Check if proxy allows connections to SSO provider"
        local remediation_ref="https://ona.com/docs/ona/sso/overview"
        test_endpoint "$SSO_URL" "true" "10" "Users won't be able to authenticate via SSO" "$remediation_steps" "$remediation_ref"
    fi
    
    # Custom URLs
    if [ ${#TEST_URLS[@]} -gt 0 ]; then
        print_header "Custom URLs"
        for url in "${TEST_URLS[@]}"; do
            [[ ! "$url" =~ ^http ]] && url="https://$url"
            local remediation_steps="Verify the URL is correct|Add this domain to firewall allowlist|Check if VPN or private link is required"
            local remediation_ref="https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
            test_endpoint "$url" "true" "10" "This URL is not reachable from this network" "$remediation_steps" "$remediation_ref"
        done
    fi
}

# =============================================================================
# JSON Report Generation
# =============================================================================

save_json_report() {
    local filepath="$1"
    
    # Get timestamp in ISO 8601 format
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Start JSON document
    cat > "$filepath" << EOF
{
  "version": "$VERSION",
  "timestamp": "$timestamp",
  "aws_context": {
    "region": $([ -n "$AWS_REGION_DETECTED" ] && echo "\"$AWS_REGION_DETECTED\"" || echo "null"),
    "account_id": $([ -n "$AWS_ACCOUNT_DETECTED" ] && echo "\"$AWS_ACCOUNT_DETECTED\"" || echo "null"),
    "detection_method": "$AWS_DETECTION_METHOD"
  },
  "summary": {
    "total": $TOTAL_TESTS,
    "passed": $PASSED_TESTS,
    "failed": $FAILED_TESTS,
    "warnings": $WARN_TESTS
  },
  "tests": [
EOF
    
    # Add test results
    local first=1
    for result in "${TEST_RESULTS_JSON[@]}"; do
        if [ $first -eq 0 ]; then
            echo "," >> "$filepath"
        fi
        echo "    $result" >> "$filepath"
        first=0
    done
    
    # Close JSON document
    cat >> "$filepath" << EOF

  ]
}
EOF
    
    echo ""
    echo "JSON report saved to: $filepath"
}

# =============================================================================
# Summary
# =============================================================================

print_summary() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "\n${BOLD}Summary${RESET}"
    echo "──────────────────────────────────────────────────────────────────"
    echo ""
    echo "Total tests: $TOTAL_TESTS"
    echo "  ✅ Passed: $PASSED_TESTS"
    echo "  ❌ Failed: $FAILED_TESTS"
    echo "  ⚠️  Warnings: $WARN_TESTS"
    echo ""
    
    if [ "$FAILED_TESTS" -gt 0 ]; then
        echo "Failed tests require attention before runner deployment."
        echo "See remediation steps above for each failure."
    else
        echo "✅ All tests passed! Ready for runner deployment."
    fi
    
    echo ""
    echo "Documentation: https://ona.com/docs/ona/runners/aws/detailed-access-requirements"
    echo ""
}

# =============================================================================
# Argument Parsing
# =============================================================================

usage() {
    cat << EOF
Ona Network Connectivity Diagnostic Tool v$VERSION

Usage: $0 [OPTIONS]

Options:
  --region REGION          AWS region (e.g., us-east-1)
  --account-id ID          AWS account ID
  --scm URL                SCM provider URL (can be specified multiple times)
  --sso URL                SSO provider URL (e.g., mycompany.okta.com)
  --internal-registry URL  Internal container registry URL
  --test-url URL           Additional URL to test (can be specified multiple times)
  --skip-aws               Skip AWS endpoint tests
  --skip-vscode            Skip VS Code endpoint tests
  --skip-jetbrains         Skip JetBrains endpoint tests
  --skip-cursor            Skip Cursor editor endpoint tests
  --skip-mcp               Skip MCP integration tests (Linear, Notion, Figma, Sentry)
  --json FILE              Save results to JSON file
  --verbose                Enable verbose output
  --help                   Show this help message

Examples:
  $0
  $0 --region us-east-1 --verbose
  $0 --scm github.com --scm gitlab.company.com
  $0 --sso mycompany.okta.com --json report.json

EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --region)
            REGION="$2"
            shift 2
            ;;
        --account-id)
            ACCOUNT_ID="$2"
            shift 2
            ;;
        --scm)
            SCM_URLS+=("$2")
            shift 2
            ;;
        --sso)
            SSO_URL="$2"
            [[ ! "$SSO_URL" =~ ^http ]] && SSO_URL="https://$SSO_URL"
            shift 2
            ;;
        --internal-registry)
            INTERNAL_REGISTRY="$2"
            [[ ! "$INTERNAL_REGISTRY" =~ ^http ]] && INTERNAL_REGISTRY="https://$INTERNAL_REGISTRY"
            shift 2
            ;;
        --test-url)
            TEST_URLS+=("$2")
            shift 2
            ;;
        --skip-aws)
            SKIP_AWS=1
            shift
            ;;
        --skip-vscode)
            SKIP_VSCODE=1
            shift
            ;;
        --skip-jetbrains)
            SKIP_JETBRAINS=1
            shift
            ;;
        --skip-cursor)
            SKIP_CURSOR=1
            shift
            ;;
        --skip-mcp)
            SKIP_MCP=1
            shift
            ;;
        --json)
            JSON_OUTPUT="$2"
            shift 2
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
        --help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# =============================================================================
# Main
# =============================================================================

main() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BOLD}Ona Network Connectivity Diagnostic Tool v$VERSION${RESET}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}Error: curl is not installed${RESET}"
        exit 1
    fi
    
    if ! command -v openssl &> /dev/null; then
        echo -e "${RED}Error: openssl is not installed${RESET}"
        exit 1
    fi
    
    # Detect AWS context
    detect_aws_context
    
    if [ -n "$AWS_REGION_DETECTED" ]; then
        echo ""
        echo "AWS region: $AWS_REGION_DETECTED (detected via $AWS_DETECTION_METHOD)"
        [ -n "$AWS_ACCOUNT_DETECTED" ] && echo "AWS account: $AWS_ACCOUNT_DETECTED"
    elif [ "$SKIP_AWS" -eq 0 ]; then
        echo ""
        echo "⚠️  AWS region not detected. Use --region or --skip-aws"
    fi
    
    # Run tests
    run_tests
    
    # Print summary
    print_summary
    
    # Save JSON report if requested
    if [ -n "$JSON_OUTPUT" ]; then
        save_json_report "$JSON_OUTPUT"
    fi
    
    # Exit with appropriate code
    [ "$FAILED_TESTS" -gt 0 ] && exit 1 || exit 0
}

main
