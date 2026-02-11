#!/bin/bash

TARGETS_FILE="targets.latest.txt"
SOCKS_PROXY="socks5://127.0.0.1:9050"
DOMAIN_FILTER=""
INFO_ONLY=false
XML=false
NO_COLOR=false

# Function to parse arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                DOMAIN_FILTER="$2"
                shift 2
                ;;
            --info-only)
                INFO_ONLY=true
                shift
                ;;
            --xml)
                XML=true
                shift
                ;;
            --no-color)
                NO_COLOR=true
                shift
                ;;
            -*|--*)
                echo "Unknown option $1"
                exit 1
                ;;
            *)
                TARGETS_FILE="$1"
                shift
                ;;
        esac
    done
}

# Function to check if the SOCKS5 proxy is running
check_proxy() {
    echo "[*] Checking SOCKS5 proxy at $SOCKS_PROXY..."
    if curl --socks5-hostname 127.0.0.1:9050 -s --connect-timeout 5 https://ifconfig.io > /dev/null; then
        echo "[+] SOCKS5 proxy is active."
        echo -n "[+] Current IP via proxy: "
        curl --socks5-hostname 127.0.0.1:9050 -s https://ifconfig.io
        USE_PROXY=true
    else
        echo "[-] SOCKS5 proxy not detected. Proceeding without proxy."
        echo -n "[+] Current IP without proxy: "
        curl -s https://ifconfig.io
        USE_PROXY=false
    fi
}

# Function to update Nuclei and its templates
update_tools() {
    echo "[*] Updating HTTPx, DNSx, Nuclei and templates..."
    httpx -silent -up 2>/dev/null
    dnsx -silent -up 2>/dev/null
    nuclei -silent -ut 2>/dev/null
    nuclei -silent -up 2>/dev/null
}

# Function to run Nuclei scans for each severity level
run_severity_scans() {
    if [ ! -f "$TARGETS_FILE" ]; then
        echo "[-] Target file '$TARGETS_FILE' not found!"
        exit 1
    fi

    # If a domain filter is specified, filter targets
    if [ -n "$DOMAIN_FILTER" ]; then
        echo "[*] Filtering targets for domain: $DOMAIN_FILTER"
        grep "\.${DOMAIN_FILTER}$" "$TARGETS_FILE" > filtered_targets.txt
        FINAL_TARGETS="filtered_targets.txt"
    else
        FINAL_TARGETS="$TARGETS_FILE"
    fi

    TARGET_COUNT=$(wc -l < "$FINAL_TARGETS")
    echo "[*] Starting Nuclei scans on $TARGET_COUNT targets..."

    if [ "$INFO_ONLY" = true ]; then
        SEVERITIES=("info")
    else
        SEVERITIES=("critical" "high" "medium" "low" "info")
    fi

    PROTOCOLS=("dns" "file" "http" "headless" "tcp" "workflow" "ssl" "websocket" "whois" "code" "javascript")

    for severity in "${SEVERITIES[@]}"; do
        echo "[*] Severity: $severity"
        for proto in "${PROTOCOLS[@]}"; do
            echo "    [*] Protocol: $proto"
            template_count=$(nuclei -silent -tl -severity "$severity" -type "$proto" | wc -l)
            if [ "$template_count" -eq 0 ]; then
                continue
            fi
            echo "    [+] Found $template_count templates for severity: $severity and protocol: $proto"
            CMD=(nuclei -l "$FINAL_TARGETS" -type "$proto" -severity "$severity" -page-timeout 3 -timeout 3 -concurrency 10 -bulk-size 10 -rate-limit 100 -silent -stats -mp 9092)

            if [ "$USE_PROXY" = true ]; then
                CMD+=(-p "$SOCKS_PROXY")
            fi

            if [ "$NO_COLOR" = true ]; then
                CMD+=(-no-color)
            fi

            if [ "$XML" = true ]; then
                CMD+=(-p "$SOCKS_PROXY")
            fi

            "${CMD[@]}" 2>/dev/null
        done
    done
}

# Main execution flow
parse_arguments "$@"
check_proxy
update_tools
run_severity_scans
