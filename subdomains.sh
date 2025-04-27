#!/bin/bash

# Check if necessary directories exist. If not, create them.
if [ ! -d "targets.subfinder" ]; then
    mkdir -p "targets.subfinder"
fi

if [ ! -d "targets.amass" ]; then
    mkdir -p "targets.amass"
fi

if [ ! -d "targets.bbot" ]; then
    mkdir -p "targets.bbot"
fi

input_file="${1:-targets.txt}"

# Check if input file exists
if [ ! -f "$input_file" ]; then
    echo "Input file not found: ${input_file}"
    exit 1
fi

timestamp=$(date +%Y%m%d-%H%M%S)
subfinder_output="targets.subfinder/targets.subfinder.${timestamp}.txt"
amass_output="targets.amass/targets.amass.${timestamp}.txt"
#bbot_raw_output="targets.bbot/${timestamp}/output.csv"
#bbot_output="targets.bbot/targets.bbot.${timestamp}.txt"
subdomain_latest_output="targets.latest.txt"
previous_subdomains_file="/tmp/targets.latest.txt"
TIMEOUT=2 # in minutes

# If the latest output file exists, copy it to the temp location
if [ -f "$subdomain_latest_output" ]; then
    cp "$subdomain_latest_output" "$previous_subdomains_file"
else
    touch "$previous_subdomains_file"
fi

# Update subfinder
echo "Updating subfinder"
subfinder -up >/dev/null 2>&1

# Execute subfinder to get the list of subdomains
echo "Running subfinder to obtain subdomains from ${input_file}..."
subfinder -list "$input_file" -o "$subfinder_output"

# Execute amass to get the list of subdomains
echo "Running amass to obtain subdomains :${TIMEOUT}mn timeout..."
amass enum -df "$input_file" -passive -timeout "$TIMEOUT" -o "$amass_output"

# Execute bbot to get the list of subdomains
# echo "Running bbot to obtain subdomains :"
# bbot -t "$input_file" -n "$timestamp" -f subdomain-enum -y --modules azure_tenant certspotter crt dnscommonsrv dnsdumpster hackertarget leakix massdns otx rapiddns sslcert urlscan -o targets.bbot/
# bbot -t "$input_file" -n "$timestamp" -f subdomain-enum -y --modules azure_tenant dnscommonsrv leakix massdns sslcert urlscan -o targets.bbot/
# grep ^DNS_NAME, "$bbot_raw_output" | grep ,distance-0, | awk -F, '{print $2}' | grep -v ^_ | sort -u > "$bbot_output"

# Display new subdomains
if [ -f "$previous_subdomains_file" ]; then
    echo "New subdomains found:"
    grep -v -F -x -f "$previous_subdomains_file" "$subfinder_output"
    grep -v -F -x -f "$previous_subdomains_file" "$amass_output"
    # grep -v -F -x -f "$previous_subdomains_file" "$bbot_output"
else
    echo "No previous subdomains output found. Here are all found subdomains:"
    cat "$subfinder_output"
fi

# cat "$subfinder_output" "$amass_output" "$bbot_output" "$previous_subdomains_file" | sort -u > "$subdomain_latest_output"
cat "$subfinder_output" "$amass_output" "$previous_subdomains_file" | grep -v '^2a\.' | sort -u > "$subdomain_latest_output"
