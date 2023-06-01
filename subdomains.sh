#!/bin/bash

# Check if necessary directories exist. If not, create them.
if [ ! -d "targets.subfinder" ]; then
    mkdir -p "targets.subfinder"
fi

if [ ! -d "targets.amass" ]; then
    mkdir -p "targets.amass"
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
subdomain_latest_output="targets.latest.txt"
previous_subdomains_file="/tmp/targets.latest.txt"
TIMEOUT=10 # in minutes

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

# Display new subdomains
if [ -f "$previous_subdomains_file" ]; then
    echo "New subdomains found:"
    grep -v -F -x -f "$previous_subdomains_file" "$subfinder_output"
    grep -v -F -x -f "$previous_subdomains_file" "$amass_output"
else
    echo "No previous subdomains output found. Here are all found subdomains:"
    cat "$subfinder_output"
fi

cat "$subfinder_output" "$amass_output" "$previous_subdomains_file" | sort -u > "$subdomain_latest_output"
