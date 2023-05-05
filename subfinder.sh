#!/bin/bash

# Check if an input file has been provided
if [ -z "$1" ]; then
    echo "Error: Please provide a file containing the list of target domains."
    exit 1
fi

input_file="$1"
timestamp=$(date +%Y%m%d-%H%M%S)
subfinder_output="targets.subfinder.${timestamp}.txt"
subfinder_latest_output="targets.subfinder.latest.txt"
previous_subfinder_file="$subfinder_latest_output"

# Execute subfinder to get the list of subdomains
echo "Running subfinder to obtain subdomains..."
subfinder -list "$input_file" -o "$subfinder_output"
sort -u "$subfinder_output" "$previous_subfinder_file" > /tmp/subfinder.tmp.txt

# Display new subdomains
if [ -f "$previous_subfinder_file" ]; then
    echo "New subdomains found:"
    grep -v -F -x -f "$previous_subfinder_file" "$subfinder_output"
else
    echo "No previous subfinder output found. Here are all found subdomains:"
    cat "$subfinder_output"
fi

mv /tmp/subfinder.tmp.txt "$subfinder_output"
cp "$subfinder_output" "$subfinder_latest_output"
