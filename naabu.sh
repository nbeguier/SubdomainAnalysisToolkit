#!/bin/bash

INPUT_FILE="${1:-targets.latest.txt}"
OUTPUT_TMP_FILE="naabu.latest.tmp.txt"
OUTPUT_TMP2_FILE="naabu.latest.tmp2.txt"
OUTPUT_FILE="naabu.latest.txt"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Input file not found: ${INPUT_FILE}"
    exit 1
fi

# Update naabu
echo "Updating naabu"
naabu -up >/dev/null 2>&1

# Run naabu with specified ports and save the output to a temporary file
naabu -l "$INPUT_FILE" -p 21,22,25,53,8080,135,136,137,138,139,143,445,993,995,1723,3306,3389,6379,27017,5900,8443,5901,88,161,389,689,500,1812,1813,3000,4000,5000,5060,1433,1434,5432,9933,8110,8014,8107,8034,9999,15672,7777,8762 > "$OUTPUT_TMP_FILE"

# Check if temporary output file exists
if [ ! -f "$OUTPUT_TMP_FILE" ]; then
    echo "Temporary output file not found: ${OUTPUT_TMP_FILE}"
    exit 1
fi

# Extract lines containing the domain:port information and save it to the output file
grep -E ':[0-9]+$' "$OUTPUT_TMP_FILE" > "$OUTPUT_TMP2_FILE"

sort -u "$OUTPUT_TMP2_FILE" "$OUTPUT_FILE" > "$OUTPUT_TMP_FILE"
mv "$OUTPUT_TMP_FILE" "$OUTPUT_FILE"

# Print the output file name
echo "Writing file $OUTPUT_FILE"

# Remove temporary file
rm -f "$OUTPUT_TMP2_FILE"
