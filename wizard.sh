#!/bin/bash

# Check if input file exists
if [ ! -f "targets.txt" ]; then
    echo "Input file not found: targets.txt"
    exit 1
fi

echo "Generate a list of subdomains"
bash subdomains.sh

echo "Generate a list of TCP reachable domains (not 80, 443)"
bash naabu.sh

echo "Generate a nuclei report for targets.latest.txt"
python3 nuclei.py
echo "Generate a nuclei report for naabu.latest.txt"
python3 nuclei.py naabu.latest.txt
if [ -f "targets.custom.txt" ]; then
    echo "Generate a nuclei report for targets.custom.txt"
    python3 nuclei.py targets.custom.txt
fi

echo "Merge all reports into a single report"
bash merge_all_reports.sh

echo "Display the new findings, during the last day"
python3 diff_nuclei.py --days 1
echo "...and now only the severe ones"
python3 diff_nuclei.py --severe --days 1

echo "Generate stats from the nuclei report"
python3 nuclei_report_stats.py report.nuclei.latest.txt
