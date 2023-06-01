#!/usr/bin/env python3

import sys
import re
import subprocess

# Define color codes
COLOR_RED = '\033[91m'
COLOR_GREEN = '\033[92m'
COLOR_ORANGE = '\033[93m'
COLOR_RESET = '\033[0m'

INPUT_FILE = sys.argv[1] if len(sys.argv) > 1 else 'report.nuclei.latest.txt'
REPORT = '/tmp/report.without_info.txt'

# Read the input file and filter lines not containing '[info]'
with open(INPUT_FILE, 'r', encoding='utf-8') as input_f, open(REPORT, 'w', encoding='utf-8') as report_f:
    for line in input_f:
        if '[info]' not in line:
            report_f.write(line)

# Process each line in the report file
with open(REPORT, 'r', encoding='utf-8') as report_f:
    for line in report_f:
        line = line.strip()
        category = re.findall(r'\[(.*?)\]', line)[0].split(':')[0]
        target = line.split()[3]
        if target.startswith('http'):
            target = target.split('/')[2]

        # Execute the nuclei command
        completed_process = subprocess.run(['nuclei', '-silent', '-id', category, '-u', target], capture_output=True, text=True)
        nuclei_output = completed_process.stdout.strip()

        # Remove bash color codes from nuclei_output
        color_pattern = re.compile(r'\x1b\[[0-9;]+m')
        nuclei_output = re.sub(color_pattern, '', nuclei_output)

        if nuclei_output == line:
            print(f'{COLOR_RED}NOT FIX: {nuclei_output}{COLOR_RESET}')
        elif nuclei_output:
            print(f'{COLOR_ORANGE}NOT FIX (DIFFERENT): {nuclei_output}{COLOR_RESET}')
        else:
            print(f'{COLOR_GREEN}FIX!: {line}{COLOR_RESET}')
