#!/usr/bin/env python
"""
A script to perform a scan using httpx and nuclei, with options to exclude
certain templates and specify an input file containing targets.
"""

import argparse
import subprocess
from datetime import datetime
from pathlib import Path
import tempfile

from settings import nuclei_exclude_templates, nuclei_target_blacklist

# Debug
from pdb import set_trace as st

def main(input_file: str):
    """
    Run httpx and nuclei with the given input file, and store the output in a report file.
    """
    if not Path(input_file).exists():
        print(f"Input file '{input_file}' not found. Exiting.")
        return

    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    nuclei_output = f'reports/report.nuclei.{timestamp}.txt'
    nuclei_tmp_output = 'report.nuclei.tmp.txt'

    # Update nuclei
    print('Updating httpx and nuclei')
    subprocess.run(['httpx', '-silent', '-up'])
    subprocess.run(['nuclei', '-silent', '-up'])
    subprocess.run(['nuclei', '-silent', '-ut'])

    # Execute httpx and nuclei to perform the scan
    print(f'Launching httpx and nuclei to perform the scan... ({nuclei_tmp_output})')
    try:
        with open(input_file, encoding='utf-8') as targets:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                for target in targets:
                    if target.strip() not in nuclei_target_blacklist:
                        temp.write(target)
                temp.flush()
        with open(temp.name, 'r', encoding='utf-8') as temp_in:
            httpx_process = subprocess.Popen(
                ['httpx', '-silent'],
                stdin=temp_in,
                stdout=subprocess.PIPE)
            nuclei_process = subprocess.Popen(
                ['nuclei', '-et', ','.join(nuclei_exclude_templates),
                    '-o', nuclei_tmp_output, '-page-timeout', '3',
                    '-timeout', '3', '-concurrency', '50',
                    '-bulk-size', '50', '-rate-limit', '500'], stdin=httpx_process.stdout)
            nuclei_process.communicate()
    except (subprocess.CalledProcessError, KeyboardInterrupt):
        print('Nuclei process interrupted. Continuing...')

    if Path(nuclei_tmp_output).exists():
        Path(nuclei_tmp_output).rename(nuclei_output)
        print(f'The nuclei report has been generated in the file {nuclei_output}')
    else:
        print('Nuclei process did not generate a report.')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Perform a scan using httpx and nuclei')
    parser.add_argument('input_file',
        nargs='?', default='targets.subfinder.latest.txt',
        help='The input file containing targets (default: targets.subfinder.latest.txt)')
    args = parser.parse_args()

    main(args.input_file)
