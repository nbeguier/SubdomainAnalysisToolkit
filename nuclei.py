#!/usr/bin/env python
"""
A script to perform a scan using httpx and nuclei, with options to exclude
certain templates and specify an input file containing targets.
"""

import argparse
import subprocess
from datetime import datetime
from pathlib import Path
import importlib.util
import tempfile

try:
    spec = importlib.util.spec_from_file_location('settings', 'settings.py')
    settings = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(settings)
except FileNotFoundError:
    # If settings.py doesn't exist, import settings.py.sample
    print('Warning: settings.py not found. Falling back to settings.sample.py !')
    spec = importlib.util.spec_from_file_location('settings', 'settings.sample.py')
    settings = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(settings)

# Debug
# from pdb import set_trace as st

def update_tools():
    """Update dnsx, httpx and nuclei tools"""
    print('Updating dnsx, httpx and nuclei')
    subprocess.run(['dnsx', '-silent', '-up'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['httpx', '-silent', '-up'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['nuclei', '-silent', '-up'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    subprocess.run(['nuclei', '-silent', '-ut'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)


def perform_scan(input_file, nuclei_no_tcp_tmp_output):
    """Perform the scan using httpx and nuclei"""
    print(f'Launching httpx and nuclei to perform the scan...')
    try:
        with open(input_file, encoding='utf-8') as targets:
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                for target in targets:
                    if target.strip() not in settings.nuclei_target_blacklist:
                        temp.write(target)
                temp.flush()
        with open(temp.name, 'r', encoding='utf-8') as temp_in:
            httpx_process = subprocess.Popen(
                ['httpx', '-silent'],
                stdin=temp_in,
                stdout=subprocess.PIPE)
            nuclei_process = subprocess.Popen(
                ['nuclei', '-silent', '-et', ','.join(settings.nuclei_exclude_templates),
                    '-exclude-type', 'tcp',
                    '-o', nuclei_no_tcp_tmp_output, '-page-timeout', '3',
                    '-timeout', '3', '-concurrency', '50',
                    '-bulk-size', '50', '-rate-limit', '500'], stdin=httpx_process.stdout)
            nuclei_process.communicate()
    except (subprocess.CalledProcessError, KeyboardInterrupt):
        print('Nuclei process interrupted. Continuing...')


def generate_ips(input_file):
    """Generate a list of IPs from subdomains"""
    try:
        print('Generating a list of IPs from subdomains...')
        command = "awk -F ':' '{print $1}' "+input_file+" | dnsx -resp -a"
        output = subprocess.check_output(command, shell=True, text=True)

        # Parse output and build dictionary
        ip_to_domains = {}
        for line in output.strip().split('\n'):
            domain, ip = line.strip().split(' ')
            ip = ip[1:-1]  # Remove square brackets around IP
            if ip not in ip_to_domains:
                ip_to_domains[ip] = []
            ip_to_domains[ip].append(domain)

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            temp_file.write('\n'.join([i for i in ip_to_domains]))
            temp_file.flush()

        return temp_file.name, ip_to_domains
    except (subprocess.CalledProcessError, KeyboardInterrupt):
        print('Nuclei process interrupted. Continuing...')
        return None


def perform_tcp_scan(ip_file, nuclei_tcp_tmp_output):
    """Perform a TCP scan using nuclei"""
    print(f'Launching nuclei to perform the TCP scan...')
    try:
        nuclei_process = subprocess.Popen(
            ['nuclei', '-silent', '-l', ip_file,
                '-et', ','.join(settings.nuclei_exclude_templates),
                '-type', 'tcp',
                '-o', nuclei_tcp_tmp_output, '-page-timeout', '3',
                '-timeout', '3', '-concurrency', '50',
                '-bulk-size', '50', '-rate-limit', '500'])
        nuclei_process.communicate()
    except (subprocess.CalledProcessError, KeyboardInterrupt):
        print('Nuclei process interrupted. Continuing...')


def add_metadata_tcp_scan(ip_to_domains, nuclei_tcp_tmp_output):
    # Read the file and split it into lines
    with open(nuclei_tcp_tmp_output, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # Create a new list to store modified lines
    new_lines = []

    # Loop over each line
    for line in lines:
        # Remove newline character
        line = line.strip()

        # Check if line contains any IP from ip_to_domains keys
        for ip in ip_to_domains.keys():
            if f' {ip}:' in line:
                # If it does, append the associated value from the dict to the line
                line += ' subdomains:' + ','.join(ip_to_domains[ip])

        # Add the (possibly modified) line to the new_lines list
        new_lines.append(line)

    # Write the new lines back to the file
    with open(nuclei_tcp_tmp_output, 'w', encoding='utf-8') as file:
        for line in new_lines:
            file.write(line + '\n')  # Add newline character back in


def generate_report(nuclei_no_tcp_tmp_output, nuclei_tcp_tmp_output, nuclei_output):
    """Generate the final report"""
    if Path(nuclei_no_tcp_tmp_output).exists() and Path(nuclei_tcp_tmp_output).exists():
        with open(nuclei_no_tcp_tmp_output, 'r', encoding='utf-8') as f1, open(nuclei_tcp_tmp_output, 'r', encoding='utf-8') as f2, open(nuclei_output, 'w', encoding='utf-8') as out_file:
            out_file.write(f1.read() + f2.read())
        Path(nuclei_no_tcp_tmp_output).unlink()
        Path(nuclei_tcp_tmp_output).unlink()
        print(f'The nuclei report has been generated in the file {nuclei_output}')
    elif Path(nuclei_no_tcp_tmp_output).exists():
        Path(nuclei_no_tcp_tmp_output).rename(nuclei_output)
        print(f'The nuclei report has been generated in the file {nuclei_output}')
    elif Path(nuclei_tcp_tmp_output).exists():
        Path(nuclei_tcp_tmp_output).rename(nuclei_output)
        print(f'The nuclei report has been generated in the file {nuclei_output}')
    else:
        print('Nuclei process did not generate a report.')


def filter_subdomains(input_file: str, output_file: str, top_domain: str):
    """
    Filter the input file to include only subdomains
    of the top_domain and write them to the output file.
    """
    with open(input_file, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    subdomains = []
    for line in lines:
        domain = line.strip()
        if domain == top_domain or domain.endswith(f'.{top_domain}'):
            subdomains.append(domain)

    with open(output_file, 'w', encoding='utf-8') as file:
        file.write('\n'.join(subdomains))


def main(input_file: str, top_domain: str):
    """
    Run httpx and nuclei with the given input file, and store the output in a report file.
    """
    if not Path(input_file).exists():
        print(f'Input file "{input_file}" not found. Exiting.')
        return

    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    nuclei_output = f'reports/report.nuclei.{timestamp}.txt'
    tmp_nuclei_no_tcp_output = '/tmp/report.nuclei.no.tcp.txt'
    tmp_nuclei_tcp_output = '/tmp/report.nuclei.tcp.txt'
    tmp_subdomains_file = f'/tmp/subdomains.{timestamp}.txt'

    update_tools()

    if top_domain:
        print(f'Run nuclei on a specific domain: {top_domain}')
        filter_subdomains(input_file, tmp_subdomains_file, top_domain)
        input_file = tmp_subdomains_file

    perform_scan(input_file, tmp_nuclei_no_tcp_output)

    ip_file, ip_dict = generate_ips(input_file)

    if ip_file:
        perform_tcp_scan(ip_file, tmp_nuclei_tcp_output)
        add_metadata_tcp_scan(ip_dict, tmp_nuclei_tcp_output)

    generate_report(tmp_nuclei_no_tcp_output, tmp_nuclei_tcp_output, nuclei_output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Perform a scan using httpx and nuclei')
    parser.add_argument('input_file',
        nargs='?', default='targets.latest.txt',
        help='The input file containing targets')
    parser.add_argument('--domain',  default='',
        help='The domain to scan')
    args = parser.parse_args()

    main(args.input_file, args.domain)
