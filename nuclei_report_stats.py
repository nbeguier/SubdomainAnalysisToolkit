#!/usr/bin/env python
"""
Nuclei Report Stats
"""
import sys
import re
from pathlib import Path
from collections import defaultdict
import socket
from tabulate import tabulate

from settings import products, false_positive

# Debug
# from pdb import set_trace as st

def resolve_a_records(fqdn):
    """
    Resolve the A record(s) for a given FQDN (fully qualified domain name).

    :param fqdn: the FQDN to resolve
    :return: the first A record IP address, or 'unknown' if resolution fails
    """
    try:
        a_records = socket.getaddrinfo(fqdn, None, socket.AF_INET)
        return [record[4][0] for record in a_records][0]
    except socket.gaierror:
        return 'unknown'

def classify_subdomains(subdomain):
    """
    Classify a subdomain based on the products dictionary.

    :param subdomain: a string representing the subdomain to classify
    :return: the product name if a match is found, otherwise None
    """
    for product, pattern in products.items():
        if re.match(pattern, subdomain):
            return product
    return None

def process_nuclei_report_line(line):
    """
    Process a line from the nuclei report file and extract relevant information.

    :param line: a string representing a line from the nuclei report file
    :return: a tuple containing:
             - a boolean indicating if the line was successfully processed
             - the category, cat2, severity, and subproduct extracted from the line
    """
    # Match and extract required information from each line
    match = re.search(r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.*)', line)
    if not match:
        return False, None, None, None, None
    category, cat2, severity, subproduct = match.groups()
    if subproduct.startswith('http:') or subproduct.startswith('https:'):
        subproduct = subproduct.split('/')[2]
    subproduct = subproduct.split(':')[0].split(' ')[0]
    return True, category, cat2, severity, subproduct

def get_nuclei_line_severity(line):
    """
    Get the severity of a line from the nuclei report file.

    :param line: a string representing a line from the nuclei report file
    :return: a string representing the severity level of the line
    """
    # Match and extract required information from each line
    match = re.search(r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.*)', line)
    _, _, severity, _ = match.groups()
    return severity

def wp_extractor(product_dict, line, category):
    if category == 'wordpress-detect':
        match = re.search(r".+ (.+)$", line)
        if match:
            product_dict['url'] = match.group(1)
    elif category.startswith('wordpress-detect:'):
        match = re.search(r".+ (.+) \[(.+)\]$", line)
        if match:
            product_dict['version'] = match.group(2)
            if product_dict['url'] == '-':
                product_dict['url'] = match.group(1)
    elif category == 'metatag-cms':
        match = re.search(r'.* \[.*WordPress ([0-9\.]+).*\]', line)
        if match:
            product_dict['version'] = match.group(1)

def main():
    """
    Main function to read the nuclei report file, extract statistics and
    display the results.
    """
    if len(sys.argv) != 2:
        print("Error: Please provide a nuclei report file as input.")
        sys.exit(1)

    report_file = sys.argv[1]

    # Initialize the dictionaries for storing statistics
    stats = defaultdict(lambda: defaultdict(int))
    product_stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    product_lines = defaultdict(lambda: set())
    wp_list = defaultdict(lambda: {'version': '-', 'url': '-'})
    db_list = defaultdict(lambda: set())
    remote_list = defaultdict(lambda: set())

    report_path = Path(report_file)
    # Read the report file
    with report_path.open('r', encoding='utf-8') as file:
        for line in file:
            if line in false_positive:
                continue
            # Match and extract required information from each line
            is_valid, category, protocol, severity, subproduct = process_nuclei_report_line(line)
            if not is_valid:
                continue
            # Update global statistics
            stats[severity][category] += 1
            # Extract the product name and update product statistics
            product = classify_subdomains(subproduct)
            product_stats[product][severity][category] += 1
            if severity not in ['info'] and protocol != 'ssl':
                product_lines[product].add(line)
            # Create a list of Wordpress
            if category.startswith('wordpress-detect') or category == 'metatag-cms':
                wp_extractor(wp_list[subproduct], line, category)
            # Create a list of DB
            if category in ['mysql-detect', 'pgsql-detect', 'redis-detect', 'mongodb-detect', 'cql-detect', 'cql-detect', 
'proftpd-server-detect', 'rabbitmq-detect', 's3-detect', 'smb-detect', 'samba-detect', 'microsoft-ftp-service', 'mikrotik-ftp-server-detect', 'xlight-ftp-service-detect']:
                db_list[category].add(f'{resolve_a_records(subproduct)} {subproduct}')
            # Create a list of Remote conn
            if category in ['rdp-detect', 'openssh-detect', 'sshd-dropbear-detect', 'telnet-detect']:
                remote_list[category].add(f'{resolve_a_records(subproduct)} {subproduct}')


    # Display global statistics
    print("Global statistics:")
    for severity in ['high', 'medium', 'low', 'info']:
        print(f"{severity.capitalize()} : {sum(stats[severity].values())}")

    # Display product-wise statistics
    print("\nStatistics per product:")
    for product, product_stat in product_stats.items():
        print(f"\n## Product: {product}")
        for severity in ['high', 'medium', 'low', 'info']:
            print(f"  {severity.capitalize()} : {sum(product_stat[severity].values())}")
            for line in product_lines[product]:
                if get_nuclei_line_severity(line) == severity:
                    print(f'  {line}')

    # Display a list of WordPress
    print("\nList of Wordpress:")
    table_data = []

    for wp_name in wp_list:
        product = classify_subdomains(wp_name)
        row = [wp_name, wp_list[wp_name]['version'], wp_list[wp_name]['url'], product]
        table_data.append(row)

    sorted_table_data = sorted(table_data, key=lambda row: (row[3], row[0]))

    print(tabulate(sorted_table_data, headers=["WordPress Site", "Version", "URL", "Product"], tablefmt="grid"))

    # Display a list of dbs
    print("\nList of dbs:")

    for db_engine in db_list:
        print(f'## List of {db_engine}')
        table_data = []
        unique_ips = set()

        for db_name in db_list[db_engine]:
            ipv4, domain = db_name.split(' ')

            # If the current IP is not unique, skip this entry
            if ipv4 in unique_ips and db_engine != 's3-detect':
                continue

            # Add the current IP to the unique_ips set
            if db_engine != 's3-detect':
                unique_ips.add(ipv4)

            product = classify_subdomains(domain)

            # Add a row to the table data
            if db_engine == 's3-detect':
                row = [domain, product]
            else:
                row = [ipv4, domain, product]
            table_data.append(row)

        if db_engine == 's3-detect':
            # Sort the table data first by the product name and then by IP
            sorted_table_data = sorted(table_data, key=lambda row: (row[1], row[0]))
            headers = ["Domain", "Product"]
        else:
            # Sort the table data first by the product name and then by IP
            sorted_table_data = sorted(table_data, key=lambda row: (row[2], row[0]))
            headers = ["IP", "Domain", "Product"]

        print(tabulate(sorted_table_data, headers=headers, tablefmt="grid"))

    # Display a list of remote connections
    print("\nList of remote conn:")
    for conn_engine in remote_list:
        print(f'## List of {conn_engine}')
        table_data = []
        unique_ips = set()

        for conn in remote_list[conn_engine]:
            ipv4, domain = conn.split(' ')

            # If the current IP is not unique, skip this entry
            if ipv4 in unique_ips:
                continue

            # Add the current IP to the unique_ips set
            unique_ips.add(ipv4)

            product = classify_subdomains(domain)

            # Add a row to the table data
            row = [ipv4, domain, product]
            table_data.append(row)

        # Sort the table data first by the product name and then by IP
        sorted_table_data = sorted(table_data, key=lambda row: (row[2], row[0]))

        headers = ["IP", "Domain", "Product"]

        print(tabulate(sorted_table_data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    main()
