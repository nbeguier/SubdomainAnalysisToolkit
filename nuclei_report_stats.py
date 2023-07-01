#!/usr/bin/env python
"""
Nuclei Report Stats
"""
import sys
import re
from pathlib import Path
from collections import defaultdict
from tabulate import tabulate

from settings import products, false_positive, nuclei_target_blacklist

# Debug
# from pdb import set_trace as st

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

def detect_os_from_banner(line):
    """
    Returns an OS guess from openssh banner
    """
    os_guess = ''
    match = re.search(r'(OpenSSH.*) subdomains:', line)
    if not match:
        os_guess = f'Unknown-({line.replace(" ", "_")})'
    else:
        # -12 to remove " subdomains:"
        version = match.group(0)[:-12]

        if re.search(r'(Debian-[0-9]+)', version):
            os_guess = re.search(r'(Debian-[0-9]+)', version).group(0)
        elif re.search('OpenSSH_7.2p2 Ubuntu-4', version):
            os_guess = 'Ubuntu-16.04'
        elif re.search('OpenSSH_7.6p1 Ubuntu-4', version):
            os_guess = 'Ubuntu-18.04'
        elif re.search('OpenSSH_8.2p1 Ubuntu-4', version):
            os_guess = 'Ubuntu-20.04'
        elif re.search('OpenSSH_8.9p1 Ubuntu-3', version):
            os_guess = 'Ubuntu-21.04'
        elif re.search('Ubuntu', version):
            os_guess = 'Ubuntu-x.x'
        else:
            os_guess = f'Unknown-({version.replace(" ", "_")})'

    return os_guess

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
            if True in [ subproduct.startswith(b) or '/'+b in subproduct for b in nuclei_target_blacklist ]:
                continue
            # Update global statistics
            stats[severity][category] += 1
            # Extract the product name and update product statistics
            product = classify_subdomains(subproduct)
            if protocol == 'tcp':
                product = classify_subdomains(line.split()[-1])
            product_stats[product][severity][category] += 1
            if severity not in ['info'] and protocol != 'ssl':
                product_lines[product].add(line)
            # Ignore TCP when not IP address
            if protocol == 'tcp' and not re.search(r'^[0-9\.]*$',subproduct):
                continue
            # Create a list of Wordpress
            if category.startswith('wordpress-detect') or category == 'metatag-cms':
                wp_extractor(wp_list[subproduct], line, category)
            # Create a list of DB
            if category in ['mysql-detect', 'pgsql-detect', 'redis-detect', 'mongodb-detect', 'cql-detect', 'cql-detect',
'proftpd-server-detect', 'rabbitmq-detect', 's3-detect', 'smb-detect', 'samba-detect', 'microsoft-ftp-service', 'mikrotik-ftp-server-detect', 'xlight-ftp-service-detect']:
                db_list[category].add(f'{subproduct} {line.split()[-1]}')
            # Add panel in the list of DB
            if category.endswith('-panel') or category.endswith('-manager'):
                db_list[category].add(f'{subproduct} {line.split()[3]}')
            # Create a list of Remote conn
            if category in ['rdp-detect', 'openssh-detect', 'sshd-dropbear-detect', 'telnet-detect']:
                remote_list[category].add(f'{subproduct} {line.split()[-1]} {detect_os_from_banner(line)}')


    # Display global statistics
    print("Global statistics:")
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        print(f"{severity.capitalize()} : {sum(stats[severity].values())}")

    # Display product-wise statistics
    print("\nStatistics per product:")
    for product, product_stat in product_stats.items():
        print(f"\n## Product: {product}")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
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
            if 'subdomains:' in domain:
                domain = domain.split(':')[1].split(',')[0]

            # If the current IP is not unique, skip this entry
            if ipv4 in unique_ips and db_engine != 's3-detect':
                continue

            # Add the current IP to the unique_ips set
            if db_engine != 's3-detect':
                unique_ips.add(ipv4)

            product = classify_subdomains(domain)

            # Add a row to the table data
            if db_engine == 's3-detect' or db_engine.endswith('-panel') or db_engine.endswith('-manager'):
                row = [domain, product]
            else:
                row = [ipv4, domain, product]
            table_data.append(row)

        if db_engine == 's3-detect' or db_engine.endswith('-panel') or db_engine.endswith('-manager'):
            # Sort the table data first by the product name and then by IP
            sorted_table_data = sorted(table_data, key=lambda row: (row[1], row[0]))
            headers = ["URL", "Product"]
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
            ipv4, domain, os = conn.split(' ')
            if 'subdomains:' in domain:
                domain = domain.split(':')[1].split(',')[0]

            # If the current IP is not unique, skip this entry
            if ipv4 in unique_ips:
                continue

            # Add the current IP to the unique_ips set
            unique_ips.add(ipv4)

            product = classify_subdomains(domain)

            # Add a row to the table data
            row = [ipv4, domain, product, os]
            table_data.append(row)

        # Sort the table data first by the product name and then by IP
        sorted_table_data = sorted(table_data, key=lambda row: (row[2], row[0]))

        headers = ["IP", "Domain", "Product", "OS"]

        print(tabulate(sorted_table_data, headers=headers, tablefmt="grid"))

if __name__ == "__main__":
    main()
