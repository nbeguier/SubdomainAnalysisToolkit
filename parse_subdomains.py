#!/usr/bin/env python
"""
This script takes a list of subdomains from a file,
resolves their IPs, gets the CNAME if available, and the IP Provider.
It then prints the information in either a table, CSV format, or a visual graph.
"""

import argparse
import sys
import csv
from tabulate import tabulate
from ipwhois import IPWhois
from graphviz import Graph
import dns.resolver

# from pdb import set_trace as st

def get_aws_zone(ptr):
    """
    Get the AWS zone from the PTR value.

    Args:
        ptr (str): The PTR value.

    Returns:
        str: The AWS zone or 'AMAZON' if not found.
    """
    if not ptr.endswith('.amazonaws.com.'):
        return 'AMAZON'
    return ptr.split('.')[-5]


def resolve_ip(domain):
    """
    Resolve the IP, CNAME, and IP Provider for a given domain.

    Args:
        domain (str): The domain to resolve.

    Returns:
        tuple: A tuple containing the IP, CNAME, and IP Provider. Empty strings if not found.
    """
    resolver = dns.resolver.Resolver()
    ipv4 = ''
    cname = ''
    ptr = ''
    provider = ''

    try:
        ipv4 = str(resolver.resolve(domain, 'A')[0])
    except Exception:
        pass

    try:
        reverse_name = dns.reversename.from_address(ipv4)
        ptr = str(resolver.resolve(reverse_name, 'PTR')[0])
    except Exception:
        pass

    try:
        cname = str(resolver.resolve(domain, 'CNAME')[0])
    except Exception:
        pass

    try:
        rdap = IPWhois(ipv4).lookup_rdap()
        provider = rdap['asn_description']

        if 'AMAZON' in provider and 'AMAZON-4' in rdap['objects']:
            provider = 'AMAZON - Cloudfront'
        elif 'AMAZON' in provider:
            provider = f'AMAZON - {get_aws_zone(ptr)}'
            if provider == 'AMAZON - AMAZON':
                cname = ptr
                provider = 'AMAZON'
    except Exception:
        pass

    return ipv4, cname, provider


def print_table(rows):
    """
    Print the table format of the output.

    Args:
        rows (list): The rows to print.
    """
    # Sort the rows by the "IP Provider" field
    rows = sorted(rows, key=lambda row: row[3])

    headers = ['Subdomain', 'CNAME', 'IP', 'IP Provider']
    print(tabulate(rows, headers=headers, tablefmt='grid'))


def print_csv(rows):
    """
    Print the CSV format of the output.

    Args:
        rows (list): The rows to print.
    """
    headers = ['Subdomain', 'CNAME', 'IP', 'IP Provider']
    csv_writer = csv.writer(sys.stdout)
    csv_writer.writerow(headers)
    csv_writer.writerows(rows)


def create_graph(rows):
    """
    Create a visual graph with bubbles representing providers and subdomains.

    Args:
        rows (list): The rows to create the graph from.
    """
    graph = Graph('Providers', format='png')

    # Create nodes
    providers = set(row[3] for row in rows)
    for provider in providers:
        subdomains = [row[0] for row in rows if row[3] == provider]
        bubble_label = provider + '\n' + '\n'.join(subdomains)
        graph.node(provider, label=bubble_label, shape='square')

    # Connect nodes that start with 'AMAZON'
    amazon_providers = [provider for provider in providers if provider.startswith('AMAZON')]
    for i in range(len(amazon_providers) - 1):
        # You might want to replace this with your own logic to determine the connections
        graph.edge(amazon_providers[i], amazon_providers[i + 1])

    graph.render('graph', view=True)


def main():
    """
    Read subdomains from a file, resolve their details, and print the output.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', default='targets.latest.txt', help='Input file name')
    parser.add_argument('--csv', action='store_true', help='Output in CSV format')
    parser.add_argument('--graph', action='store_true', help='Create a visual graph')
    args = parser.parse_args()

    try:
        with open(args.file, 'r', encoding='utf-8') as file:
            subdomains = [line.strip() for line in file.readlines()]
    except IOError:
        print(f"Error: Failed to open file '{args.file}'")
        return

    rows = []
    for subdomain in subdomains:
        ipv4, cname, provider = resolve_ip(subdomain)
        if ipv4 and ipv4 != '127.0.0.1' and not ipv4.startswith('::'):
            if cname and cname != subdomain and cname in subdomains:
                continue
            rows.append([subdomain, cname, ipv4, provider])

    if args.graph:
        create_graph(rows)
    elif args.csv:
        print_csv(rows)
    else:
        print_table(rows)


if __name__ == '__main__':
    main()
