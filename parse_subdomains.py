#!/usr/bin/env python
"""
This script takes a list of subdomains from the standard input,
resolves their IPs, gets the CNAME if available, and the IP Provider.
It then prints a table with this information.
"""

import sys
import dns.resolver
from tabulate import tabulate
from ipwhois import IPWhois

def resolve_ip(domain):
    """
    Resolve the IP, CNAME and IP Provider for a given domain.

    Args:
        domain (str): The domain to resolve.

    Returns:
        tuple: A tuple containing the IP, CNAME and IP Provider. Empty strings if not found.
    """
    resolver = dns.resolver.Resolver()
    ipv4 = ''
    cname = ''
    provider = ''
    try:
        ipv4 = str(resolver.resolve(domain, 'A')[0])
        cname = str(resolver.resolve(domain, 'CNAME')[0])
        provider = IPWhois(ipv4).lookup_rdap()['asn_description']
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        provider = ''
    return ipv4, cname, provider


def main():
    """
    Read subdomains from stdin, resolve their details, and print a table.
    """
    subdomains = [line.strip() for line in sys.stdin.readlines()]

    rows = []
    for subdomain in subdomains:
        ipv4, cname, provider = resolve_ip(subdomain)
        if ipv4 and ipv4 != '127.0.0.1' and not ipv4.startswith('::'):
            if cname and cname != subdomain and cname in subdomains:
                continue
            rows.append([subdomain, cname, ipv4, provider])

    if rows:
        print(tabulate(rows, headers=['Subdomain', 'CNAME', 'IP', 'IP Provider'], tablefmt='grid'))
    else:
        print('No subdomains with resolved IPs')


if __name__ == '__main__':
    main()
