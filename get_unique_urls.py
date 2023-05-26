#!/usr/bin/env python
"""
This script retrieves unique URLs for a given subdomain from web.archive.org,
ignoring files with specified extensions.
"""

import argparse
import json
import time
from requests import RequestException, Session

MAX_RETRIES = 3
RETRY_DELAY = 1  # in seconds
SESSION = Session()

def get_unique_urls(subdomain: str) -> list:
    """
    Retrieve unique URLs for a given subdomain from web.archive.org API.

    :param subdomain: The subdomain for which to retrieve unique URLs.
    :return: A list of unique URLs.
    """
    url = f'https://web.archive.org/web/timemap/json?url={subdomain}&matchType=prefix&collapse=urlkey&output=json&fl=original%2Cmimetype%2Ctimestamp%2Cendtimestamp%2Cgroupcount%2Cuniqcount&filter=!statuscode%3A%5B45%5D..&limit=10000&_=1683528722633'

    retries = 0
    while retries < MAX_RETRIES:
        try:
            response = SESSION.get(url)
            response.raise_for_status()
            data = json.loads(response.text)[1:]

            unique_urls = set()
            for entry in data:
                unique_urls.add(entry[0])

            return list(unique_urls)

        except (RequestException, ValueError):
            retries += 1
            if retries < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
            else:
                print(f"Failed to retrieve unique URLs for subdomain: {subdomain}")
                return []

def main():
    """
    Parse command line arguments, retrieve unique URLs for each line in a file and print the filtered output.
    """
    parser = argparse.ArgumentParser(description='Retrieve unique URLs from web.archive.org for a given subdomain or from a file')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='The domain to retrieve URLs for')
    group.add_argument('-f', '--file', help='The file containing subdomains to retrieve URLs for, one per line')
    parser.add_argument('--all', action='store_true', help='Ignore extension filtering and display all URLs')

    args = parser.parse_args()

    if args.domain:
        subdomains = [args.domain]
    else:
        with open(args.file, 'r', encoding='utf-8') as f:
            subdomains = f.read().splitlines()

    for subdomain in subdomains:
        unique_urls = get_unique_urls(subdomain)

        unique_urls = sorted(unique_urls)

        for url in unique_urls:
            if not args.all:
                extension = url.split('?')[0].split('.')[-1]
                if extension in [
                    'css',
                    'eot',
                    'gif',
                    'jpg',
                    'js',
                    'png',
                    'svg',
                    'ttf',
                    'webp'
                    'woff',
                    'woff2',
                ]:
                    continue
            print(url)

if __name__ == '__main__':
    main()
