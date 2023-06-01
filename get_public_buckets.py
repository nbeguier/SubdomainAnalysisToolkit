#!/usr/bin/env python
"""
This script uses the grayhatwarfare.com API
to fetch and display bucket information based on a keyword,
optimizing subsequent searches for the same keyword by
loading results from a temporary file instead of making repeated API requests.
"""

import argparse
import importlib.util
import json
import os
import pickle
import re
import requests
import sys

# Custom imports
try:
    spec = importlib.util.spec_from_file_location("settings", "settings.py")
    settings = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(settings)
except FileNotFoundError:
    # If settings.py doesn't exist, import settings.py.sample
    print("Warning: settings.py not found. Falling back to settings.sample.py !")
    spec = importlib.util.spec_from_file_location("settings", "settings.sample.py")
    settings = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(settings)

# Debug
from pdb import set_trace as st

def get_buckets_info(keyword):
    """
    Function to get bucket information based on a given keyword.

    It makes a GET request to the API endpoint and retrieves the
    result. If a temporary file with the result for the same keyword
    exists, it loads the result from the file instead of making
    another API request.

    Args:
        keyword: The keyword to search in the API.

    Returns:
        The result from the API request or from the temporary file.
    """
    tmp_file = f"/tmp/{keyword}_tmp_file.pkl"
    if os.path.exists(tmp_file):
        with open(tmp_file, 'rb') as f:
            result = pickle.load(f)
    else:
        url = "https://buckets.grayhatwarfare.com/api/v2/files"
        headers = {
            'Authorization': f'Bearer {settings.graywarefare_api_key}'
        }
        params = {
            'keywords': keyword,
        }
        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            print(response.text)
            sys.exit(1)
        result = json.loads(response.text)
        with open(tmp_file, 'wb') as f:
            pickle.dump(result, f)
    return result


def parse_buckets_info(result):
    """
    Function to parse the result and extract the bucket names and other stats.

    Args:
        result: The result to parse.

    Returns:
        The extracted bucket names and other stats.
    """
    files = result['files']
    unique_buckets = list(set([file['bucket'] for file in files]))
    bucket_info = []
    for bucket in unique_buckets:
        for file in files:
            if file['bucket'] == bucket:
                bucket_info.append([bucket, file['url']])
                break

    other_stats = {
        'total_results': result['meta']['results'],
        'total_files_in_index': result['meta']['notice'].split(' ')[9],
    }
    return bucket_info, other_stats


def main():
    parser = argparse.ArgumentParser(description='Get bucket info')
    parser.add_argument('keyword', type=str, help='Keyword to search')
    args = parser.parse_args()

    result = get_buckets_info(args.keyword)
    bucket_info, other_stats = parse_buckets_info(result)

    print("Bucket Name\t\t\tExample URL")
    for info in bucket_info:
        # Highlight bucket name in green
        bucket_name = f"\033[92m{info[0]}\033[0m"
        # Highlight keyword in red (case insensitive)
        example_url = re.sub(f'({args.keyword})', f'\033[91m\\1\033[0m', info[1], flags=re.IGNORECASE)
        print(f"{bucket_name}\t\t{example_url}")

    print(f'Other Stats: {other_stats}')


if __name__ == "__main__":
    main()
