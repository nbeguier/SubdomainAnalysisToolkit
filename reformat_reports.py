#!/usr/bin/env python
"""
Reformat reports
"""

from datetime import datetime
from pathlib import Path
import csv
import hashlib
import io
import re

# from pdb import set_trace as st

def extract_timestamp(filename: str) -> datetime:
    """
    Extract the timestamp from the filename and convert it to a datetime object.

    :param filename: Filename in format "report.nuclei.20230427-143329.txt"
    :return: datetime object representing the timestamp
    """
    timestamp_str = filename.split('.')[2]
    return datetime.strptime(timestamp_str, '%Y%m%d-%H%M%S')

def process_file(filepath: Path) -> list:
    """
    Process a file and convert it into rows of CSV data with timestamp and hash.

    :param filepath: Path of the file to process
    :return: List of rows for CSV output
    """

    ignored_values = [
        'dmarc-detect', 'caa-fingerprint', 'mx-fingerprint', 'switch-protocol', 'options-method',
        'tech-detect', 'cname-service', 'mismatched-ssl-certificate', 'ssl-dns-names',
        'ssl-issuer', 'txt-fingerprint', 'cname-fingerprint', 'nameserver-fingerprint',
        'apple-app-site-association', 'waf-detect', 'secui-waf-detect', 'dns-waf-detect',
        'http-missing-security-headers', 'weak-cipher-suites', 'mx-service-detector'
    ]

    with open(filepath, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    rows = []
    timestamp = extract_timestamp(filepath.name)
    pattern = r'\[([^\]]+)\] \[([^\]]+)\] \[([^\]]+)\] (.*)'

    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = re.search(pattern, line)
        if not match:
            continue

        parts = list(match.groups())
        parts.append(' '.join(parts[3].split()[1:]))
        parts[3] = parts[3].split()[0]

        if any(parts[0].startswith(ignored_value) for ignored_value in ignored_values):
            continue

        hash_input = ''.join(parts[:4])
        hash_output = hashlib.md5(hash_input.encode()).hexdigest()

        row = [timestamp] + parts + [hash_output]
        rows.append(row)

    return rows

def main():
    report_files = list(Path('reports/').glob('report.nuclei.2*.txt'))

    csv_rows = {}
    header = ['Timestamp', 'Type', 'Protocol', 'Severity', 'Asset', 'Extra', 'Hash']

    for report_file in report_files:
        rows = process_file(report_file)
        for row in rows:
            key = ';'.join(row[1:5])
            if key not in csv_rows or csv_rows[key][0] < row[0]:
                csv_rows[key] = row

    sorted_csv_rows = sorted(csv_rows.values(), key=lambda x: x[0])

    with io.StringIO() as csvfile:
        csv_output = csv.writer(csvfile, delimiter=';')
        csv_output.writerow(header)
        csv_output.writerows(sorted_csv_rows)
        print(csvfile.getvalue())

if __name__ == "__main__":
    main()
