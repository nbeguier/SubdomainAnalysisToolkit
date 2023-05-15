#!/usr/bin/env python
"""
Nuclei Report Diff
"""

import re
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from tabulate import tabulate

# from pdb import set_trace as st

def get_files(pattern: str) -> list:
    """
    Returns a list of files in the "reports" directory that match the given pattern.

    :param pattern: A string representing a regex pattern
    :return: List of matching files
    """
    reports_dir = Path("reports")
    files = list(reports_dir.glob('*'))
    return [f for f in files if re.match(pattern, f.name)]

def extract_most_recent(files):
    """
    Extracts the most recent value of each line in the given list of files.
    Returns a dictionary where the keys are the first 4 columns of each line,
    and the values are tuples of (filename, line).
    """
    most_recent = {}

    for file in files:
        with open(file, 'r', encoding='utf-8') as f:
            for line in f:
                columns = line.split()[:4]
                key = tuple(columns)

                if key in most_recent:
                    if file > most_recent[key][0]:
                        most_recent[key] = (file, line.strip())
                else:
                    most_recent[key] = (file, line.strip())

    return most_recent

def extract_old(files, days):
    """
    Extracts the most recent value of each line in the files that are older than the specified number of days.
    Returns a dictionary where the keys are the first 4 columns of each line,
    and the values are tuples of (filename, line).
    """
    most_recent = {}

    cutoff_date = datetime.now() - timedelta(days=days)
    cutoff_date_str = cutoff_date.strftime("%Y%m%d-%H%M%S")

    for file in files:
        if file.name > f"report.nuclei.{cutoff_date_str}.txt":
            continue

        with open(file, 'r', encoding='utf-8') as f:
            for line in f:
                columns = line.split()[:4]
                key = tuple(columns)

                if key in most_recent:
                    if file > most_recent[key][0]:
                        most_recent[key] = (file, line.strip())
                else:
                    most_recent[key] = (file, line.strip())

    return most_recent

def print_most_recent(most_recent, severe):
    """
    Prints the most recent value of each line in the given list.
    If severe is True, only lines with severity [high], [medium], or [low] are printed.
    """
    headers = ["Category", "Protocol", "Severity", "Endpoint", "Metadata"]
    rows = []

    for entry in most_recent:
        line = entry[1]
        if len(line.split()) < 4:
            continue
        if line.split()[1] == '[ssl]':
            continue
        if not severe or "[high]" in line or "[medium]" in line or "[low]" in line:
            rows.append([line.split()[0], line.split()[1], line.split()[2], line.split()[3], ' '.join(line.split()[4:])])

    print(tabulate(rows, headers=headers))

def remove_old_findings(old, most_recent):
    """
    Removes entries in the most_recent dictionary that are older.
    Also removes entries that have appeared before.
    Returns a list of keys that are still in the most_recent dictionary after the removal.
    """
    new_most_recent = []

    for key in most_recent:
        if key not in old:
            new_most_recent.append(most_recent[key])

    return new_most_recent

if __name__ == "__main__":
    """
    Processes Nuclei reports.

    This script extracts the most recent value of each line in Nuclei reports,
    and prints the lines sorted by date and optionally filtered by severity.

    Usage:
        python process_nuclei.py [--severe] [--days <days>]

    Optional arguments:
        --severe    Only show lines with severity [high], [medium], or [low].
        --days      Show lines from the last <days> days. Default is 7.
    """

    # Regular expression pattern to extract the date from the filename
    PATTERN = r"report\.nuclei\.(\d{8}-\d{6})\.txt"

    # Set up the command line arguments
    parser = argparse.ArgumentParser(description="Process Nuclei reports.")
    parser.add_argument("--severe", action="store_true",
                        help="Only show lines with severity [high], [medium], or [low].")
    parser.add_argument("--days", type=int, default=7,
                        help="Show lines from the last <days> days. Default is 7.")
    args = parser.parse_args()

    FILES = get_files(PATTERN)
    FILES.sort(reverse=True)

    MOST_RECENT = extract_most_recent(FILES)
    OLD = extract_old(FILES, args.days)
    MOST_RECENT = remove_old_findings(OLD, MOST_RECENT)

    print_most_recent(MOST_RECENT, args.severe)
