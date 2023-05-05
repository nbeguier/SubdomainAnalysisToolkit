# Subdomain Analysis Toolkit

Subdomain Analysis Toolkit is a collection of tools designed to facilitate subdomain discovery, analysis, and reporting. This repository includes scripts to automate subdomain finding, parsing, generating reports, and providing statistical insights.

## Prerequisites

Please make sure you have the following prerequisites installed and configured correctly.

```bash
# Remove any previous Go installations and install Go
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf ~/Downloads/go1.20.3.linux-amd64.tar.gz

# Install latest versions of Nuclei, Httpx, and Subfinder
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Install Python dependencies
pip install -U -r requirements.txt

# Copy the sample settings file to create your own
cp settings.py.sample settings.py
```

## Tools Usage

Here is how you can use the tools included in this repository.

```bash
# Generate a list of subdomains
bash subfinder.sh targets.txt

# Get generic info from subdomains
cat targets.subfinder.latest.txt | python parse_subdomains.py

# Generate a nuclei report
bash nuclei.sh

# Display the new findings, at least low severity, during the last 7 days
python diff_nuclei.py --severe --days 7

# Merge all reports into a single report
bash merge_all_reports.sh

# Generate stats from the nuclei report
python nuclei_report_stats.py report.nuclei.latest.txt
```

This toolkit simplifies the process of subdomain discovery and analysis, making it an invaluable resource for anyone involved in network security and site reliability.
