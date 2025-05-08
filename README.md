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
go install -v github.com/owasp-amass/amass/v3/...@master

# Install Python dependencies
pip install -U -r requirements.txt

# Copy the sample settings file to create your own
cp settings.sample.py settings.py
```

## Tools Usage

Here is how you can use the tools included in this repository.

The easy way:

```bash
echo "github.com" > targets.txt
bash wizard.sh
```

or script by script

```bash
# Generate a list of subdomains
bash subdomains.sh

# Generate a list of TCP reachable domains (not 80, 443)
bash naabu.sh

# Generate a nuclei report
python nuclei.py
python nuclei.py naabu.latest.txt

# Display the new findings, at least low severity, during the last 7 days
python diff_nuclei.py --severe --days 7

# Merge all reports into a single report
bash merge_all_reports.sh

# Generate stats from the nuclei report
python nuclei_report_stats.py report.nuclei.latest.txt


# Others
# Get generic info from subdomains
python parse_subdomains.py

# Get known URLs from Internet Archives
python get_unique_urls.py -d beguier.eu
python get_unique_urls.py -f targets.latest.txt

# Create another report with timestamp and other metadata
python reformat_reports.py > report.nuclei.latest.csv

# Get public buckets
python get_public_buckets.py github

# Counter visit of vulnerabilities in report
python counter_visit.py
```

This toolkit simplifies the process of subdomain discovery and analysis, making it an invaluable resource for anyone involved in network security and site reliability.

or the TOR way...

```bash
# Run tor proxy
docker run -ti --rm -p 127.0.0.1:9050:9050 andrius/alpine-tor

# Generate a list of subdomains
bash subdomains.sh

# Run nuclei on latest targets with tor proxy
bash nuclei.sh [--domain example.com]
# you can run this during the scan:
watch 'curl -s http://localhost:9092/metrics | jq .summary'
```
