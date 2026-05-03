# Subdomain Analysis Toolkit

Subdomain Analysis Toolkit is a small collection of scripts designed to help with external exposure monitoring: subdomain discovery, target consolidation, Nuclei scans, reporting, and basic statistical insights.

It is intentionally a toolbox. You can run each step manually, chain them in a shell workflow, or schedule them with your own automation.

## Prerequisites

Please make sure you have the following prerequisites installed and configured correctly.

```bash
# Remove any previous Go installations and install Go
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf ~/Downloads/go1.20.3.linux-amd64.tar.gz

# Install latest versions of ProjectDiscovery tools and Amass
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v3/...@master

# Install Python dependencies
pip install -U tabulate requests dnspython ipwhois graphviz

# Copy the sample settings file to create your own
cp settings.sample.py settings.py
```

## Tools Usage

Here is how you can use the tools included in this repository.

Quick start:

```bash
echo "example.com" > targets.txt

# Discover and consolidate subdomains into targets.latest.txt
bash subdomains.sh

# Run Nuclei on the consolidated target list
bash nuclei.sh --no-color > "report.$(date +%G-Week%V).txt"
```

You can also run the broader local workflow:

```bash
# Generate a list of subdomains
bash subdomains.sh

# Generate a list of TCP reachable domains (not 80, 443)
bash naabu.sh > naabu.latest.txt

# Generate Nuclei reports
bash nuclei.sh --no-color > "report.$(date +%G-Week%V).txt"
bash nuclei.sh naabu.latest.txt --no-color > "report.naabu.$(date +%G-Week%V).txt"

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

## Optional systemd scheduling

One common way to use the toolkit in a recurring monitoring workflow is to install it in `/opt/SubdomainAnalysisToolkit`, refresh `targets.latest.txt` every day, and run Nuclei on a weekly timer.

Example subdomain discovery service:

```ini
# /etc/systemd/system/subdomains.service
[Unit]
Description=Subdomain Analysis Toolkit - Daily run

[Service]
Type=oneshot
WorkingDirectory=/opt/SubdomainAnalysisToolkit
ExecStart=/bin/bash /opt/SubdomainAnalysisToolkit/subdomains.sh
```

Example subdomain discovery timer:

```ini
# /etc/systemd/system/subdomains.timer
[Unit]
Description=Run Subdomain Analysis Toolkit every day at 23:00

[Timer]
OnCalendar=*-*-* 23:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Example Nuclei service:

```ini
# /etc/systemd/system/nuclei.service
[Unit]
Description=Nuclei scan - daily run

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/SubdomainAnalysisToolkit
Environment=HOME=/root
Environment=XDG_CONFIG_HOME=/root/.config
Environment=XDG_CACHE_HOME=/root/.cache
ExecStart=/bin/bash -c '/bin/bash nuclei.sh --no-color > report.$(date +%%G-Week%%V).txt'
```

Example Nuclei timer:

```ini
# /etc/systemd/system/nuclei.timer
[Unit]
Description=Run Nuclei scan every Monday at 00:00

[Timer]
OnCalendar=Mon *-*-* 00:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable the timers:

```bash
systemctl daemon-reload
systemctl enable --now subdomains.timer nuclei.timer
systemctl list-timers subdomains.timer nuclei.timer
```

Check logs and runtime metrics:

```bash
journalctl -x -u subdomains.service -f
journalctl -x -u nuclei.service -f
curl -s http://localhost:9092/metrics
```

## TOR mode

```bash
# Run tor proxy
docker run -ti --rm -p 127.0.0.1:9050:9050 andrius/alpine-tor

# Generate a list of subdomains
bash subdomains.sh

# Run nuclei on latest targets with tor proxy
bash nuclei.sh --domain example.com --no-color
# you can run this during the scan:
watch 'curl -s http://localhost:9092/metrics | jq .summary'
```
