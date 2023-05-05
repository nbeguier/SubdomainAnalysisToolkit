#!/bin/bash

merged_output="report.nuclei.latest.txt"

# "ls -r" keeps the latest event first
ls -r report.nuclei.2* | xargs cat | awk -F' ' '!seen[$1, $2, $3, $4]++' | sort -u > "$merged_output"

cat "$merged_output" | grep -v 'dmarc-detect\|caa-fingerprint\|mx-fingerprint\|switch-protocol\|options-method\|tech-detect\|cname-service\|mismatched-ssl-certificate\|ssl-dns-names\|ssl-issuer\|txt-fingerprint\|cname-fingerprint\|nameserver-fingerprint\|apple-app-site-association\|waf-detect\|secui-waf-detect\|dns-waf-detect\|http-missing-security-headers\|weak-cipher-suites\|mx-service-detector' > /tmp/merged

mv /tmp/merged "$merged_output"

echo "Merged report is saved as \"$merged_output\""
