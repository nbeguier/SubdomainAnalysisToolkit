#!/bin/bash

input_file="targets.subfinder.latest.txt"
timestamp=$(date +%Y%m%d-%H%M%S)
nuclei_output="reports/report.nuclei.${timestamp}.txt"
nuclei_tmp_output="report.nuclei.tmp.txt"

exclude_templates="exposures/backups/zip-backup-files.yaml,dns/dmarc-detect.yaml,dns/caa-fingerprint.yaml,dns/mx-fingerprint.yaml,technologies/switch-protocol.yaml,miscellaneous/options-method.yaml,technologies/tech-detect.yaml,dns/cname-service.yaml,ssl/mismatched-ssl-certificate.yaml,ssl/ssl-dns-names.yaml,ssl/detect-ssl-issuer.yaml,dns/txt-fingerprint.yaml,dns/cname-fingerprint.yaml,dns/nameserver-fingerprint.yaml,miscellaneous/apple-app-site-association.yaml,technologies/waf-detect.yaml,technologies/secui-waf-detect.yaml,dns/dns-waf-detect.yaml,misconfiguration/http-missing-security-headers.yaml,ssl/weak-cipher-suites.yaml,dns/mx-service-detector.yaml"

# Update de nuclei
echo "Update de nuclei"
nuclei -silent -up

# Exécuter httpx et nuclei pour effectuer le scan
echo "Lancement de httpx et nuclei pour effectuer le scan... ($nuclei_tmp_output)"
httpx -silent -l "$input_file" | nuclei -et "$exclude_templates" -o "$nuclei_tmp_output" -page-timeout 3 -timeout 3 -concurrency 50 -bulk-size 50 -rate-limit 500

mv "$nuclei_tmp_output" "$nuclei_output"

echo "Le rapport nuclei a été généré dans le fichier $nuclei_output"
