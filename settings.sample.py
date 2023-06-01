# Define products and their corresponding regex patterns
products = {
    "Dev":r".*(dev|staging|test).*",
    "Github": r".*\.?github\.com",
    "Unknown": r".*"
}

false_positive = [
'[dbeaver-credentials] [http] [medium] https://www.github.com/.dbeaver/credentials-config.json\n',
]

nuclei_target_blacklist = [
    'example.com'
]

nuclei_exclude_templates = [
    'dns/caa-fingerprint.yaml',
    'dns/cname-fingerprint.yaml',
    'dns/cname-service.yaml',
    'dns/dmarc-detect.yaml',
    'dns/dns-waf-detect.yaml',
    'dns/mx-fingerprint.yaml',
    'dns/mx-service-detector.yaml',
    'dns/nameserver-fingerprint.yaml',
    'dns/txt-fingerprint.yaml',
    'exposures/backups/zip-backup-files.yaml',
    'miscellaneous/apple-app-site-association.yaml',
    'miscellaneous/options-method.yaml',
    'misconfiguration/http-missing-security-headers.yaml',
    'ssl/detect-ssl-issuer.yaml',
    'ssl/mismatched-ssl-certificate.yaml',
    'ssl/ssl-dns-names.yaml',
    'ssl/weak-cipher-suites.yaml',
    'technologies/secui-waf-detect.yaml',
    'technologies/switch-protocol.yaml',
    'technologies/tech-detect.yaml',
    'technologies/waf-detect.yaml',
]

graywarefare_api_key = 'xxxxxxxxxxxxxxxxx'