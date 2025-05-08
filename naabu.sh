#!/bin/bash

# Liste des ports à scanner
PORTS="21,22,25,53,8080,135,136,137,138,139,143,445,993,995,1723,3306,3389,6379,27017,5900,8443,5901,88,161,389,689,500,1812,1813,3000,4000,5000,5060,1433,1434,5432,9933,8110,8014,8107,8034,9999,15672,7777,8762,8088,19091,9091,19090,943,4532,9093,19093,9090,4531,5055,4530,4520,1194"

# Entrée : argument 1 ou "targets.latest.txt" par défaut
INPUT="$1"
DEFAULT_FILE="targets.latest.txt"

# Mise à jour de naabu
echo "[*] Updating naabu..."
naabu -up >/dev/null 2>&1

# Fonction pour scanner un fichier
scan_file() {
    echo "[*] Scanning targets from file: $1"
    naabu -l "$1" -p "$PORTS" 2>/dev/null | grep -E ':[0-9]+$'
}

# Fonction pour scanner une seule IP/domain
scan_target() {
    echo "[*] Scanning target: $1"
    echo "$1" | naabu -p "$PORTS" 2>/dev/null | grep -E ':[0-9]+$'
}

# Traitement
if [[ -z "$INPUT" ]]; then
    if [[ -f "$DEFAULT_FILE" ]]; then
        scan_file "$DEFAULT_FILE"
    else
        echo "No input and default file '$DEFAULT_FILE' not found."
        exit 1
    fi
elif [[ -f "$INPUT" ]]; then
    scan_file "$INPUT"
else
    scan_target "$INPUT"
fi
