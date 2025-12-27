#!/usr/bin/env python3
# ==============================================================================
# SCRIPT: crtsh_enum.py
# AUTHOR: ?
# DESCRIPTION: Extracts and normalizes subdomains from crt.sh (Certificate Transparency).
# USAGE: python3 crtsh_enum.py <domain>
# ==============================================================================

import requests
import sys
import json

def get_crt_domains(domain):
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    
    try:
        req = requests.get(url, headers=headers, timeout=20)
        
        if req.status_code != 200:
            print(f"[!] Error: HTTP Status Code {req.status_code}")
            sys.exit(1)
            
        try:
            data = req.json()
        except json.JSONDecodeError:
            print("[!] Error: Response is not valid JSON (crt.sh might be down or throttled).")
            sys.exit(1)

        subdomains = set()

        for entry in data:
            # The name_value field can contain multiple domains separated by newlines
            values = entry['name_value'].split('\n')
            for val in values:
                val = val.strip()
                # Wildcard cleanup (*.example.com -> example.com)
                if val.startswith("*."):
                    val = val[2:]
                subdomains.add(val)

        for sub in sorted(subdomains):
            print(sub)

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <domain>")
        sys.exit(1)
    
    get_crt_domains(sys.argv[1])
