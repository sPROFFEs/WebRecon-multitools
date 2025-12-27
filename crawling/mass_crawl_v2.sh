#!/bin/bash

# ==============================================================================
# SCRIPT: mass_crawl_v2.sh
# AUTHOR: ?
# DESCRIPTION: Filters alive domains using httpx and launches recursive feroxbuster.
# DEPENDENCIES: feroxbuster, httpx
# ==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
THREADS_HTTPX=100
THREADS_FEROX=50
DEPTH=2
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BASE_DIR="scans_${TIMESTAMP}"
ALIVE_FILE="${BASE_DIR}/alive_targets.txt"

# 1. Dependency Validation
check_dep() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}[!] Critical Error: '$1' not found. Install it and add it to your PATH.${NC}"
        exit 1
    fi
}

check_dep "httpx"
check_dep "feroxbuster"

# 2. Argument Validation
if [ "$#" -lt 1 ]; then
    echo -e "${RED}[!] Usage: $0 <raw_domains.txt> [optional_wordlist]${NC}"
    exit 1
fi

INPUT_FILE=$1

if [ ! -z "$2" ]; then WORDLIST=$2; fi
if [ ! -f "$WORDLIST" ]; then echo -e "${RED}[!] Error: Invalid wordlist path.${NC}"; exit 1; fi

echo -e "${BLUE}[*] Setting up environment at: ${BASE_DIR}${NC}"
mkdir -p "$BASE_DIR"

# 3. Filtering Phase (The Funnel)
echo -e "${BLUE}[*] Phase 1: Detecting active web services with HTTPX...${NC}"
echo -e "${YELLOW}[i] Input: $(wc -l < $INPUT_FILE) potential domains.${NC}"

# httpx flags:
# -silent: Clean output only
# -threads: Concurrency level
# -follow-redirects: Follows redirects to capture the final actual URL
# -tech-detect: (Optional, removed for speed, add if fingerprinting is needed)
httpx -l "$INPUT_FILE" \
      -threads "$THREADS_HTTPX" \
      -follow-redirects \
      -silent \
      -o "$ALIVE_FILE"

if [ ! -s "$ALIVE_FILE" ]; then
    echo -e "${RED}[!] Fatal: No alive domains found. Check your connection or input list.${NC}"
    rm -rf "$BASE_DIR"
    exit 1
fi

ALIVE_COUNT=$(wc -l < "$ALIVE_FILE")
echo -e "${GREEN}[V] Phase 1 Complete: ${ALIVE_COUNT} alive targets identified.${NC}"
echo -e "${GREEN}[V] List saved to: ${ALIVE_FILE}${NC}"

# 4. Attack Phase (Feroxbuster)
echo -e "${BLUE}[*] Phase 2: Starting Mass Crawling with Feroxbuster...${NC}"

while IFS= read -r target_url || [ -n "$target_url" ]; do
    if [ -z "$target_url" ]; then continue; fi

    # Extract clean domain for folder name (strips http://, https:// and ports)
    domain_name=$(echo "$target_url" | sed -E 's/^\s*.*:\/\///g' | cut -d/ -f1 | cut -d: -f1)
    
    DOMAIN_DIR="${BASE_DIR}/${domain_name}"
    mkdir -p "$DOMAIN_DIR"

    echo -e "${YELLOW}[->] Scanning: ${target_url}${NC}"

    feroxbuster \
        -u "$target_url" \
        -w "$WORDLIST" \
        -t "$THREADS_FEROX" \
        -d "$DEPTH" \
        --no-state \
        -k \
        --redirects \
        -o "${DOMAIN_DIR}/ferox.txt" 2>/dev/null

    # Immediate Feedback
    if [ -s "${DOMAIN_DIR}/ferox.txt" ]; then
        FINDINGS=$(wc -l < "${DOMAIN_DIR}/ferox.txt")
        echo -e "${GREEN}    [+] Success: ${FINDINGS} paths found in ${domain_name}${NC}"
    else
        echo -e "${RED}    [-] Nothing interesting in ${domain_name} (or WAF blocking)${NC}"
        rm -rf "$DOMAIN_DIR" # Auto-cleanup if empty
    fi

done < "$ALIVE_FILE"

echo -e "${BLUE}[*] Operation finished. Reports located at: ${BASE_DIR}${NC}"
