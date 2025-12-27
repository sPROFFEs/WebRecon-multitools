#!/bin/bash

# ==============================================================================
# TITLE: SQLiTo Dependency Installer (Robust Path Edition)
# AUTHOR: ?
# DESCRIPTION: Automates setup for Go, Python, and Recon tools
# ==============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "${BLUE}[*] Starting SQLiTo Environment Setup...${NC}"

# 1. System Update & Essentials
echo -e "\n${YELLOW}[i] Updating system packages...${NC}"
sudo apt-get update -y
sudo apt-get install -y git curl wget unzip python3 python3-pip python3-venv libpcap-dev

# 2. Golang Installation
if ! command -v go &> /dev/null; then
    echo -e "\n${YELLOW}[i] Golang not found. Installing Go...${NC}"
    wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
    rm go1.21.6.linux-amd64.tar.gz
else
    echo -e "${GREEN}[+] Golang is already installed.${NC}"
fi

# 3. CRITICAL: Configure Go Path (Current & Permanent)
echo -e "\n${BLUE}[*] Configuring Environment Paths...${NC}"

# Export for THIS session immediately (so the rest of the script works)
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# Helper function to add to shell profiles if not missing
add_to_path() {
    local shell_rc=$1
    if [ -f "$shell_rc" ]; then
        if ! grep -q "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" "$shell_rc"; then
            echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$shell_rc"
            echo -e "${GREEN}[+] Added Go path to $shell_rc${NC}"
        else
            echo -e "${YELLOW}[-] Go path already exists in $shell_rc${NC}"
        fi
    fi
}

# Apply to common shell configs
add_to_path "$HOME/.bashrc"
add_to_path "$HOME/.zshrc"
add_to_path "$HOME/.profile"

# 4. Install Go Tools
echo -e "\n${BLUE}[*] Installing Go Recon Tools...${NC}"
GO_TOOLS=(
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/tomnomnom/qsreplace@latest"
)

# We use the full path to 'go' just in case
/usr/local/go/bin/go env -w GO111MODULE=on

for tool in "${GO_TOOLS[@]}"; do
    tool_name=$(echo $tool | awk -F/ '{print $NF}' | cut -d@ -f1)
    echo -e "${YELLOW}[->] Installing $tool_name...${NC}"
    /usr/local/go/bin/go install "$tool"
done

# 5. Install SQLMap
if ! command -v sqlmap &> /dev/null; then
    echo -e "\n${BLUE}[*] Installing SQLMap...${NC}"
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git ~/sqlmap-dev
    sudo ln -sf ~/sqlmap-dev/sqlmap.py /usr/local/bin/sqlmap
else
    echo -e "${GREEN}[+] SQLMap is already installed.${NC}"
fi

# 6. Install Python Tools
echo -e "\n${BLUE}[*] Installing Python Tools...${NC}"
pip3 install wafw00f uro --break-system-packages 2>/dev/null || pip3 install wafw00f uro

# 7. Finalize
echo -e "\n${BLUE}[*] Updating Nuclei Templates...${NC}"
$HOME/go/bin/nuclei -update-templates -silent

echo -e "\n${GREEN}[V] Setup Complete!${NC}"
echo -e "${RED}[!!!] IMPORTANT: Run this command now to refresh your terminal:${NC}"
echo -e "${BOLD}    source ~/.bashrc${NC}  (or source ~/.zshrc)"
