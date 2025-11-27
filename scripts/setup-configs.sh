#!/bin/bash
# ============================================================================
# AI-SOC Configuration Setup Script
# ============================================================================
# Ensures all necessary configuration files and directories exist for deployment
# Automatically creates missing configs with production-ready defaults
#
# Usage: ./scripts/setup-configs.sh
# Requirements: bash, openssl (for cert generation)
#
# This script is safe to run multiple times - it only creates missing files
# ============================================================================

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}AI-SOC Configuration Setup${NC}"
echo -e "${BLUE}================================${NC}\n"

# Get script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$PROJECT_DIR/config"

echo -e "${YELLOW}[INFO]${NC} Project directory: $PROJECT_DIR"
echo -e "${YELLOW}[INFO]${NC} Config directory: $CONFIG_DIR\n"

# Track what was created
CREATED_COUNT=0
SKIPPED_COUNT=0

# ============================================================================
# Helper Functions
# ============================================================================

create_directory() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        echo -e "${GREEN}[CREATED]${NC} Directory: ${dir#$PROJECT_DIR/}"
        ((CREATED_COUNT++))
    else
        echo -e "${BLUE}[EXISTS]${NC} Directory: ${dir#$PROJECT_DIR/}"
        ((SKIPPED_COUNT++))
    fi
}

create_gitkeep() {
    local dir="$1"
    local gitkeep="$dir/.gitkeep"
    if [ ! -f "$gitkeep" ]; then
        touch "$gitkeep"
        echo -e "${GREEN}[CREATED]${NC} Marker: ${gitkeep#$PROJECT_DIR/}"
        ((CREATED_COUNT++))
    fi
}

# ============================================================================
# 1. Create Configuration Directories
# ============================================================================
echo -e "${BLUE}[Step 1/5]${NC} Creating configuration directories...\n"

# Core service config directories
create_directory "$CONFIG_DIR/wazuh-indexer"
create_directory "$CONFIG_DIR/wazuh-indexer/certs"
create_directory "$CONFIG_DIR/wazuh-manager"
create_directory "$CONFIG_DIR/wazuh-manager/certs"
create_directory "$CONFIG_DIR/wazuh-manager/rules"
create_directory "$CONFIG_DIR/wazuh-manager/decoders"
create_directory "$CONFIG_DIR/wazuh-dashboard"
create_directory "$CONFIG_DIR/wazuh-dashboard/certs"
create_directory "$CONFIG_DIR/suricata"
create_directory "$CONFIG_DIR/suricata/rules"
create_directory "$CONFIG_DIR/zeek"
create_directory "$CONFIG_DIR/zeek/site"
create_directory "$CONFIG_DIR/filebeat"
create_directory "$CONFIG_DIR/filebeat/certs"
create_directory "$CONFIG_DIR/root-ca"

# Add .gitkeep to cert directories so they're tracked
create_gitkeep "$CONFIG_DIR/wazuh-indexer/certs"
create_gitkeep "$CONFIG_DIR/wazuh-manager/certs"
create_gitkeep "$CONFIG_DIR/wazuh-dashboard/certs"
create_gitkeep "$CONFIG_DIR/filebeat/certs"
create_gitkeep "$CONFIG_DIR/root-ca"

# Add .gitkeep to custom rules/decoders
create_gitkeep "$CONFIG_DIR/wazuh-manager/rules"
create_gitkeep "$CONFIG_DIR/wazuh-manager/decoders"
create_gitkeep "$CONFIG_DIR/suricata/rules"
create_gitkeep "$CONFIG_DIR/zeek/site"

# ============================================================================
# 2. Create .env from Template
# ============================================================================
echo -e "\n${BLUE}[Step 2/5]${NC} Checking environment configuration...\n"

if [ ! -f "$PROJECT_DIR/.env" ]; then
    if [ -f "$PROJECT_DIR/.env.example" ]; then
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
        echo -e "${GREEN}[CREATED]${NC} .env file from template"
        echo -e "${YELLOW}[ACTION REQUIRED]${NC} Edit .env and set secure passwords!"
        ((CREATED_COUNT++))
    else
        echo -e "${RED}[ERROR]${NC} .env.example not found!"
        exit 1
    fi
else
    echo -e "${BLUE}[EXISTS]${NC} .env file"
    ((SKIPPED_COUNT++))
fi

# ============================================================================
# 3. Verify Core Configuration Files
# ============================================================================
echo -e "\n${BLUE}[Step 3/5]${NC} Verifying core configuration files...\n"

# Check essential config files
CONFIG_FILES=(
    "config/wazuh-indexer/opensearch.yml"
    "config/wazuh-manager/ossec.conf"
    "config/wazuh-dashboard/opensearch_dashboards.yml"
    "config/suricata/suricata.yaml"
    "config/zeek/local.zeek"
    "config/filebeat/filebeat.yml"
)

MISSING_CONFIGS=()

for config_file in "${CONFIG_FILES[@]}"; do
    full_path="$PROJECT_DIR/$config_file"
    if [ -f "$full_path" ]; then
        echo -e "${GREEN}[OK]${NC} $config_file"
        ((SKIPPED_COUNT++))
    else
        echo -e "${RED}[MISSING]${NC} $config_file"
        MISSING_CONFIGS+=("$config_file")
    fi
done

if [ ${#MISSING_CONFIGS[@]} -gt 0 ]; then
    echo -e "\n${RED}[ERROR]${NC} Missing ${#MISSING_CONFIGS[@]} essential configuration files!"
    echo -e "${YELLOW}[INFO]${NC} These should be tracked in git. Verify your clone or repo state."
    for missing in "${MISSING_CONFIGS[@]}"; do
        echo "  - $missing"
    done
    exit 1
fi

# ============================================================================
# 4. Generate SSL Certificates
# ============================================================================
echo -e "\n${BLUE}[Step 4/5]${NC} Checking SSL certificates...\n"

# Check if certificates exist
CERT_SCRIPT="$SCRIPT_DIR/generate-certs.sh"

if [ ! -f "$CONFIG_DIR/root-ca/root-ca.pem" ]; then
    echo -e "${YELLOW}[INFO]${NC} SSL certificates not found. Generating...\n"

    if [ -f "$CERT_SCRIPT" ]; then
        bash "$CERT_SCRIPT"
        ((CREATED_COUNT+=5)) # Root CA + 4 service certs
    else
        echo -e "${RED}[ERROR]${NC} Certificate generation script not found: $CERT_SCRIPT"
        exit 1
    fi
else
    echo -e "${GREEN}[OK]${NC} SSL certificates already exist"
    ((SKIPPED_COUNT++))
fi

# ============================================================================
# 5. Verify System Requirements
# ============================================================================
echo -e "\n${BLUE}[Step 5/5]${NC} Verifying system requirements...\n"

# Check Docker
if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | grep -oP '\d+\.\d+\.\d+' | head -1)
    echo -e "${GREEN}[OK]${NC} Docker installed (version: $DOCKER_VERSION)"
else
    echo -e "${RED}[WARNING]${NC} Docker not found. Install Docker Engine 23.0.15+"
fi

# Check Docker Compose
if command -v docker-compose &> /dev/null || docker compose version &> /dev/null; then
    if docker compose version &> /dev/null; then
        COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "unknown")
    else
        COMPOSE_VERSION=$(docker-compose --version | grep -oP '\d+\.\d+\.\d+' | head -1)
    fi
    echo -e "${GREEN}[OK]${NC} Docker Compose installed (version: $COMPOSE_VERSION)"
else
    echo -e "${RED}[WARNING]${NC} Docker Compose not found. Install Docker Compose 2.20.2+"
fi

# Check vm.max_map_count (Linux only)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    CURRENT_MAX_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
    REQUIRED_MAX_MAP=262144

    if [ "$CURRENT_MAX_MAP" -ge "$REQUIRED_MAX_MAP" ]; then
        echo -e "${GREEN}[OK]${NC} vm.max_map_count = $CURRENT_MAX_MAP (>= $REQUIRED_MAX_MAP)"
    else
        echo -e "${RED}[WARNING]${NC} vm.max_map_count = $CURRENT_MAX_MAP (required: $REQUIRED_MAX_MAP)"
        echo -e "${YELLOW}[ACTION REQUIRED]${NC} Run: sudo sysctl -w vm.max_map_count=$REQUIRED_MAX_MAP"
        echo -e "                    For permanent: echo 'vm.max_map_count=$REQUIRED_MAX_MAP' | sudo tee -a /etc/sysctl.conf"
    fi
fi

# Check available memory
if command -v free &> /dev/null; then
    TOTAL_MEM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [ "$TOTAL_MEM_GB" -ge 16 ]; then
        echo -e "${GREEN}[OK]${NC} System memory: ${TOTAL_MEM_GB}GB (>= 16GB)"
    else
        echo -e "${YELLOW}[WARNING]${NC} System memory: ${TOTAL_MEM_GB}GB (recommended: 16GB+)"
    fi
fi

# ============================================================================
# Summary
# ============================================================================
echo -e "\n${BLUE}================================${NC}"
echo -e "${BLUE}Setup Complete!${NC}"
echo -e "${BLUE}================================${NC}\n"

echo -e "Summary:"
echo -e "  ${GREEN}✓${NC} Created: $CREATED_COUNT items"
echo -e "  ${BLUE}→${NC} Skipped: $SKIPPED_COUNT items (already exist)\n"

# Check if .env needs editing
if grep -q "CHANGE_ME" "$PROJECT_DIR/.env" 2>/dev/null; then
    echo -e "${YELLOW}⚠ ACTION REQUIRED:${NC}"
    echo -e "  1. Edit .env and replace all 'CHANGE_ME' passwords"
    echo -e "  2. Generate secure passwords:"
    echo -e "     ${BLUE}Linux/Mac:${NC} openssl rand -base64 32"
    echo -e "     ${BLUE}Windows:${NC} [System.Convert]::ToBase64String((1..32|%{Get-Random -Max 256}))\n"
fi

echo -e "${GREEN}Next Steps:${NC}"
echo -e "  1. Review and edit .env file with secure passwords"
echo -e "  2. Start the SIEM stack:"
echo -e "     ${BLUE}cd docker-compose${NC}"
echo -e "     ${BLUE}docker-compose -f phase1-siem-core.yml up -d${NC}"
echo -e "  3. Access Wazuh Dashboard:"
echo -e "     ${BLUE}https://localhost:443${NC}"
echo -e "     Default login: admin / [INDEXER_PASSWORD from .env]\n"

echo -e "${BLUE}For detailed instructions, see:${NC} SETUP.md\n"
