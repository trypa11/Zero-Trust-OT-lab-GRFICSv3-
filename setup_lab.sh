#!/bin/bash

# Zero-Trust OT Lab: Initial Setup Script
# Use this to bootstrap the lab on a new machine.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}==== Initializing Zero-Trust OT Lab ====${NC}"

# 1. Detect Network Interface for MacVLAN
PARENT_IF=$(ip route | grep default | awk '{print $5}' | head -n 1)
echo -e "[*] Detected parent network interface: ${YELLOW}$PARENT_IF${NC}"

# 2. Keycloak Configuration Management
# If the container is running, create a backup.
mkdir -p keycloak_backups
if [ "$(docker ps -q -f name=keycloak)" ]; then
    echo "[*] Exporting current Keycloak configuration to backups..."
    BACKUP_FILE="./keycloak_backups/realm-export-$(date +%F).json"
    docker exec keycloak /opt/keycloak/bin/kc.sh export --file /tmp/realm-export.json --realm master 2>/dev/null
    docker cp keycloak:/tmp/realm-export.json "$BACKUP_FILE" 2>/dev/null
    # Copy to the seeding location for new lab runs
    cp "$BACKUP_FILE" ./keycloak/realm-export.json 2>/dev/null
    echo -e "  ${GREEN}[+]${NC} Keycloak backup saved to $BACKUP_FILE"
fi

# 3. Generate Wazuh Indexer Certificates (Prerequisite for SIEM)
if [ ! -d "./wazuh_config/certs" ]; then
    echo "[*] Generating Wazuh Indexer SSL certificates..."
    docker compose -f generate-indexer-certs.yml up
    echo -e "  ${GREEN}[+]${NC} Certificates generated."
fi

# 4. Build and Pull Environment
echo "[*] Building custom images (EWS, Router, PLC, HMI)..."
docker compose build

# 5. Bring up the core network and services
echo "[*] Starting Zero-Trust services..."
docker compose up -d

# 6. Final Health Check
echo "[*] Waiting for services to stabilize (60s)..."
sleep 60

echo -e "${GREEN}==== Setup Complete ====${NC}"
echo -e "Access the lab at:"
echo -e "  - HMI: https://hmi.localhost.pomerium.io"
echo -e "  - PLC: https://plc.localhost.pomerium.io"
echo -e "  - SIEM: https://localhost:5601 (admin/admin)"
echo -e ""
echo -e "${YELLOW}Note: Ensure your /etc/hosts includes the Pomerium domains if not using public DNS.${NC}"
